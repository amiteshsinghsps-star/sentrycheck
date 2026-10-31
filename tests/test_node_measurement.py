"""Accounting boundaries and real-output recording; no Kubernetes is launched."""
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("node_measurement", ROOT / "scripts" / "measure_node_probe.py")
measure = importlib.util.module_from_spec(spec)
spec.loader.exec_module(measure)


class ProcessAccountingTests(unittest.TestCase):
    def row(self, pid, ppid, session, start=10):
        return {"pid": pid, "ppid": ppid, "session": session, "start_ticks": start, "state": "S"}

    def test_proc_name_parentheses_and_own_cpu_exclude_child_cpu(self):
        fields = ["S"] + ["0"] * 21
        fields[1:4] = ["1", "42", "42"]
        fields[11:15] = ["3", "7", "100", "200"]
        fields[19] = "1234"
        fields[21] = "2"
        row = measure.parse_stat("42 (name with ) delimiter) " + " ".join(fields), 4096)
        self.assertEqual(row["name"], "name with ) delimiter")
        self.assertEqual(row["cpu_ticks"], 10)
        self.assertEqual(row["rss_sum_bytes"], 8192)
        self.assertEqual(row["start_ticks"], 1234)

    def test_descendants_session_daemons_and_reparented_identities_are_included(self):
        server = self.row(10, 1, 10)
        child = self.row(11, 10, 11)
        daemon = self.row(12, 1, 10)
        unrelated = self.row(99, 1, 99)
        remembered = set()
        rows = measure.select_processes({row["pid"]: row for row in [server, child, daemon, unrelated]}, [server], remembered)
        self.assertEqual({row["pid"] for row in rows}, {10, 11, 12})
        child["ppid"] = 1
        rows = measure.select_processes({row["pid"]: row for row in [server, child, unrelated]}, [server], remembered)
        self.assertEqual({row["pid"] for row in rows}, {10, 11})

    def test_pid_reuse_is_not_an_old_process_and_shared_shell_session_is_excluded(self):
        server = self.row(10, 1, 7)
        reused = self.row(11, 1, 7, start=20)
        rows = measure.select_processes({10: server, 11: reused}, [server], {(11, 10)})
        self.assertEqual([row["pid"] for row in rows], [10])
        with self.assertRaisesRegex(ValueError, "PID was reused"):
            measure.select_processes({10: self.row(10, 1, 7, start=99)}, [server], set())

    def test_incomplete_report_is_unavailable_and_unverified_cannot_be_healthy(self):
        with tempfile.TemporaryDirectory(prefix="sentrycheck-node-unit-") as directory:
            path = Path(directory) / "probe.json"
            path.write_text('{"state":')
            self.assertIsNone(measure.read_probe(path))
            self.assertFalse(measure.healthy({"state": "canary-verified", "healthy": True, "verified": False}))


class RecorderTests(unittest.TestCase):
    def execute(self, root, source):
        return subprocess.run([sys.executable, str(ROOT / "scripts" / "record_demo.py"), "--output", str(root / "demo.cast"),
                               "--events", str(root / "events.jsonl"), "--start-marker", "BEGIN", "--stop-marker", "END",
                               "--", sys.executable, "-u", "-c", source], capture_output=True, text=True, timeout=15)

    def test_capture_contains_actual_marker_window_and_monotonic_times(self):
        with tempfile.TemporaryDirectory(prefix="sentrycheck-record-unit-") as directory:
            root = Path(directory)
            result = self.execute(root, "print('setup'); print('BEGIN'); print('actual canary output'); print('END'); print('cleanup')")
            self.assertEqual(result.returncode, 0, result.stderr)
            rows = [json.loads(line) for line in (root / "demo.cast").read_text().splitlines()]
            self.assertEqual(rows[0]["version"], 2)
            output = "".join(row[2] for row in rows[1:])
            self.assertIn("actual canary output", output)
            self.assertNotIn("setup", output)
            self.assertNotIn("cleanup", output)
            self.assertEqual([row[0] for row in rows[1:]], sorted(row[0] for row in rows[1:]))
            metadata = json.loads((root / "demo.cast.metadata.json").read_text())
            self.assertEqual(metadata["status"], "complete")
            self.assertEqual(metadata["asciicast_sha256"], measure.digest(root / "demo.cast"))
            repeat = self.execute(root, "print('BEGIN'); print('END')")
            self.assertEqual(repeat.returncode, 2)

    def test_command_failure_or_missing_end_marker_cannot_be_complete(self):
        for source in ["print('BEGIN'); raise SystemExit(3)", "print('BEGIN'); print('no final marker')"]:
            with self.subTest(source=source), tempfile.TemporaryDirectory(prefix="sentrycheck-record-fail-") as directory:
                root = Path(directory)
                result = self.execute(root, source)
                self.assertEqual(result.returncode, 2)
                self.assertEqual(json.loads((root / "demo.cast.metadata.json").read_text())["status"], "failed")


if __name__ == "__main__":
    unittest.main()
