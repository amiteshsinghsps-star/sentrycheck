"""Read-only demo verification and live-mode opt-in boundaries."""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import demo
import make_fixtures
sys.path.pop(0)


class RelocationTests(unittest.TestCase):
    def test_only_artifact_fields_and_complete_prefix_boundaries_are_relocated(self):
        original = {"source_binary": "/old/workload", "trace_ref": "/old/runs/trace", "url": "/old/doc",
                    "dynamic_evidence": {"native": [{"trace_excerpt_ref": "/old/runs/trace", "stdout_ref": "/older/output"}]}}
        changed = demo.rebase_references(original, [("/old", "/new")])
        self.assertEqual(Path(changed["trace_ref"]), Path("/new/runs/trace"))
        self.assertEqual(changed["source_binary"], original["source_binary"])
        self.assertEqual(changed["url"], original["url"])
        self.assertEqual(changed["dynamic_evidence"]["native"][0]["stdout_ref"], "/older/output")
        self.assertEqual(original["trace_ref"], "/old/runs/trace")

    def test_empty_relocation_prefix_is_rejected(self):
        for value in ["missing-equals", "=new", "old="]:
            with self.subTest(value=value), self.assertRaises(ValueError):
                demo.mappings_from([value])


class DemoCliTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.binary = Path(os.environ.get("SENTRYCHECK_BIN", ROOT / "target/debug" / ("sentrycheck.exe" if os.name == "nt" else "sentrycheck"))).resolve()
        if not cls.binary.is_file():
            raise RuntimeError("Build the scanner before testing the demo")

    def run_demo(self, *args):
        return subprocess.run([sys.executable, str(ROOT / "scripts/demo.py"), "--binary", str(self.binary), *map(str, args)],
                              capture_output=True, text=True, timeout=60)

    def test_verify_uses_retained_report_without_claiming_new_execution(self):
        with tempfile.TemporaryDirectory(prefix="sentrycheck-demo-unit-") as directory:
            root = Path(directory)
            make_fixtures.oci(root / "image", {"workload": make_fixtures.elf(bytes.fromhex("b83c00000031ff0f05"))})
            report = root / "retained.json"
            with report.open("wb") as output:
                result = subprocess.run([str(self.binary), "scan", str(root / "image"), "--static-only", "--no-cache",
                                         "--cache", str(root / "cache"), "--format", "json"], stdout=output, stderr=subprocess.PIPE)
            self.assertEqual(result.returncode, 2)
            original = report.read_bytes()
            checked = self.run_demo("--mode", "verify", "--report", report, "--artifacts-root", root, "--out", root / "verified")
            self.assertEqual(checked.returncode, 0, checked.stderr + checked.stdout)
            summary = json.loads((root / "verified/summary.json").read_text())
            self.assertEqual(summary["status"], "complete")
            self.assertFalse(summary["new_workload_execution_requested"])
            self.assertFalse(summary["reports"][0]["new_workload_execution"])
            self.assertEqual(summary["reports"][0]["status"], "incomplete")
            self.assertTrue((root / "verified/report.html").is_file())
            self.assertEqual(report.read_bytes(), original)

    def test_verify_rejects_live_flags_before_creating_output(self):
        with tempfile.TemporaryDirectory(prefix="sentrycheck-demo-mode-") as directory:
            out = Path(directory) / "output"
            result = self.run_demo("--mode", "verify", "--full", "--out", out)
            self.assertEqual(result.returncode, 2)
            self.assertIn("require --mode live", result.stderr)
            self.assertFalse(out.exists())

    def test_previous_evidence_is_not_overwritten_even_with_malformed_summary(self):
        with tempfile.TemporaryDirectory(prefix="sentrycheck-demo-preserve-") as directory:
            out = Path(directory)
            summary = out / "summary.json"
            summary.write_text("sentinel previous evidence")
            result = self.run_demo("--out", out)
            self.assertEqual(result.returncode, 2)
            self.assertEqual(summary.read_text(), "sentinel previous evidence")
            self.assertIn("existing evidence", result.stderr)


if __name__ == "__main__":
    unittest.main()
