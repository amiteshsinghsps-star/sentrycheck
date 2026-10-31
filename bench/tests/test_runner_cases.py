"""Run driver and case registry guards: no host paths in records, explicit KB budget.

These are the failure modes that would silently corrupt a published table: an argv that
forgot --max-kb-age-days, a staging path that leaked /mnt/c into a record, or an artifact
name that walked out of the run directory.
"""
import unittest
from pathlib import Path

from bench import cases as case_registry
from bench import preflight
from bench import runner
from bench.common import BENCH, ROOT, BenchError, read_json, sha256_file
from bench.tests import support


class ArgvTests(unittest.TestCase):
    def test_every_scan_states_a_kb_age_budget(self):
        argv = runner.scan_argv("scanner", "image", "profile.toml", "cache", "artifacts", "report.json")
        self.assertIn("--max-kb-age-days", argv)
        index = argv.index("--max-kb-age-days")
        self.assertEqual(argv[index + 1], str(runner.PRODUCT_KB_AGE_DAYS))
        self.assertIn("--no-cache", argv, "the ELF cache would make a repeat run non-comparable")

    def test_live_mode_uses_the_runtime_and_no_static_flag(self):
        argv = runner.scan_argv("scanner", "image", "profile.toml", "cache", "artifacts", "report.json",
                                runsc="runsc", release="20260921.0", max_age_days=400, mode="live")
        self.assertNotIn("--static-only", argv)
        self.assertNotIn("--native-only", argv)
        self.assertEqual(argv[argv.index("--runsc-bin") + 1], "runsc")
        self.assertEqual(argv[argv.index("--version") + 1], "20260921.0")
        self.assertEqual(argv[argv.index("--max-kb-age-days") + 1], "400")

    def test_native_only_mode_is_explicit(self):
        argv = runner.scan_argv("s", "i", "p", "c", "a", "r", mode="native-only")
        self.assertIn("--native-only", argv)


class LiveScriptTests(unittest.TestCase):
    def setUp(self):
        self.argv = runner.scan_argv("$WORK/scanner", "$WORK/image", "$WORK/profile.toml", "$WORK/cache",
                                     "$WORK/artifacts", "$WORK/report.json", "$WORK/runsc", "20260921.0", 400, "live")
        self.copy_in = [("bin/sentrycheck-linux", "scanner", "file"), ("profiles/synthetic.toml", "profile.toml", "file"),
                        ("artifacts/live-images/io_uring", "image", "dir"), (".cache/linux/bin/runsc", "runsc", "file"),
                        (".cache/linux/bin/gvisor-bin", "gvisor-bin", "bindir")]
        self.text = runner.live_script("$HOME/bench-work/case", "/mnt/c/repo", "/mnt/c/repo/bench/.tmp/stage",
                                       self.argv, self.copy_in)

    def test_script_stages_every_input(self):
        for source, target, kind in self.copy_in:
            flag = "cp -rL" if kind in ("dir", "bindir") else "cp -L"
            self.assertIn('%s "$repo/%s" "$WORK/%s"' % (flag, source, target), self.text,
                          "%s is never copied into the work root" % source)
        self.assertIn('rm -rf "$WORK"', self.text, "a stale work root would contaminate the next run")

    def test_sidecar_lands_beside_the_staged_runsc(self):
        # runsc looks for gvisor-bin relative to the binary it was invoked as and aborts the
        # sandbox under --sidecar-usage-policy STRICT when it is missing.
        self.assertIn('cp -rL "$repo/.cache/linux/bin/gvisor-bin" "$WORK/gvisor-bin"', self.text)
        self.assertIn('chmod -R +x "$WORK/gvisor-bin"', self.text)
        staged_runsc = self.argv[self.argv.index("--runsc-bin") + 1]
        sidecar = next(target for source, target, kind in self.copy_in if kind == "bindir")
        self.assertEqual("%s/%s" % (str(Path(staged_runsc).parent), sidecar), "$WORK/gvisor-bin",
                         "the sidecar tree must sit next to the staged runsc, not elsewhere")

    def test_release_companions_are_pinned_by_the_install_manifest(self):
        pins = read_json(preflight.INSTALL_MANIFEST)["components"]
        sidecar = "gvisor-bin/gvisor_sentry"
        self.assertIn(sidecar, pins, "the manifest pins no sidecar, so staging it cannot be verified")
        self.assertTrue((ROOT / runner.GVISOR_BIN / "gvisor_sentry").is_file())

    def test_work_root_is_ext4_home(self):
        self.assertIn("$HOME/bench-work/case", self.text)

    def test_artifacts_are_copied_back(self):
        for name in ("report.json", "stdout.txt", "stderr.txt", "status.txt", "time.txt"):
            self.assertIn(name, self.text)
        self.assertIn('cp -r "$WORK/artifacts"', self.text)

    def test_recorded_scan_time_excludes_staging(self):
        invocations = "  /usr/bin/time -f \"%M %x\" -o"
        # A duration measured off a settable wall clock can come out negative when the VM steps
        # its time, and the run contract rejects that, so the driver has to use a monotonic source.
        self.assertIn('start=$(awk \'{printf "%d", $1*1000}\' /proc/uptime)', self.text)
        self.assertIn('end=$(awk \'{printf "%d", $1*1000}\' /proc/uptime)', self.text)
        self.assertNotIn("date +%s", self.text)
        self.assertLess(self.text.index("start=$(awk"), self.text.index(invocations))
        self.assertLess(self.text.index(invocations), self.text.index("end=$(awk"))
        # Staging must be finished before the clock starts, or the timing includes the copies.
        self.assertLess(self.text.index('cp -L "$repo/bin/sentrycheck-linux"'), self.text.index("start=$(awk"))

    def test_script_lines_are_lf(self):
        path = support.scratch_root("script") / "live.sh"
        with path.open("w", encoding="utf-8", newline="\n") as handle:
            handle.write(self.text)
        self.assertNotIn(b"\r", path.read_bytes())
        support.cleanup(path)


class ArtifactMappingTests(unittest.TestCase):
    def setUp(self):
        self.stage = support.scratch_root("artifacts")
        base = self.stage / "artifacts" / "runs" / "scan-1"
        for mode in ("native-0", "sandbox-0", "sandbox-1"):
            directory = base / mode
            directory.mkdir(parents=True)
            (directory / "guest.trace").write_bytes(b"trace\n")
            (directory / "stdout.txt").write_bytes(b"out\n")
            (directory / "stderr.txt").write_bytes(b"err\n")
            (directory / "runsc.log").write_bytes(b"log\n")

    def tearDown(self):
        support.cleanup(self.stage)

    def test_traces_outputs_and_logs_are_separated(self):
        found = runner.collect_artifacts(self.stage)
        self.assertIn("traces/native-0-guest.trace", found)
        self.assertIn("traces/sandbox-1-guest.trace", found)
        self.assertIn("outputs/sandbox-0-stdout.txt", found)
        self.assertIn("logs/sandbox-0-runsc.log", found)
        for key in found:
            self.assertTrue(key.startswith(("traces/", "outputs/", "logs/")), key)

    def test_repetitions_are_read_from_the_report(self):
        payload = {"dynamic": {"native": [{"exit_code": 0, "duration_ms": 12}, {"exit_code": 0, "duration_ms": 9}],
                               "sandbox": [{"exit_code": 42, "duration_ms": 30}]}}
        self.assertEqual(runner.repetitions_from(payload),
                         {"native_exits": [0, 0], "sandbox_exits": [42], "native_durations_ms": [12, 9],
                          "sandbox_durations_ms": [30]})
        empty = runner.repetitions_from(None)
        self.assertEqual(empty["native_exits"], [])
        self.assertEqual(empty["sandbox_durations_ms"], [])


class HostRecordTests(unittest.TestCase):
    def test_environment_block_carries_nulls_instead_of_guesses(self):
        host = read_json(BENCH / "hosts" / "wsl2-1.json")
        block = runner.environment_block(host, "linux:bench-work")
        self.assertEqual(block["work_root"], "linux:bench-work")
        self.assertEqual(len(block["cores"]), host["cpu"]["cores"])
        self.assertIs(block["host_load_controlled"], False)
        for key in ("governor", "smt"):
            self.assertIn(key, block)


class RegistryTests(unittest.TestCase):
    def test_every_written_case_matches_the_digests_on_disk(self):
        for path in sorted((BENCH / "cases").glob("*/case.json")):
            record = read_json(path)
            seed = case_registry.REGISTRY[record["case_id"]]
            self.assertEqual(sha256_file(ROOT / record["profile"]["path"]), record["profile"]["sha256"],
                             "%s profile digest drifted" % record["case_id"])
            layout = ROOT / record["image"]["local_path"]
            descriptor, _manifest, layers = case_registry._layout_manifest(layout)
            self.assertEqual(descriptor["digest"], record["image"]["digest"])
            self.assertEqual([item["digest"] for item in layers], record["image"]["layer_digests"])
            self.assertEqual(seed["suites"], record["suites"])

    def test_blocked_cases_are_not_written(self):
        written = {path.parent.name for path in (BENCH / "cases").glob("*/case.json")}
        for case_id, seed in case_registry.REGISTRY.items():
            _, blocker = case_registry.case_record(case_id, seed)
            if blocker:
                self.assertNotIn(case_id, written, "%s is blocked but was written" % case_id)

    def test_registry_rejects_a_missing_layout(self):
        seed = dict(case_registry.REGISTRY["synthetic-baseline"], layout="artifacts/live-images/does-not-exist")
        _record, blocker = case_registry.case_record("synthetic-baseline", seed)
        self.assertIn("blocked", blocker)

    def test_layout_manifest_digest_is_self_checking(self):
        with self.assertRaises(BenchError):
            case_registry._layout_manifest(ROOT / "bench" / "schema")


if __name__ == "__main__":
    unittest.main()
