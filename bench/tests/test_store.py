"""BH-06 store tests, including the negative tamper control the PRD gate requires."""
import unittest

from bench.common import BenchError, read_json
from bench.store import RunStore
from bench.tests import support


class StoreTests(unittest.TestCase):
    def setUp(self):
        self.root = support.scratch_root("store")
        self.store = RunStore(self.root)

    def tearDown(self):
        support.cleanup(self.root)

    def commit(self, record=None, artifacts=None):
        record = record or support.make_record()
        artifacts = artifacts if artifacts is not None else support.make_artifacts()
        directory = self.store.put(record, artifacts)
        return record, directory

    def test_clean_store_verifies(self):
        self.commit()
        report = self.store.verify()
        self.assertTrue(report["ok"], report["problems"] + report["index_problems"])
        self.assertEqual(report["runs"], 1)
        self.assertEqual(report["artifacts_checked"], 5)

    def test_flipping_one_byte_in_a_trace_is_reported(self):
        record, directory = self.commit()
        trace = directory / "traces" / "native-0-guest.trace"
        original = trace.read_bytes()
        flipped = bytearray(original)
        flipped[0] = flipped[0] ^ 0x01
        trace.write_bytes(bytes(flipped))
        report = self.store.verify()
        self.assertFalse(report["ok"])
        self.assertEqual(len(report["problems"]), 1, report["problems"])
        self.assertIn("digest mismatch", report["problems"][0])
        self.assertIn(record["run_id"], report["problems"][0])
        self.assertIn("native-0-guest.trace", report["problems"][0])

    def test_deleting_an_artifact_is_reported(self):
        _, directory = self.commit()
        (directory / "outputs" / "native-0-stdout.txt").unlink()
        report = self.store.verify()
        self.assertFalse(report["ok"])
        self.assertTrue(any("missing artifact" in problem for problem in report["problems"]), report["problems"])

    def test_index_survives_a_rebuild(self):
        self.commit()
        before = read_json(self.root / "index.json")
        self.store.index(write=True)
        self.assertEqual(self.store.verify()["index_problems"], [])
        self.assertEqual(read_json(self.root / "index.json")["artifact_count"], before["artifact_count"])

    def test_stale_index_is_detected(self):
        self.commit()
        index = self.root / "index.json"
        payload = read_json(index)
        payload["artifact_count"] += 1
        index.write_bytes(b'{"schema_version":"1.0"}\n')
        report = self.store.verify()
        self.assertFalse(report["ok"])
        self.assertTrue(report["index_problems"], report["index_problems"])

    def test_stored_refs_are_repo_relative_posix(self):
        record, directory = self.commit()
        trace = directory / "traces" / "native-0-guest.trace"
        trace.write_bytes(b"still the same content\n")
        stored = self.store.records()[0]["artifacts"]["traces"][0]["path"]
        self.assertTrue(stored.startswith("bench/.tmp/"), stored)
        self.assertNotIn("\\", stored)
        self.assertNotIn(":", stored)

    def test_invalid_runs_are_kept_not_dropped(self):
        self.commit(support.make_record(run_id="r-valid"))
        self.commit(support.make_record(run_id="r-invalid", case_id="other-case", valid=False))
        self.assertEqual(len(self.store.records()), 2)
        self.assertEqual([item["run_id"] for item in self.store.records(valid_only=True)], ["r-valid"])
        self.assertTrue(self.store.verify()["ok"], "an invalid run must still be hashable evidence")

    def test_absent_report_is_allowed_for_log_only_runs(self):
        record, directory = self.commit(artifacts={"logs/scanner-stderr.txt": b"boom\n"})
        stored = self.store.records()[0]
        self.assertIsNone(stored["artifacts"]["report"])
        self.assertTrue(self.store.verify()["ok"], stored["run_id"])

    def test_record_is_schema_checked_before_writing(self):
        record = support.make_record()
        record["suite"] = "BM-99"
        with self.assertRaises(BenchError):
            self.store.put(record, support.make_artifacts())
        # A rejected record must leave no trace: a directory of artifacts with no run.json is
        # invisible to the analyzer yet still sized by the index, so it reads as lost evidence.
        self.assertEqual([path.name for path in self.root.rglob("*")], [])
        self.assertEqual(self.store.records(), [])

    def test_a_negative_duration_is_rejected_not_written(self):
        record = support.make_record()
        record["timings_ms"]["scan"] = -37
        with self.assertRaises(BenchError):
            self.store.put(record, support.make_artifacts())
        self.assertEqual([path.name for path in self.root.rglob("*")], [])

    def test_rejects_absolute_host_paths_in_artifact_names(self):
        record = support.make_record()
        with self.assertRaises(BenchError):
            self.store.put(record, {"../escaped.txt": b"no\n"})


class MergeTests(unittest.TestCase):
    """BH-11 merge_from: runs from a second host directory are imported correctly."""

    def setUp(self):
        self.target_root = support.scratch_root("merge-target")
        self.source_root = support.scratch_root("merge-source")
        self.store = RunStore(self.target_root)
        self.source = RunStore(self.source_root)

    def tearDown(self):
        support.cleanup(self.target_root)
        support.cleanup(self.source_root)

    def test_merge_imports_runs_from_source(self):
        # Commit a run in the source store
        record = support.make_record(run_id="r-remote-1", host_id="hremote-1")
        self.source.put(record, support.make_artifacts())
        result = self.store.merge_from(self.source_root)
        self.assertEqual(result["merged_runs"], 1)
        self.assertIn("hremote-1", result["hosts"])
        # Target store must now have that run
        records = self.store.records()
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["run_id"], "r-remote-1")

    def test_merge_does_not_duplicate_existing_runs(self):
        record = support.make_record(run_id="r-remote-2", host_id="hremote-1")
        self.source.put(record, support.make_artifacts())
        # First merge
        self.store.merge_from(self.source_root)
        first_count = len(self.store.records())
        # Second merge must be a no-op (same path already present)
        self.store.merge_from(self.source_root)
        second_count = len(self.store.records())
        self.assertEqual(first_count, second_count,
                         "merging the same source twice must not duplicate records")

    def test_merge_raises_when_source_is_empty(self):
        empty = support.scratch_root("merge-empty")
        with self.assertRaises(BenchError):
            self.store.merge_from(empty)
        support.cleanup(empty)

    def test_merged_store_passes_verify(self):
        record = support.make_record(run_id="r-remote-3", host_id="hremote-1")
        self.source.put(record, support.make_artifacts())
        self.store.merge_from(self.source_root)
        report = self.store.verify()
        self.assertTrue(report["ok"], report["problems"] + report["index_problems"])


class ChecksumFileTests(unittest.TestCase):
    def setUp(self):
        self.root = support.scratch_root("checksums")

    def tearDown(self):
        support.cleanup(self.root)

    def test_missing_entry_and_escape_are_failures(self):
        from bench.store import verify_checksum_file
        from bench.common import sha256_file, write_text
        target = self.root / "ok.txt"
        write_text(target, "content\n")
        digest = sha256_file(target)
        listing = self.root / "checksums.txt"
        write_text(listing, "%s  %s\n%s  bench/.tmp/does-not-exist.txt\n" % (digest, target.name, digest))
        report = verify_checksum_file(listing)
        self.assertEqual(report["checked"], 2)
        self.assertTrue(any("missing file" in line for line in report["failures"]), report["failures"])


if __name__ == "__main__":
    unittest.main()
