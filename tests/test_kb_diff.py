"""KB diff invariants using synthetic mutations; these are not release measurements."""
import copy
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class KnowledgeBaseDiffTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.binary = Path(os.environ.get("SENTRYCHECK_BIN", ROOT / "target" / "debug" / ("sentrycheck.exe" if os.name == "nt" else "sentrycheck")))
        if not cls.binary.exists():
            raise RuntimeError("Build sentrycheck before running KB diff tests")
        cls.original = json.loads((ROOT / "kb" / "snapshot.json").read_text(encoding="utf-8"))
        cls.temp = tempfile.TemporaryDirectory(prefix="sentrycheck-kb-diff-")
        cls.directory = Path(cls.temp.name)
        cls.old_path = cls.directory / "old.json"
        cls.new_path = cls.directory / "new.json"

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def compare(self, before=None, after=None, *, human=False):
        self.old_path.write_text(json.dumps(self.original if before is None else before), encoding="utf-8")
        self.new_path.write_text(json.dumps(self.original if after is None else after), encoding="utf-8")
        result = subprocess.run([str(self.binary), "kb", "diff", str(self.old_path), str(self.new_path), "--format", "human" if human else "json"], capture_output=True, text=True, timeout=30)
        return result, json.loads(result.stdout) if result.returncode == 0 and not human else None

    def test_identical_snapshot_and_raw_byte_identity(self):
        result, diff = self.compare()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(diff["support_changes"], [])
        self.assertEqual(diff["gap_changes"], [])
        self.assertEqual(diff["summary"]["rows_unchanged"], len(self.original["syscall_support"]))
        self.assertEqual(diff["before"]["input_sha256"], "sha256:" + hashlib.sha256(self.old_path.read_bytes()).hexdigest())
        self.assertFalse(diff["authenticated"])
        self.assertFalse(diff["source_hashes_verified"])

    def test_status_documentation_and_location_changes_are_separate(self):
        changed = copy.deepcopy(self.original)
        by_name = {(r["architecture"], r["syscall"]): r for r in changed["syscall_support"]}
        by_name[("amd64", "msync")]["status"] = "unimplemented"
        next(g for g in changed["entries"] if g["id"] == "gap-gvisor-amd64-msync")["status"] = "unimplemented"
        by_name[("amd64", "read")]["detail"] = "Synthetic documentation-only test change."
        by_name[("arm64", "read")]["source_line"] += 1
        result, diff = self.compare(after=changed)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(diff["summary"]["rows_changed"], 3)
        for key in ("support_status_changes", "detail_changes", "source_location_changes"):
            self.assertEqual(diff["summary"][key], 1)
        self.assertEqual(diff["summary"]["gap_definition_changes"], 1)
        self.assertEqual(diff["summary"]["gap_provenance_changes"], 0)
        for row in diff["support_changes"]:
            for side in ("before", "after"):
                self.assertEqual(row[side]["citation"]["source_revision"], self.original["source_commit"])
                self.assertIn("#L", row[side]["citation"]["url"])

    def test_added_removed_and_renumbered_are_not_status_guesses(self):
        changed = copy.deepcopy(self.original)
        changed["syscall_support"] = [r for r in changed["syscall_support"] if not (r["architecture"] == "amd64" and r["syscall"] == "read")]
        added = copy.deepcopy(self.original["syscall_support"][0])
        added.update(syscall="synthetic_new_call", number=60000)
        changed["syscall_support"].append(added)
        next(r for r in changed["syscall_support"] if r["architecture"] == "arm64" and r["syscall"] == "read")["number"] = 60001
        result, diff = self.compare(after=changed)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(diff["summary"]["rows_added"], 1)
        self.assertEqual(diff["summary"]["rows_removed"], 1)
        self.assertEqual(diff["summary"]["number_changes"], 1)
        self.assertEqual(diff["summary"]["support_status_changes"], 0)
        removed = next(r for r in diff["support_changes"] if r["change"] == "removed")
        self.assertIsNone(removed["after"])
        self.assertIn("unknown", " ".join(diff["interpretation"]))

    def test_release_and_commit_change_does_not_invent_support_delta(self):
        changed = copy.deepcopy(self.original)
        changed["runtime_releases"]["gvisor"] = ["20260914.0"]
        changed["snapshot_version"] = "synthetic-test/gvisor-20260914.0"
        changed["source_commit"] = "a" * 40
        for gap in changed["entries"]:
            if gap["applicability"] == "release-pinned":
                gap["runtime_versions"] = ["20260914.0"]
                gap["citation"]["source_revision"] = changed["source_commit"]
                gap["citation"]["url"] = gap["citation"]["url"].replace(self.original["source_commit"], changed["source_commit"])
        result, diff = self.compare(after=changed)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(diff["support_changes"], [])
        self.assertEqual(diff["summary"]["gap_definition_changes"], 0)
        self.assertGreater(diff["summary"]["gap_provenance_changes"], 0)
        self.assertIn("source_commit", diff["snapshot_fields_changed"])

    def test_order_is_deterministic(self):
        changed = copy.deepcopy(self.original)
        changed["syscall_support"].reverse()
        changed["entries"].reverse()
        result, diff = self.compare(after=changed)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(diff["support_changes"], [])
        self.assertEqual(diff["gap_changes"], [])
        changed["syscall_support"][0]["source_line"] += 1
        changed["syscall_support"][-1]["source_line"] += 1
        _, diff = self.compare(after=changed)
        keys = [(r["runtime"], r["architecture"], r["syscall"]) for r in diff["support_changes"]]
        self.assertEqual(keys, sorted(keys))

    def test_invalid_table_or_scope_fails_closed_on_either_input(self):
        mutations = [
            lambda d: d["syscall_support"][0].update(status="supported-maybe"),
            lambda d: d["syscall_support"][0].update(number=-1),
            lambda d: d["syscall_support"][0].update(source_line=0),
            lambda d: d["syscall_support"][0].update(runtime="kata"),
            lambda d: d["syscall_support"].append(copy.deepcopy(d["syscall_support"][0])),
            lambda d: d["runtime_releases"]["gvisor"].append("20260914.0"),
            lambda d: d["runtime_releases"].update(kata=["3.3.0"]),
            lambda d: d.update(source_commit="invalid"),
            lambda d: d["source_hashes"].update({"linux64.go": "0"}),
            lambda d: d["entries"][0]["citation"].update(source_revision="a" * 40),
            lambda d: d["entries"][0].update(status="unimplemented"),
            lambda d: d["entries"][0].update(first_observed="2026-02-30"),
            lambda d: d.update(created_at="invalid"),
        ]
        for index, mutate in enumerate(mutations):
            with self.subTest(mutation=index):
                changed = copy.deepcopy(self.original)
                mutate(changed)
                result, diff = self.compare(before=changed) if index % 2 else self.compare(after=changed)
                self.assertEqual(result.returncode, 2, result.stderr)
                self.assertIsNone(diff)
                self.assertEqual(result.stdout, "")

    def test_invalid_arguments_and_missing_file_are_errors(self):
        for args in [[], ["missing.json"], ["missing.json", "missing.json"], ["x", "y", "z"], ["x", "y", "--force"], ["x", "y", "--format", "yaml"]]:
            result = subprocess.run([str(self.binary), "kb", "diff", *args], capture_output=True, text=True, timeout=30)
            self.assertEqual(result.returncode, 2, result.stderr)

    def test_human_output_preserves_unknown_and_informational_exit_code(self):
        changed = copy.deepcopy(self.original)
        changed["syscall_support"] = [r for r in changed["syscall_support"] if r["syscall"] != "read"]
        result, _ = self.compare(after=changed, human=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("absent (unknown)", result.stdout)
        self.assertIn("not observed workload compatibility", result.stdout)


if __name__ == "__main__":
    unittest.main()
