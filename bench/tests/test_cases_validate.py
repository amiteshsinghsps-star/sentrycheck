"""Tests for bench/cases.py community submission validation (validate_submission)."""
import copy
import json
import unittest

from bench.common import BenchError
from bench.tests import support


def _valid_template():
    """A fully schema-valid community case record matching the full case schema."""
    return {
        "schema_version": "1.0",
        "case_id": "community-test-001",
        "group": "community",
        "image": {
            "reference": "registry.example.com/test:1.0",
            "local_path": None,
            "digest": "sha256:" + "a" * 64,
            "source_url": "https://github.com/example/test-app",
            "license": "Apache-2.0",
            "architecture": "amd64",
            "media_type": "application/vnd.oci.image.manifest.v1+json",
            "layer_digests": ["sha256:" + "b" * 64],
        },
        "profile": {
            "kind": "command",
            "path": "profiles/test.toml",
            "sha256": "sha256:" + "c" * 64,
            "coverage_notes": "Exercises startup path",
        },
        "runtime": {
            "name": "gvisor",
            "release": "20260921.0",
            "platform": "systrap",
            "flags": [],
        },
        "expected_interfaces": ["write", "exit_group"],
        "label": None,
        "split": "development",
        "suites": ["BM-01"],
        "host_classes": ["wsl2-ext4"],
        "tags": ["community"],
        "added_in": "bench-1.0",
        "retired_in": None,
        "notes": "Synthetic test submission for validation tests.",
    }


class ValidateSubmissionTests(unittest.TestCase):
    def setUp(self):
        self.root = support.scratch_root("cases-validate")

    def tearDown(self):
        support.cleanup(self.root)

    def _write(self, data, name="submission.json"):
        path = self.root / name
        path.write_text(json.dumps(data), encoding="utf-8")
        return path

    def test_valid_template_passes(self):
        from bench.cases import validate_submission
        path = self._write(_valid_template())
        # validate_submission returns True on success
        result = validate_submission(path)
        self.assertTrue(result)

    def test_template_file_passes(self):
        """The committed community_case.json template must be valid."""
        from bench.cases import validate_submission
        from bench.common import BENCH
        template = BENCH / "templates" / "community_case.json"
        if template.is_file():
            result = validate_submission(template)
            self.assertTrue(result, "The bundled template must pass validation")

    def test_self_assigning_to_test_split_is_rejected(self):
        from bench.cases import validate_submission
        data = _valid_template()
        data["split"] = "test"
        path = self._write(data)
        with self.assertRaises(BenchError) as ctx:
            validate_submission(path)
        self.assertIn("test", str(ctx.exception).lower(),
                      "Error must mention the test split: %s" % ctx.exception)

    def test_missing_license_is_rejected(self):
        from bench.cases import validate_submission
        data = _valid_template()
        data["image"]["license"] = ""
        path = self._write(data)
        with self.assertRaises(BenchError):
            validate_submission(path)

    def test_empty_expected_interfaces_is_rejected(self):
        from bench.cases import validate_submission
        data = _valid_template()
        data["expected_interfaces"] = []
        path = self._write(data)
        with self.assertRaises(BenchError):
            validate_submission(path)

    def test_nonexistent_file_raises_bench_error(self):
        from bench.cases import validate_submission
        bad_path = self.root / "does-not-exist.json"
        with self.assertRaises(BenchError):
            validate_submission(bad_path)

    def test_invalid_case_id_is_rejected(self):
        from bench.cases import validate_submission
        data = _valid_template()
        data["case_id"] = "UPPERCASE_INVALID"
        path = self._write(data)
        with self.assertRaises(BenchError) as ctx:
            validate_submission(path)
        self.assertIn("case_id", str(ctx.exception).lower())


if __name__ == "__main__":
    unittest.main()
