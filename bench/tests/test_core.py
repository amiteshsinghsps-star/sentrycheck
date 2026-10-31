"""Determinism, contract and environment checks for the harness primitives."""
import json
import unittest
from pathlib import Path

from bench import preflight, schemas
from bench.common import (BENCH, BenchError, canonical_json, now_iso, pure_rel_ok, quantize, read_json,
                          rel_path, resolve, sha256_bytes, write_json, write_text)
from bench.tests import support


class DeterminismTests(unittest.TestCase):
    def test_canonical_json_orders_keys_and_rejects_nan(self):
        first = canonical_json({"b": 1, "a": {"z": [1, 2], "y": None}})
        second = canonical_json({"a": {"y": None, "z": [2, 1]}, "b": 1})
        self.assertNotEqual(first, second, "arrays keep their order; objects are sorted")
        self.assertIn('"a": {', first)
        self.assertLess(first.index('"a"'), first.index('"b"'))
        with self.assertRaises(ValueError):
            canonical_json({"x": float("nan")})

    def test_quantize_rejects_non_finite_values(self):
        self.assertEqual(quantize(1.23456789), 1.234568)
        self.assertEqual(quantize(3), 3)
        self.assertEqual(quantize(True), True)
        for value in (float("inf"), float("nan")):
            with self.assertRaises(BenchError):
                quantize(value)

    def test_written_text_is_lf_only(self):
        path = support.scratch_root("lf") / "file.txt"
        write_text(path, "one\r\ntwo\r\n")
        self.assertEqual(path.read_bytes(), b"one\r\ntwo\r\n", "input newlines are preserved verbatim")
        write_json(path, {"b": 1, "a": 2})
        self.assertNotIn("\r", path.read_text(encoding="utf-8"))
        support.cleanup(path)

    def test_paths_escape_is_refused(self):
        with self.assertRaises(BenchError):
            resolve("../../outside.json")
        self.assertEqual(rel_path(BENCH / "runs"), "bench/runs")

    def test_pure_rel_ok_rules(self):
        for good in ("bench/runs/x/report.json", "a", "traces/native-0.trace"):
            self.assertTrue(pure_rel_ok(good), good)
        for bad in ("/abs/path", "C:/x", "..\\x", "a/../b", "a//b", "", "a/./b"):
            self.assertFalse(pure_rel_ok(bad), bad)

    def test_digests_are_prefixed_and_stable(self):
        self.assertEqual(sha256_bytes(b""),
                         "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")

    def test_timestamps_are_utc_second_precision(self):
        stamp = now_iso()
        self.assertRegex(stamp, r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")


class SchemaTests(unittest.TestCase):
    def test_selftest_round_trips_every_contract(self):
        result = schemas.selftest()
        self.assertEqual(len(result), 6)
        for entry in result:
            self.assertGreater(entry["required_members"], 0, entry)

    def test_unknown_keyword_is_an_error_not_a_pass(self):
        found = schemas.validate({"type": "object", "wat": True}, {"a": 1})
        self.assertTrue(any("unsupported schema keyword" in error for error in found), found)

    def test_pattern_and_enum_are_enforced(self):
        found = schemas.validate({"type": "string", "pattern": "^sha256:[a-f0-9]{64}$"}, "sha256:ZZ")
        self.assertEqual(len(found), 1, found)
        self.assertIn("does not match pattern", found[0])
        # A trailing newline must not sneak past an anchored pattern.
        self.assertNotEqual(schemas.validate({"type": "string", "pattern": "^a$"}, "a\n"), [],
                            "an anchored pattern accepted a trailing newline")
        self.assertEqual(schemas.validate({"type": "string", "enum": ["a", "b"]}, "c"),
                         ["/: 'c' is not one of ['a', 'b']"])

    def test_additional_properties_are_closed(self):
        record = support.make_record()
        record["surprise"] = 1
        with self.assertRaises(BenchError):
            schemas.check("run", record, record["run_id"])

    def test_generated_contracts_are_lf_and_parseable(self):
        for name in ("case", "run", "label", "host"):
            path = BENCH / "schema" / ("%s.schema.json" % name)
            raw = path.read_bytes()
            self.assertNotIn(b"\r", raw, "%s must be LF for a stable digest" % name)
            document = json.loads(raw.decode("utf-8"))
            self.assertTrue(document["title"].startswith("SENTRYCHECK benchmark "), document["title"])
            self.assertIn("2020-12", document["$schema"])
            self.assertEqual(document["$id"], "urn:sentrycheck:bench:%s:1.0" % name)


class PreflightTests(unittest.TestCase):
    def test_host_without_load_fails_the_load_check(self):
        host = read_json(BENCH / "hosts" / "windows-1.json")
        result = preflight.check(host_record=host, work_root=BENCH, manifest=Path("/nonexistent/manifest.json"))
        by_id = {entry["id"]: entry["status"] for entry in result["checks"]}
        self.assertEqual(by_id["host-load"], "fail")
        self.assertEqual(by_id["runtime-checksums"], "fail")
        self.assertFalse(result["ok"])
        self.assertIn("host-load", result["failed"])

    def test_9p_work_root_is_refused(self):
        host = read_json(BENCH / "hosts" / "wsl2-1.json")
        result = preflight.check(host_record=host, work_root="/mnt/c/Users/vijay", manifest=support.SCRATCH / "none.json")
        detail = next(entry for entry in result["checks"] if entry["id"] == "work-root")
        self.assertEqual(detail["status"], "fail")
        self.assertIn("9p", detail["detail"])

    def test_disk_budget_is_explicit(self):
        result = preflight.check(host_record=None, min_free_mb=10 ** 12, work_root=BENCH)
        self.assertFalse(result["ok"])
        self.assertIn("free-disk", result["failed"])

    def test_checks_are_sorted_by_id(self):
        result = preflight.check(work_root=BENCH)
        ids = [entry["id"] for entry in result["checks"]]
        self.assertEqual(ids, sorted(ids))
        self.assertEqual(ids, ["clock", "free-disk", "host-load", "runtime-checksums", "work-root"])

    def test_unobservable_load_blocks_timing_not_compatibility(self):
        host = read_json(BENCH / "hosts" / "windows-1.json")
        result = preflight.check(host_record=host, work_root=BENCH, manifest=Path("/nonexistent/manifest.json"))
        self.assertIn("host-load", result["failed"])
        self.assertFalse(result["ok"])
        self.assertFalse(result["timing_capable"])
        self.assertFalse(result["live_capable"], "the pinned runtime manifest is missing in this fixture")

    def test_pinned_digest_prefix_forms_agree(self):
        self.assertEqual(preflight.bare_digest("sha256:abc"), "abc")
        self.assertEqual(preflight.bare_digest("abc"), "abc")
        host = read_json(BENCH / "hosts" / "wsl2-1.json")
        result = preflight.check(host_record=host, work_root=str(BENCH))
        checksums = next(entry for entry in result["checks"] if entry["id"] == "runtime-checksums")
        self.assertEqual(checksums["status"], "pass", checksums["detail"])


if __name__ == "__main__":
    unittest.main()
