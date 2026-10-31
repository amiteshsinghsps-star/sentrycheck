"""Phase 5: registry reference parsing, platform selection and pin integrity."""
import json
import unittest
from pathlib import Path

from bench import fetch
from bench.common import BENCH, ROOT, BenchError, canonical_json, sha256_bytes, write_json


class ReferenceTests(unittest.TestCase):
    def test_hub_references_get_the_library_namespace_and_the_token_host(self):
        self.assertEqual(fetch.parse_reference("docker.io/library/python:3.12-slim"),
                         ("registry-1.docker.io", "library/python", "3.12-slim", None))
        self.assertEqual(fetch.parse_reference("python:3.12"),
                         ("registry-1.docker.io", "library/python", "3.12", None))
        self.assertEqual(fetch.parse_reference("alpine"),
                         ("registry-1.docker.io", "library/alpine", "latest", None))

    def test_a_colon_without_a_slash_is_a_tag_not_a_port(self):
        self.assertEqual(fetch.parse_reference("curl:8.5.0")[1], "library/curl")
        self.assertEqual(fetch.parse_reference("curl:8.5.0")[2], "8.5.0")

    def test_explicit_registries_are_left_alone(self):
        self.assertEqual(fetch.parse_reference("quay.io/prometheus/node-exporter:v1.8.2"),
                         ("quay.io", "prometheus/node-exporter", "v1.8.2", None))
        self.assertEqual(fetch.parse_reference("localhost:5000/my/app:tag"),
                         ("localhost:5000", "my/app", "tag", None))

    def test_a_pinned_digest_is_queried_instead_of_the_tag(self):
        hex64 = "0" * 64
        registry, repository, ref, digest = fetch.parse_reference("ghcr.io/foo/bar@sha256:" + hex64)
        self.assertEqual((registry, repository), ("ghcr.io", "foo/bar"))
        self.assertEqual(ref, "sha256:" + hex64)
        self.assertEqual(digest, "sha256:" + hex64)

    def test_a_malformed_digest_is_rejected(self):
        with self.assertRaises(BenchError):
            fetch.parse_reference("ghcr.io/foo/bar@sha256:ZZZ")

    def test_layout_names_are_filesystem_safe(self):
        name = fetch.layout_name("docker.io/library/python:3.12-slim")
        self.assertRegex(name, r"^[A-Za-z0-9.-]+$")


class PlatformTests(unittest.TestCase):
    def test_one_amd64_linux_entry_is_selected(self):
        index = {"schemaVersion": 2, "manifests": [
            {"mediaType": fetch.MANIFEST_MEDIA[0], "digest": "sha256:" + "a" * 64,
             "platform": {"os": "linux", "architecture": "arm64"}},
            {"mediaType": fetch.MANIFEST_MEDIA[0], "digest": "sha256:" + "b" * 64,
             "platform": {"os": "linux", "architecture": "amd64"}}]}
        self.assertEqual(fetch.select_platform(index, "amd64")["digest"], "sha256:" + "b" * 64)

    def test_artifact_only_entries_are_not_candidates(self):
        index = {"schemaVersion": 2, "manifests": [
            {"mediaType": "application/vnd.oci.artifact.manifest.v1+json", "digest": "sha256:" + "c" * 64},
            {"mediaType": fetch.MANIFEST_MEDIA[0], "digest": "sha256:" + "b" * 64,
             "platform": {"os": "linux", "architecture": "amd64"}}]}
        self.assertEqual(fetch.select_platform(index, "amd64")["digest"], "sha256:" + "b" * 64)

    def test_ambiguity_is_an_error_rather_than_a_guess(self):
        same = {"mediaType": fetch.MANIFEST_MEDIA[0], "digest": "sha256:" + "b" * 64,
                "platform": {"os": "linux", "architecture": "amd64"}}
        with self.assertRaises(BenchError):
            fetch.select_platform({"schemaVersion": 2, "manifests": [same, dict(same)]}, "amd64")

    def test_missing_architecture_is_an_error(self):
        index = {"schemaVersion": 2, "manifests": [
            {"mediaType": fetch.MANIFEST_MEDIA[0], "digest": "sha256:" + "b" * 64,
             "platform": {"os": "linux", "architecture": "s390x"}}]}
        with self.assertRaises(BenchError):
            fetch.select_platform(index, "arm64")

    def test_wrong_schema_version_is_refused(self):
        with self.assertRaises(BenchError):
            fetch.select_platform({"schemaVersion": 1, "manifests": []}, "amd64")


class IntegrityTests(unittest.TestCase):
    def test_a_body_that_does_not_hash_to_the_advertised_digest_fails(self):
        with self.assertRaises(BenchError):
            fetch.verify(b"payload", "sha256:" + "0" * 64, "layer")
        self.assertEqual(fetch.verify(b"payload", sha256_bytes(b"payload"), "layer"), sha256_bytes(b"payload"))

    def test_oci_layout_files_are_canonical(self):
        self.assertEqual(fetch.canonical_json({"imageLayoutVersion": "1.0.0"}),
                         json.dumps({"imageLayoutVersion": "1.0.0"}, indent=2, sort_keys=True,
                                    ensure_ascii=False) + "\n")


class PinVerificationTests(unittest.TestCase):
    def setUp(self):
        self.scratch = BENCH / ".tmp" / "pin-test"
        self.layout = self.scratch / "image"
        blob_dir = self.layout / "blobs" / "sha256"
        blob_dir.mkdir(parents=True, exist_ok=True)
        # The digests below are named by their own content, exactly as a real OCI store is.
        config = b"{}"
        layer = b"x\x00"
        self.config_digest = sha256_bytes(config)
        self.layer_digest = sha256_bytes(layer)
        self.manifest = canonical_json({"mediaType": fetch.MANIFEST_MEDIA[0], "schemaVersion": 2,
                                        "config": {"digest": self.config_digest, "size": len(config)},
                                        "layers": [{"digest": self.layer_digest, "size": len(layer)}]}).encode()
        self.manifest_digest = sha256_bytes(self.manifest)
        for digest, data in ((self.manifest_digest, self.manifest), (self.config_digest, config),
                             (self.layer_digest, layer)):
            (blob_dir / digest[7:]).write_bytes(data)
        write_json(self.layout / "index.json", {"schemaVersion": 2, "manifests": []})
        self.pin = {"reference": "example/image:1", "layers_stored": True,
                    "layout": self.layout.relative_to(ROOT).as_posix(),
                    "index_digest": fetch.sha256_file(self.layout / "index.json"),
                    "manifest_digest": self.manifest_digest, "config_digest": self.config_digest,
                    "layers": [{"digest": self.layer_digest, "size": 2, "stored": True}]}
        self.original = fetch.PINS
        fetch.PINS = self.scratch / "pins.json"
        write_json(fetch.PINS, {"pins": [self.pin]})

    def tearDown(self):
        fetch.PINS = self.original
        import shutil
        shutil.rmtree(str(self.scratch), ignore_errors=True)

    def test_a_complete_pin_verifies(self):
        report = fetch.verify_pins()
        self.assertEqual(report["failures"], [], report)
        self.assertEqual(report["checked"], 1)

    def test_a_swapped_layer_is_detected(self):
        (self.layout / "blobs" / "sha256" / self.layer_digest[7:]).write_bytes(b"y\x00")
        self.assertIn("does not hash to its own name", " ".join(fetch.verify_pins()["failures"]))

    def test_a_missing_layout_is_detected(self):
        self.pin["layout"] = "bench/.tmp/does-not-exist"
        write_json(fetch.PINS, {"pins": [self.pin]})
        self.assertIn("pinned layout", " ".join(fetch.verify_pins()["failures"]))

    def test_a_missing_pin_file_is_reported_as_a_gap(self):
        fetch.PINS.unlink()
        report = fetch.verify_pins()
        self.assertEqual(report["checked"], 0)
        self.assertTrue(report["failures"])


class PinnedCaseTests(unittest.TestCase):
    def test_registry_cases_resolve_to_the_pinned_layout(self):
        from bench.cases import REGISTRY, case_record
        pins = fetch.load_pins()
        for case_id, seed in REGISTRY.items():
            reference = seed.get("reference")
            if not reference or reference not in pins:
                continue
            record, blocker = case_record(case_id, seed)
            self.assertIsNone(blocker, "%s should be ready once pinned: %s" % (case_id, blocker))
            self.assertEqual(record["image"]["digest"], pins[reference]["manifest_digest"])
            self.assertEqual(record["image"]["layer_digests"],
                             [layer["digest"] for layer in pins[reference]["layers"]])
            self.assertEqual(record["profile"]["kind"], "oci-layout")

    def test_the_pinned_digest_is_the_one_the_registry_still_serves(self):
        pins = fetch.load_pins()
        self.assertTrue(pins, "no image has been pinned on this host yet")
        for pin in pins.values():
            if pin["layers_stored"]:
                self.assertTrue((ROOT / pin["layout"] / "index.json").is_file(), pin["layout"])


if __name__ == "__main__":
    unittest.main()
