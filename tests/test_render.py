"""Offline HTML report rendering, using synthetic evidence rather than live claims."""
import copy
from html.parser import HTMLParser
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

from test_cli import ROOT, fixtures


class ReportHTML(HTMLParser):
    """Inspect the browser's data-element boundary, not serializer internals."""
    def __init__(self, html):
        super().__init__(convert_charrefs=False)
        self.elements = []
        self.data_elements = []
        self.capture = None
        self.feed(html)
        self.close()

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        self.elements.append((tag, attrs))
        if tag == "script" and attrs.get("id") == "sentrycheck-data":
            self.capture = []
            self.data_elements.append((attrs, self.capture))

    def handle_endtag(self, tag):
        if tag == "script":
            self.capture = None

    def handle_data(self, data):
        if self.capture is not None:
            self.capture.append(data)

    def payload(self):
        if len(self.data_elements) != 1:
            raise AssertionError("HTML must contain exactly one report data element")
        attrs, parts = self.data_elements[0]
        if attrs.get("type") != "application/json":
            raise AssertionError("Report data must not be executable JavaScript")
        return json.loads("".join(parts))


class RenderTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.binary = Path(os.environ.get("SENTRYCHECK_BIN", ROOT / "target/debug" / ("sentrycheck.exe" if os.name == "nt" else "sentrycheck")))
        if not cls.binary.exists():
            raise RuntimeError("Build sentrycheck before running render tests")
        cls.temp = tempfile.TemporaryDirectory(prefix="sentrycheck-render-tests-")
        cls.root = Path(cls.temp.name)
        image = cls.root / "image"
        digest = fixtures.oci(image, {"workload": fixtures.elf(bytes.fromhex("b8a90100000f05b83c00000031ff0f05"))})
        common = ("scan", str(image), "--format", "json", "--cache", str(cls.root / "cache"), "--version", "20260921.0")
        static = cls.command(*common, "--static-only")
        if static.returncode != 2:
            raise AssertionError(static.stderr)
        cls.static = json.loads(static.stdout)
        evidence = fixtures.evidence(cls.root / "evidence", digest, "hard-failure")
        failed = cls.command(*common, "--evidence", str(evidence))
        if failed.returncode != 1:
            raise AssertionError(failed.stderr)
        cls.failed = json.loads(failed.stdout)

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    @classmethod
    def command(cls, *args):
        return subprocess.run([str(cls.binary), *args], cwd=ROOT, capture_output=True,
                              text=True, encoding="utf-8", timeout=30)

    def setUp(self):
        self.work = self.root / self._testMethodName
        self.work.mkdir()

    def save(self, report=None, name="report.json"):
        path = self.work / name
        path.write_text(json.dumps(self.static if report is None else report, ensure_ascii=False), encoding="utf-8")
        return path

    def render(self, source, destination, *args):
        return self.command("report", "render", str(source), "--output", str(destination), *args)

    def read_html(self, path):
        html = path.read_text(encoding="utf-8")
        self.assertIn("<!doctype html", html.lower())
        document = ReportHTML(html)
        return document, document.payload()

    def test_runtime_matrix_renders_original_reports_and_rejects_false_summary(self):
        # A static, explicitly synthetic Kata child has no guest observations.
        kata = copy.deepcopy(self.static)
        kata["target_runtime"].update(name="kata", version="3.3.0")
        kata["candidate_gaps"] = []
        kata["incomplete_reasons"].append("Synthetic matrix UI fixture; no Kata execution was performed.")
        gvisor_path = self.save(self.failed, "gvisor.json")
        kata_path = self.save(kata, "kata.json")
        compared = self.command("report", "compare", str(gvisor_path), str(kata_path), "--format", "json")
        self.assertEqual(compared.returncode, 1, compared.stderr)
        matrix = json.loads(compared.stdout)
        source = self.save(matrix, "matrix.json")
        destination = self.work / "matrix.html"
        rendered = self.render(source, destination)
        self.assertEqual(rendered.returncode, 0, rendered.stderr)
        _, payload = self.read_html(destination)
        self.assertEqual(payload["input_kind"], "matrix")
        self.assertEqual(payload["report"], matrix)
        self.assertEqual(payload["report"]["reports"], [self.failed, kata])
        self.assertTrue(payload["validation"]["semantic_consistency"])
        self.assertFalse(payload["validation"]["authenticated"])
        matrix["cross_runtime"]["comparable"] = True
        bad = self.save(matrix, "invalid-matrix.json")
        invalid_output = self.work / "invalid.html"
        rendered = self.render(bad, invalid_output)
        self.assertEqual(rendered.returncode, 2, rendered.stderr)
        self.assertFalse(invalid_output.exists())

    def test_incomplete_and_failed_reports_render_without_upgrading_evidence(self):
        for name, report in [("static", self.static), ("failed", self.failed)]:
            with self.subTest(name=name):
                source = self.save(report, name + ".json")
                destination = self.work / (name + ".html")
                result = self.render(source, destination)
                self.assertEqual(result.returncode, 0, result.stderr)
                document, data = self.read_html(destination)
                self.assertEqual(data["report"], report)
                self.assertEqual(data["report"]["status"], "incomplete")
                self.assertTrue(data.get("rendered_at"))
                self.assertTrue(data.get("generator_version"))
                self.assertTrue(data["validation"]["semantic_consistency"])
                self.assertFalse(data["validation"]["authenticated"])
                self.assertFalse(any(attrs.get("src", "").startswith(("https:", "http:", "//"))
                                     for tag, attrs in document.elements if tag == "script"))

    def test_report_strings_cannot_escape_the_json_script_element(self):
        report = copy.deepcopy(self.static)
        attack = '</script><script id="render-injected">globalThis.renderInjected=true</script><img id="render-injected" src=x onerror=alert(1)> & \u2028 \u2029'
        report["image"] = attack
        report["limitations"].append(attack)
        source = self.save(report)
        destination = self.work / "injection.html"
        result = self.render(source, destination)
        self.assertEqual(result.returncode, 0, result.stderr)
        document, data = self.read_html(destination)
        self.assertEqual(data["report"]["image"], attack)
        self.assertEqual(data["report"]["limitations"][-1], attack)
        self.assertFalse(any(attrs.get("id") == "render-injected" for _, attrs in document.elements))

    def test_malformed_or_contradictory_reports_create_no_html(self):
        invalid = ["{", json.dumps({"schema_version": "1.0"})]
        contradiction = copy.deepcopy(self.static)
        contradiction.update(status="complete", incomplete_reasons=[])
        invalid.append(json.dumps(contradiction))
        for index, text in enumerate(invalid):
            with self.subTest(case=index):
                source = self.work / f"bad-{index}.json"
                source.write_text(text, encoding="utf-8")
                destination = self.work / f"bad-{index}.html"
                result = self.render(source, destination)
                self.assertEqual(result.returncode, 2, result.stderr)
                self.assertFalse(destination.exists())

    def test_directory_output_preserves_neighbors_and_requires_force_to_replace_index(self):
        source = self.save()
        destination = self.work / "site"
        destination.mkdir()
        neighbor = destination / "keep.txt"
        neighbor.write_text("unrelated user file", encoding="utf-8")
        result = self.render(source, destination)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.read_html(destination / "index.html")
        original = (destination / "index.html").read_bytes()
        result = self.render(source, destination)
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertEqual((destination / "index.html").read_bytes(), original)
        result = self.render(source, destination, "--force")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(neighbor.read_text(encoding="utf-8"), "unrelated user file")

    def test_existing_html_is_preserved_without_force(self):
        source = self.save()
        destination = self.work / "existing.htm"
        destination.write_bytes(b"user-authored HTML")
        result = self.render(source, destination)
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertEqual(destination.read_bytes(), b"user-authored HTML")
        result = self.render(source, destination, "--force")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.read_html(destination)

    def test_force_cannot_overwrite_report_or_kb_input(self):
        source = self.save(name="source.html")
        original = source.read_bytes()
        result = self.render(source, source, "--force")
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertEqual(source.read_bytes(), original)
        kb = self.work / "kb.html"
        kb.write_bytes((ROOT / "kb/snapshot.json").read_bytes())
        original_kb = kb.read_bytes()
        result = self.render(source, kb, "--kb", str(kb), "--force")
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertEqual(kb.read_bytes(), original_kb)

    def test_output_symlinks_and_symlink_ancestors_are_refused(self):
        source = self.save()
        outside = self.work / "outside"
        outside.mkdir()
        existing = outside / "existing.html"
        existing.write_bytes(b"outside content")
        alias = self.work / "alias.html"
        directory_alias = self.work / "alias-dir"
        try:
            alias.symlink_to(existing)
            directory_alias.symlink_to(outside, target_is_directory=True)
        except (OSError, NotImplementedError) as error:
            self.skipTest(f"OS does not permit test symlinks: {error}")
        for destination in [alias, directory_alias / "new.html"]:
            with self.subTest(destination=str(destination)):
                result = self.render(source, destination, "--force")
                self.assertEqual(result.returncode, 2, result.stderr)
        self.assertEqual(existing.read_bytes(), b"outside content")
        self.assertFalse((outside / "new.html").exists())

    def test_matching_kb_is_embedded_and_explicit_mismatch_is_rejected(self):
        source = self.save()
        kb = json.loads((ROOT / "kb/snapshot.json").read_text(encoding="utf-8"))
        destination = self.work / "with-kb.html"
        result = self.render(source, destination, "--kb", str(ROOT / "kb/snapshot.json"))
        self.assertEqual(result.returncode, 0, result.stderr)
        _, data = self.read_html(destination)
        self.assertEqual(data["kb"]["snapshot_version"], kb["snapshot_version"])
        mismatch = copy.deepcopy(kb)
        mismatch["snapshot_version"] = "different-reviewed-snapshot"
        mismatched_path = self.work / "mismatch.json"
        mismatched_path.write_text(json.dumps(mismatch), encoding="utf-8")
        result = self.render(source, self.work / "mismatched.html", "--kb", str(mismatched_path))
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertFalse((self.work / "mismatched.html").exists())

    def test_default_kb_is_omitted_when_the_report_names_another_snapshot(self):
        report = copy.deepcopy(self.static)
        report["kb_snapshot_version"] = "archived-snapshot-not-bundled"
        source = self.save(report)
        destination = self.work / "archived.html"
        result = self.render(source, destination)
        self.assertEqual(result.returncode, 0, result.stderr)
        _, data = self.read_html(destination)
        self.assertEqual(data["report"]["kb_snapshot_version"], report["kb_snapshot_version"])
        self.assertIsNone(data["kb"])

    def test_sentrycheck_sarif_renders_but_foreign_or_malformed_exports_do_not(self):
        source = self.save(self.failed)
        exported = self.command("report", "sarif", str(source))
        self.assertEqual(exported.returncode, 1, exported.stderr)
        sarif = json.loads(exported.stdout)
        sarif_path = self.save(sarif, "report.sarif")
        result = self.render(sarif_path, self.work / "sarif.html")
        self.assertEqual(result.returncode, 0, result.stderr)
        _, data = self.read_html(self.work / "sarif.html")
        self.assertEqual(data["input_kind"], "sarif")
        self.assertEqual(data["report"], sarif)
        self.assertFalse(data["validation"]["semantic_consistency"])
        self.assertFalse(data["validation"]["authenticated"])
        static_source = self.save(self.static, "static.json")
        static_export = self.command("report", "sarif", str(static_source))
        self.assertEqual(static_export.returncode, 2, static_export.stderr)
        static_sarif = json.loads(static_export.stdout)
        static_path = self.save(static_sarif, "static.sarif")
        result = self.render(static_path, self.work / "static-sarif.html")
        self.assertEqual(result.returncode, 0, result.stderr)
        _, static_data = self.read_html(self.work / "static-sarif.html")
        self.assertEqual(static_data["report"], static_sarif)
        for case in ["foreign-tool", "wrong-version", "missing-status", "multiple-runs", "false-clean-assessment", "wrong-rule-index", "mismatched-evidence-tier", "complete-imported", "complete-without-profile"]:
            with self.subTest(case=case):
                bad = copy.deepcopy(sarif)
                if case == "foreign-tool": bad["runs"][0]["tool"]["driver"]["name"] = "ANOTHER-SCANNER"
                if case == "wrong-version": bad["version"] = "2.0.0"
                if case == "missing-status": del bad["runs"][0]["properties"]["scanStatus"]
                if case == "multiple-runs": bad["runs"].append(copy.deepcopy(bad["runs"][0]))
                if case == "false-clean-assessment": bad["runs"][0]["properties"]["assessment"] = "no-incompatibility-observed-in-profile"
                if case == "wrong-rule-index": bad["runs"][0]["results"][0]["ruleIndex"] = len(bad["runs"][0]["tool"]["driver"]["rules"])
                if case == "mismatched-evidence-tier": bad["runs"][0]["properties"]["evidenceTier"] = "dynamic-native-only"
                if case in ("complete-imported", "complete-without-profile"):
                    run = bad["runs"][0]
                    run["properties"]["scanStatus"] = "complete"
                    run["invocations"][0]["executionSuccessful"] = True
                    run["invocations"][0]["toolExecutionNotifications"] = []
                    run["properties"]["provenance"] = "locally-executed" if case == "complete-without-profile" else "imported-user-supplied"
                    if case == "complete-without-profile":
                        del run["properties"]["profileSha256"]
                        for result in run["results"]:
                            result["properties"]["dynamicEvidence"]["provenance"] = "locally-executed"
                bad_source = self.save(bad, case + ".sarif")
                destination = self.work / (case + ".html")
                result = self.render(bad_source, destination)
                self.assertEqual(result.returncode, 2, result.stderr)
                self.assertFalse(destination.exists())

    def test_output_is_required_and_render_rejects_execution_options(self):
        source = self.save()
        result = self.command("report", "render", str(source))
        self.assertEqual(result.returncode, 2, result.stderr)
        result = self.render(source, self.work / "bad-options.html", "--runsc-bin", "must-not-execute")
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertFalse((self.work / "bad-options.html").exists())


if __name__ == "__main__":
    unittest.main()
