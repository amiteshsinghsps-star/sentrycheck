"""Phase 4: the link library is recorded as fetched, failures included."""
import unittest

from bench import sources
from bench.common import ROOT


class ClassificationTests(unittest.TestCase):
    def test_status_codes_map_to_findings(self):
        for status, outcome in [(200, "ok"), (206, "ok"), (301, "redirect"), (302, "redirect"),
                                (404, "not-found"), (403, "blocked"), (429, "rate-limited"),
                                (500, "server-error"), (418, "other")]:
            self.assertEqual(sources.classify(status, None), outcome, status)
        self.assertEqual(sources.classify(None, "timeout"), "error")

    def test_a_transport_error_is_not_retried_into_success(self):
        record = {"outcome": "error", "http_status": None, "error": "URLError: timed out",
                  "url": "https://example.invalid/x", "final_url": "https://example.invalid/x",
                  "resource": "example", "file": None}
        text = sources.summarize({"outcome_counts": {"error": 1}, "entries": [record],
                                  "not_located": [], "link_count": 1})
        self.assertIn("timed out", text)
        self.assertIn("example.invalid", text)


class NamingTests(unittest.TestCase):
    def test_github_blob_becomes_a_raw_url(self):
        raw = sources.github_raw("https://github.com/opencontainers/image-spec/blob/v1.0.1/spec.md")
        self.assertEqual(raw, "https://raw.githubusercontent.com/opencontainers/image-spec/v1.0.1/spec.md")

    def test_non_blob_urls_have_no_raw_counterpart(self):
        for url in ["https://github.com/google/gvisor", "https://gvisor.dev/docs/user_guide/compatibility/",
                    "https://github.com/opencontainers/image-spec"]:
            self.assertIsNone(sources.github_raw(url), url)

    def test_extension_prefers_the_content_type_then_the_magic(self):
        self.assertEqual(sources.extension_for("application/pdf", "https://x/y", b""), ".pdf")
        self.assertEqual(sources.extension_for("", "https://x/y", b"%PDF-1.7 rest"), ".pdf")
        self.assertEqual(sources.extension_for("text/html", "https://x/y.md", b"<html>"), ".html")
        self.assertEqual(sources.extension_for("", "https://x/y.md", b"junk"), ".md")
        self.assertEqual(sources.extension_for("application/octet-stream", "https://x/y", b"junk"), ".bin")

    def test_slug_is_a_filename(self):
        slug = sources.slugify("OCI Image Layout (v1.0.1)")
        self.assertRegex(slug, r"^[a-z0-9-]+$")
        self.assertTrue(len(slug) <= 60)


class LibraryTests(unittest.TestCase):
    def setUp(self):
        self.entries = sources.build_library()

    def test_the_library_is_the_prd_list(self):
        self.assertEqual(len(self.entries), 62)
        self.assertEqual(len(sources.NOT_LOCATED), 13)
        self.assertEqual(len({entry["url"] for entry in self.entries}), len(self.entries),
                         "the same url recorded twice would double-count a link integrity result")
        for entry in self.entries:
            self.assertIn(entry["section"], sources.SECTIONS)
            self.assertTrue(entry["note"], "an unexplained citation is not a reference")

    def test_every_url_is_https(self):
        for entry in self.entries:
            self.assertTrue(entry["url"].startswith("https://"), entry["url"])

    def test_fetched_manifest_records_more_than_it_succeeded(self):
        manifest = ROOT / "bench" / "sources" / "manifest.json"
        if not manifest.is_file():
            self.skipTest("the library has not been fetched on this host")
        import json
        document = json.loads(manifest.read_text(encoding="utf-8"))
        self.assertEqual(document["link_count"], len(sources.LIBRARY))
        self.assertEqual(sum(document["outcome_counts"].values()), document["link_count"])
        for entry in document["entries"]:
            if entry["outcome"] == "ok":
                self.assertTrue(entry["file"], entry["url"])
                self.assertTrue((ROOT / entry["file"]).is_file(), entry["file"])
            else:
                self.assertIsNone(entry["file"], "a failed fetch must not leave a partial document behind")


if __name__ == "__main__":
    unittest.main()
