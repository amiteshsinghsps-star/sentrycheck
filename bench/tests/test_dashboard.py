"""Tests for bench/dashboard.py: HTML generation, section presence, and idempotency."""
import unittest

from bench.tests import support


class DashboardTests(unittest.TestCase):
    def setUp(self):
        self.root = support.scratch_root("dashboard")

    def tearDown(self):
        support.cleanup(self.root)

    def test_generate_dashboard_produces_html_file(self):
        from bench.dashboard import generate_dashboard
        out_dir = self.root / "dash"
        path = generate_dashboard(out=str(out_dir))
        self.assertTrue(path.is_file(), "generate_dashboard must return an existing file path")
        self.assertEqual(path.suffix, ".html")

    def test_dashboard_contains_required_sections(self):
        from bench.dashboard import generate_dashboard
        out_dir = self.root / "dash"
        path = generate_dashboard(out=str(out_dir))
        html = path.read_text(encoding="utf-8")
        self.assertIn("<html", html.lower())
        self.assertIn("SENTRYCHECK", html)
        # Core suite identifiers expected in report
        for suite in ("BM-01", "BM-02", "BM-07", "BM-08"):
            self.assertIn(suite, html, "Dashboard must reference %s" % suite)

    def test_dashboard_is_self_contained(self):
        """No external resource URLs — the file must render offline."""
        from bench.dashboard import generate_dashboard
        out_dir = self.root / "dash"
        path = generate_dashboard(out=str(out_dir))
        html = path.read_text(encoding="utf-8")
        for external in ("https://", "http://", "cdn.jsdelivr", "fonts.googleapis"):
            self.assertNotIn(external, html,
                             "Dashboard must not reference external resource: %s" % external)

    def test_generate_dashboard_is_idempotent(self):
        """Calling twice with the same data must produce the same file bytes."""
        from bench.dashboard import generate_dashboard
        out_dir = self.root / "dash"
        path1 = generate_dashboard(out=str(out_dir))
        first_bytes = path1.read_bytes()
        path2 = generate_dashboard(out=str(out_dir))
        self.assertEqual(first_bytes, path2.read_bytes(),
                         "generate_dashboard must be deterministic across calls")

    def test_dashboard_directory_is_created(self):
        from bench.dashboard import generate_dashboard
        nested = self.root / "deep" / "nested" / "out"
        path = generate_dashboard(out=str(nested))
        self.assertTrue(nested.is_dir())
        self.assertTrue(path.is_file())


if __name__ == "__main__":
    unittest.main()
