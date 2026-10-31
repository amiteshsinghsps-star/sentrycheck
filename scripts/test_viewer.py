"""Exercise the offline viewer in an installed browser; never download a browser.

All workload reports in this test are explicitly synthetic fixtures. These checks
measure viewer behavior and evidence presentation, not runtime compatibility.
Requires the optional Python playwright package and a built sentrycheck CLI.
"""
import argparse
import copy
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone


ROOT = Path(__file__).resolve().parents[1]


def installed_browser(explicit):
    if explicit:
        path = Path(explicit).expanduser().resolve()
        if not path.is_file():
            raise RuntimeError(f"Browser executable does not exist: {path}")
        return path
    candidates = []
    if os.name == "nt":
        for variable in ("PROGRAMFILES(X86)", "PROGRAMFILES", "LOCALAPPDATA"):
            base = os.environ.get(variable)
            if base:
                candidates.extend([Path(base) / "Microsoft/Edge/Application/msedge.exe",
                                   Path(base) / "Google/Chrome/Application/chrome.exe"])
    else:
        for name in ("google-chrome", "google-chrome-stable", "chromium", "chromium-browser", "microsoft-edge"):
            if found := shutil.which(name):
                candidates.append(Path(found))
    for candidate in candidates:
        if candidate.is_file():
            return candidate.resolve()
    raise RuntimeError("No installed Chrome/Chromium/Edge found; use --browser PATH. This script never downloads one.")


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def fixtures(binary, directory):
    spec = importlib.util.spec_from_file_location("viewer_fixtures", ROOT / "scripts/make_fixtures.py")
    helper = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(helper)

    def command(*args, expected=0):
        result = subprocess.run([str(binary), *map(str, args)], cwd=ROOT, capture_output=True,
                                text=True, encoding="utf-8", timeout=45)
        if result.returncode != expected:
            raise RuntimeError(f"CLI {' '.join(map(str, args[:2]))} returned {result.returncode}, expected {expected}: {result.stderr[-4000:]}")
        return result.stdout

    image = directory / "image"
    digest = helper.oci(image, {"workload": helper.elf(bytes.fromhex("b8a90100000f05b83c00000031ff0f05"))})
    common = ("scan", image, "--format", "json", "--cache", directory / "cache", "--version", "20260921.0")
    static = json.loads(command(*common, "--static-only", expected=2))
    bundle = helper.evidence(directory / "evidence", digest, "hard-failure")
    failed = json.loads(command(*common, "--evidence", bundle, expected=1))
    require(static["candidate_gaps"], "Static fixture must contain at least one candidate")
    require(failed["findings"], "Failure fixture must contain findings")
    documents = {"static": static, "failed": failed}
    # Deliberately fabricated Kata guest records verify UI mechanics only.
    kata_bundle = helper.evidence(directory / "kata-evidence", digest, "fallback")
    kata_data = json.loads(kata_bundle.read_text())
    kata_data["target_runtime"].update(name="kata", version="3.3.0")
    for record in kata_data["sandbox"]:
        record.update(runtime="kata", runtime_version="3.3.0", trace_kind="strace-guest")
        trace = b'1 io_uring_setup(8, {flags=0}) = 3\n1 write(1, "ok\\n", 3) = 3\n1 exit_group(0) = ?\n'
        (kata_bundle.parent / record["trace"]).write_bytes(trace)
        record["trace_sha256"] = helper.digest(trace)
    kata_bundle.write_text(json.dumps(kata_data))
    kata_common = ("scan", image, "--runtime", "kata", "--version", "3.3.0", "--format", "json", "--cache", directory / "cache")
    kata = json.loads(command(*kata_common, "--evidence", kata_bundle, expected=2))
    kata_static = json.loads(command(*kata_common, "--static-only", expected=2))
    gvisor_path = directory / "matrix-gvisor.json"
    kata_path = directory / "matrix-kata.json"
    gvisor_path.write_text(json.dumps(failed))
    for name, report in [("matrix", kata), ("matrix_missing", kata_static)]:
        kata_path.write_text(json.dumps(report))
        documents[name] = json.loads(command("report", "compare", gvisor_path, kata_path, "--format", "json", expected=1))
    attack = copy.deepcopy(static)
    attack_text = '</script><script id="viewer-injected">globalThis.__sentrycheckPwned=true</script><img id="viewer-injected" src="https://example.invalid/leak" onerror="globalThis.__sentrycheckPwned=true"> & \u2028 \u2029'
    attack["image"] = attack_text
    attack["limitations"].append(attack_text)
    attack["candidate_gaps"] = []
    for index, scheme in enumerate(("javascript:globalThis.__sentrycheckPwned=true", "data:text/html,<script>alert(1)</script>", "file:///sentrycheck-must-not-open")):
        candidate = copy.deepcopy(static["candidate_gaps"][0])
        candidate["description"] = attack_text
        candidate["source_binary"] = f"/synthetic/unsafe-citation-{index}"
        candidate["citation"]["title"] = "Synthetic untrusted citation"
        candidate["citation"]["url"] = scheme
        attack["candidate_gaps"].append(candidate)
    documents["attack"] = attack
    many = copy.deepcopy(static)
    many["candidate_gaps"] = []
    for index in range(600):
        candidate = copy.deepcopy(static["candidate_gaps"][0])
        candidate["source_binary"] = f"/synthetic/pagination-{index:05d}"
        candidate["description"] = f"Synthetic pagination sentinel {index:05d}; no workload measurement."
        many["candidate_gaps"].append(candidate)
    documents["many"] = many
    paths = {}
    for name, document in documents.items():
        source = directory / f"{name}.json"
        source.write_text(json.dumps(document, ensure_ascii=False), encoding="utf-8")
        html = directory / f"{name}.html"
        command("report", "render", source, "--output", html)
        paths[name] = {"source": source, "html": html, "report": document}
    sarif = json.loads(command("report", "sarif", paths["failed"]["source"], expected=1))
    source = directory / "failed.sarif"
    source.write_text(json.dumps(sarif), encoding="utf-8")
    html = directory / "sarif.html"
    command("report", "render", source, "--output", html)
    paths["sarif"] = {"source": source, "html": html, "report": sarif}
    malformed = directory / "malformed.json"
    malformed.write_text('{"schema_version":', encoding="utf-8")
    paths["malformed"] = malformed
    return paths


def check_viewer(playwright, browser_path, paths, summary, artifacts):
    browser = playwright.chromium.launch(executable_path=str(browser_path), headless=True,
                                        args=["--disable-background-networking", "--disable-component-update", "--no-first-run"])
    context = browser.new_context(viewport={"width": 1440, "height": 1000}, offline=True)
    errors, requests, dialogs = [], [], []
    context.route(re.compile(r"^https?://"), lambda route: route.abort())
    page = context.new_page()
    page.set_default_timeout(12000)
    page.on("pageerror", lambda error: errors.append(str(error)))
    page.on("request", lambda request: requests.append(request.url) if request.url.startswith(("http://", "https://")) else None)

    def dismiss(dialog):
        dialogs.append({"type": dialog.type, "message": dialog.message})
        dialog.dismiss()
    page.on("dialog", dismiss)

    def ready():
        page.locator("#main-content h1").wait_for(state="visible")
        require(page.locator(".fatal-panel").count() == 0, "Viewer displayed its fatal-error screen")

    def open_document(name, fragment="overview"):
        page.goto(paths[name]["html"].as_uri() + "#" + fragment, wait_until="load")
        ready()
        require(page.locator(".demo-banner").count() == 0, "Rendered evidence was replaced with demo data")

    def navigate(label):
        link = page.locator("#navigation").get_by_role("link", name=re.compile(label, re.I)).first
        target = link.get_attribute("href")
        link.click()
        page.wait_for_function("wanted => location.hash === wanted", arg=target)
        ready()

    def no_overflow():
        geometry = page.evaluate("""() => ({viewport: document.documentElement.clientWidth,
            document: document.documentElement.scrollWidth, body: document.body.scrollWidth})""")
        require(geometry["document"] <= geometry["viewport"] + 2 and geometry["body"] <= geometry["viewport"] + 2,
                f"Horizontal overflow: {geometry}")
        return geometry

    def capture(name):
        if artifacts:
            page.screenshot(path=str(artifacts / name), full_page=True)

    def check(name, action):
        start = time.monotonic()
        details = action() or {}
        require(not errors, "Uncaught viewer JavaScript errors: " + "; ".join(errors))
        require(not dialogs, f"Unexpected browser dialogs: {dialogs}")
        require(not requests, f"Viewer attempted external HTTP requests: {requests}")
        summary["checks"].append({"name": name, "passed": True, "duration_ms": round((time.monotonic() - start) * 1000), **details})
        print("PASS " + name, file=sys.stderr, flush=True)

    try:
        def overview():
            open_document("failed")
            text = page.locator("#main-content").inner_text().lower()
            require("incompatibility observed" in text and "incomplete" in text, "Failure and incomplete evidence must remain visible")
            require("authenticity is not verified" in text, "CLI rendering must not claim authentication")
            metrics = no_overflow()
            capture("desktop-overview.png")
            return metrics
        check("desktop_evidence_and_offline_render", overview)

        def static_scope():
            open_document("static")
            title = page.locator(".status-strip h3").inner_text().lower()
            require("insufficient evidence" in title, "Static-only report was presented as a clean compatibility result")
            navigate("Trace timeline")
            require("no dynamic observations" in page.locator("#main-content").inner_text().lower(), "Static input invented trace observations")
        check("static_evidence_stays_unconfirmed", static_scope)

        def detail_and_filters():
            open_document("failed")
            navigate("Findings")
            page.locator("#main-content input[type=search]").fill("sentinel-with-no-matches")
            require(page.locator("#main-content .finding-row").count() == 0, "Finding search did not filter the visible list")
            page.locator("#main-content input[type=search]").fill("")
            page.locator("#main-content select").first.select_option("hard-failure")
            require(page.locator("#main-content .finding-row").count() == 1, "Severity filter did not isolate observed workload failure")
            link = page.locator("#main-content .finding-row").first
            target = link.get_attribute("href")
            link.click()
            page.wait_for_function("wanted => location.hash === wanted", arg=target)
            ready()
            page.wait_for_selector("#main-content .detail-title", timeout=15000)
            detail_text = page.locator("#main-content").inner_text()
            require("causality" in detail_text.lower(), "Finding detail omitted evidence causality | hash=" + page.evaluate("location.hash") + " | text=" + detail_text[:1800].replace("\n", " / "))
            citations = page.locator("#main-content a[href^='https://']")
            require(citations.count() > 0, "Finding detail has no source citation")
            for rel in citations.evaluate_all("links => links.map(link => link.getAttribute('rel') || '')"):
                require("noopener" in rel and "noreferrer" in rel, "External citation lacks safe browsing attributes")
            capture("finding-detail.png")
        check("finding_navigation_search_filter_and_citation", detail_and_filters)

        def kb_and_trace():
            navigate("Knowledge base")
            require("snapshot" in page.locator("#main-content").inner_text().lower(), "Matching KB snapshot was not displayed")
            page.locator("#main-content input[type=search]").fill("io_uring")
            require(page.locator("#main-content .kb-row").count() > 0, "KB search did not return the known io_uring category")
            navigate("Trace timeline")
            require(page.locator("#main-content .observation").count() == 6, "Trace view did not preserve the six synthetic run observations")
            require("discarded" in page.locator("#main-content").inner_text().lower(), "Trace view hides dropped-record accounting")
            unmatched = copy.deepcopy(paths["static"]["report"])
            unmatched["target_runtime"]["architecture"] = "386"
            unmatched["platform"] = "linux/386"
            page.locator("#report-file").set_input_files({"name": "unmatched-architecture.json", "mimeType": "application/json", "buffer": json.dumps(unmatched).encode()})
            page.get_by_text("Local file: unmatched-architecture.json", exact=True).wait_for(state="visible")
            navigate("Knowledge base")
            require("no matching knowledge base attached" in page.locator("#main-content").inner_text().lower(), "Local import retained KB entries for an uncovered architecture")
        check("knowledge_and_trace_navigation", kb_and_trace)

        def local_import():
            open_document("static")
            with page.expect_file_chooser() as chooser:
                page.locator("#import-button").click()
            chooser.value.set_files(str(paths["failed"]["source"]))
            page.get_by_text(re.compile("Browser structural checks only", re.I)).first.wait_for(state="visible")
            require("incompatibility observed" in page.locator(".status-strip h3").inner_text().lower(), "Local imported report did not replace the active evidence")
            require("CLI consistency checks were reported" not in page.locator("#main-content").inner_text(), "Browser import inherited CLI semantic-validation trust")
        check("local_file_chooser_import_downgrades_validation", local_import)

        def malformed_import():
            cases = [("malformed-json", paths["malformed"].read_bytes())]
            for kind in ("complete-imported", "missing-profile", "invocation", "tier", "rule-index"):
                bad = copy.deepcopy(paths["sarif"]["report"])
                run = bad["runs"][0]
                if kind in ("complete-imported", "missing-profile"):
                    run["properties"]["scanStatus"] = "complete"
                    run["invocations"][0]["executionSuccessful"] = True
                    run["invocations"][0]["toolExecutionNotifications"] = []
                    if kind == "complete-imported":
                        run["results"] = []
                        run["properties"]["assessment"] = "no-incompatibility-observed-in-profile"
                    if kind == "missing-profile":
                        run["properties"]["provenance"] = "locally-executed"
                        del run["properties"]["profileSha256"]
                if kind == "invocation": run["invocations"][0]["executionSuccessful"] = True
                if kind == "tier": run["properties"]["evidenceTier"] = "dynamic-native-only"
                if kind == "rule-index": run["results"][0]["ruleIndex"] = len(run["tool"]["driver"]["rules"])
                cases.append(("sarif-" + kind, json.dumps(bad).encode()))
            for kind in ("smoke", "discarded", "unfinished", "baseline", "repetitions", "runtime-version"):
                bad = copy.deepcopy(paths["failed"]["report"])
                bad.update(status="complete", incomplete_reasons=[])
                bad["dynamic"]["provenance"] = "locally-executed"
                if kind == "smoke":
                    bad["dynamic"]["profile"]["coverage"] = "smoke"
                    bad["findings"] = []
                    bad["assessment"] = "no-incompatibility-observed-in-profile"
                if kind == "discarded": bad["dynamic"]["sandbox"][0]["trace_summary"]["discarded_guest_records"] = 1
                if kind == "unfinished": bad["dynamic"]["sandbox"][0]["trace_summary"]["unfinished_count"] = 1
                if kind == "baseline": bad["dynamic"]["native"][0]["exit_code"] = 99
                if kind == "repetitions": bad["dynamic"]["sandbox"].pop()
                if kind == "runtime-version": bad["dynamic"]["sandbox"][0]["runtime_version"] = "20990101.0"
                cases.append(("json-" + kind, json.dumps(bad).encode()))
            for index, (name, data) in enumerate(cases):
                restore_name = f"restore-{index}.json"
                page.locator("#report-file").set_input_files({"name": restore_name, "mimeType": "application/json", "buffer": json.dumps(paths["failed"]["report"]).encode()})
                page.get_by_text(f"Local file: {restore_name}", exact=True).wait_for(state="visible")
                require(page.locator("#global-notice .error-banner").count() == 0, "Valid report did not clear the prior import error")
                prior = page.locator("#sidebar-record .record-name").inner_text()
                page.locator("#report-file").set_input_files({"name": name + ".json", "mimeType": "application/json", "buffer": data})
                page.locator("#global-notice .error-banner").wait_for(state="visible")
                require("could not open report" in page.locator("#global-notice").inner_text().lower(), f"Invalid {name} import did not produce a visible error")
                require(page.locator("#sidebar-record .record-name").inner_text() == prior, f"Invalid {name} import silently replaced the current report")
            return {"rejected_import_cases": len(cases)}
        check("malformed_import_preserves_previous_report", malformed_import)

        def injection():
            open_document("attack")
            for index in range(3):
                navigate("Findings")
                page.get_by_role("button", name=re.compile("^Static candidates")).click()
                rows = page.locator("#main-content .finding-row")
                require(rows.count() == 3, "Unsafe citation fixture did not load all candidates")
                target = rows.nth(index).get_attribute("href")
                rows.nth(index).click()
                page.wait_for_function("wanted => location.hash === wanted", arg=target)
                unsafe = page.locator("a[href]").evaluate_all("links => links.map(link => link.getAttribute('href')).filter(href => /^(javascript|data|file):/i.test(href.trim()))")
                require(not unsafe, f"Untrusted citation became an actionable URL: {unsafe}")
                require(page.locator("#viewer-injected").count() == 0, "Report text created an executable HTML element")
                require(page.evaluate("typeof globalThis.__sentrycheckPwned === 'undefined'"), "Untrusted report text executed JavaScript")
            # The same data must be safe through the browser's local-file path.
            page.locator("#report-file").set_input_files(str(paths["attack"]["source"]))
            page.get_by_text(re.compile("Browser structural checks only", re.I)).first.wait_for(state="visible")
            require(page.locator("#viewer-injected").count() == 0 and page.evaluate("typeof globalThis.__sentrycheckPwned === 'undefined'"), "Local import executed untrusted report markup")
        check("script_escape_and_unsafe_citation_schemes", injection)

        def reduced_sarif():
            open_document("sarif")
            require("reduced" in page.locator("#global-notice").inner_text().lower(), "SARIF omitted its reduced-evidence notice")
            navigate("Trace timeline")
            require("unavailable in sarif" in page.locator("#main-content").inner_text().lower(), "SARIF view invented trace summaries")
            navigate("Findings")
            page.get_by_role("button", name=re.compile("^Static candidates")).click()
            require("not included in sarif" in page.locator("#main-content").inner_text().lower(), "SARIF invented static candidate details")
        check("sarif_does_not_invent_missing_evidence", reduced_sarif)

        def matrix_views():
            open_document("matrix")
            selector = page.get_by_role("combobox", name="Runtime evidence", exact=True)
            require(selector.input_value() == "gvisor", "Matrix did not open the gVisor report")
            require("separate native baselines" in page.locator("#matrix-summary").inner_text().lower(), "Matrix hides separate baseline experiments")
            require("dynamic-runsc-diff" in page.locator("#matrix-summary").inner_text() and "dynamic-kata-diff" in page.locator("#matrix-summary").inner_text(), "Matrix collapsed the per-runtime evidence tiers")
            require("dynamic-three-way-diff" not in page.locator("#main-content").inner_text(), "Matrix invented a combined evidence tier")
            capture("matrix-overview.png")
            selector.select_option("kata")
            require("insufficient evidence" in page.locator(".status-strip h3").inner_text().lower(), "Kata selection inherited the gVisor failure")
            navigate("Knowledge base")
            require("no matching knowledge base attached" in page.locator("#main-content").inner_text().lower(), "Kata selection reused the gVisor KB")
            selector.select_option("gvisor")
            require(page.locator("#main-content .kb-row").count() > 0, "gVisor selection lost its matching KB")
            selector.select_option("kata")
            navigate("Trace timeline")
            require(page.locator("#main-content .observation").count() == 6, "Kata observations were replaced or dropped")
            page.reload(wait_until="load")
            ready()
            require(selector.input_value() == "kata", "Reloaded matrix link lost the selected runtime")
            page.locator("#report-file").set_input_files(str(paths["matrix"]["source"]))
            page.get_by_text(re.compile("Browser structural checks only", re.I)).first.wait_for(state="visible")
            require("CLI consistency checks were reported" not in page.locator("#main-content").inner_text(), "Matrix import inherited CLI-validation trust")
            open_document("matrix_missing")
            require("unavailable" in page.locator("#matrix-summary").inner_text().lower(), "Missing Kata observations were represented as success")
            page.get_by_role("combobox", name="Runtime evidence", exact=True).select_option("kata")
            navigate("Trace timeline")
            require("no dynamic observations" in page.locator("#main-content").inner_text().lower(), "Matrix manufactured a missing runtime trace")
        check("matrix_runtime_selection_scope_and_missing_observations", matrix_views)

        def invalid_matrix_import():
            for mutation in ("summary", "outcome", "profile", "image", "complete", "order", "target", "missing-runtime"):
                open_document("matrix")
                changed = copy.deepcopy(paths["matrix"]["report"])
                if mutation == "summary": changed["cross_runtime"]["comparable"] = False
                elif mutation == "outcome": changed["cross_runtime"]["outcomes"]["kata"] = "failure"
                elif mutation == "profile": changed["reports"][1]["dynamic"]["profile_sha256"] = "sha256:" + "a" * 64
                elif mutation == "image": changed["image_digest"] = "sha256:" + "b" * 64
                elif mutation == "complete": changed.update(status="complete", incomplete_reasons=[])
                elif mutation == "order": changed["reports"].reverse()
                elif mutation == "target": changed["target_runtimes"][1]["version"] = "latest"
                else: changed["reports"].pop()
                prior = page.locator("#matrix-summary").inner_text()
                page.locator("#report-file").set_input_files({"name": f"invalid-matrix-{mutation}.json", "mimeType": "application/json", "buffer": json.dumps(changed).encode()})
                page.locator("#global-notice .error-banner").wait_for(state="visible")
                require(page.locator("#matrix-summary").inner_text() == prior, f"Invalid matrix {mutation} replaced the previous comparison")
                require(page.get_by_role("combobox", name="Runtime evidence", exact=True).input_value() == "gvisor", f"Invalid matrix {mutation} changed the active runtime")
            return {"rejected_matrix_cases": 8}
        check("matrix_import_rejects_contradictory_summaries_and_identity", invalid_matrix_import)

        def bounded_pagination():
            open_document("many")
            navigate("Findings")
            page.get_by_role("button", name=re.compile("^Static candidates")).click()
            rows = page.locator("#main-content .finding-row")
            shown = rows.count()
            require(0 < shown <= 100, f"Candidate list is not paginated: {shown} DOM rows for 600 records")
            before = rows.first.inner_text()
            page.get_by_role("button", name=re.compile("^Next")).click()
            require(rows.first.inner_text() != before, "Pagination button did not change the visible records")
            page.locator("#main-content input[type=search]").fill("pagination sentinel 00599")
            require(rows.count() == 1 and "00599" in rows.first.inner_text(), "Search did not reach a candidate outside the original page")
            return {"records": 600, "initial_dom_rows": shown, "total_dom_elements": page.locator("*").count()}
        check("candidate_pagination_bounds_the_dom", bounded_pagination)

        def mobile():
            page.set_viewport_size({"width": 390, "height": 844})
            open_document("failed")
            metrics = no_overflow()
            capture("mobile-overview.png")
            navigate("Findings")
            no_overflow()
            navigate("Trace timeline")
            no_overflow()
            open_document("matrix")
            no_overflow()
            page.get_by_role("combobox", name="Runtime evidence", exact=True).select_option("kata")
            no_overflow()
            return metrics
        check("mobile_navigation_and_horizontal_layout", mobile)
        summary.update(passed=True, browser_version=browser.version, page_errors=errors,
                       external_http_requests=requests, unexpected_dialogs=dialogs)
    except Exception:
        capture("failure.png")
        summary.update(page_errors=errors, external_http_requests=requests, unexpected_dialogs=dialogs,
                       failed_page=page.url)
        raise
    finally:
        context.close()
        browser.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--browser", help="Installed Chrome, Chromium, or Edge executable")
    parser.add_argument("--binary", type=Path, default=Path(os.environ.get("SENTRYCHECK_BIN", ROOT / "target/debug" / ("sentrycheck.exe" if os.name == "nt" else "sentrycheck"))))
    parser.add_argument("--artifacts", type=Path, help="Optional output directory for summary.json and screenshots")
    args = parser.parse_args()
    summary = {"schema_version": "1.0", "scope": "Synthetic offline browser/renderer behavior; no live compatibility measurement.",
               "checked_at": datetime.now(timezone.utc).isoformat(), "passed": False, "checks": []}
    code = 0
    artifacts = args.artifacts.resolve() if args.artifacts else None
    try:
        from playwright.sync_api import sync_playwright
        binary = args.binary.resolve()
        if not binary.is_file():
            raise RuntimeError("Build sentrycheck first or supply --binary/SENTRYCHECK_BIN")
        browser = installed_browser(args.browser)
        summary["browser_executable"] = str(browser)
        if artifacts:
            artifacts.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="sentrycheck-viewer-") as directory:
            documents = fixtures(binary, Path(directory))
            with sync_playwright() as playwright:
                check_viewer(playwright, browser, documents, summary, artifacts)
    except Exception as error:
        summary["error"] = str(error)
        code = 1 if isinstance(error, AssertionError) or summary["checks"] else 2
    encoded = json.dumps(summary, indent=2, ensure_ascii=False) + "\n"
    if artifacts:
        artifacts.mkdir(parents=True, exist_ok=True)
        (artifacts / "summary.json").write_text(encoded, encoding="utf-8")
    print(encoded, end="")
    return code


if __name__ == "__main__":
    raise SystemExit(main())
