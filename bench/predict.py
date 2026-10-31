"""BT-01: deterministic report -> predicted label class mapping, published before evaluation.

PRD v2 requires this function to be defined and committed ahead of scoring, and requires
that incomplete scans never silently count as passes. The rules below read only fields the
report schema actually carries; anything the tool cannot evidence becomes `indeterminate`
and is reported as abstention, never folded into an accuracy denominator silently.

Ordering is a deliberate severity ladder: the first matching rule wins, so a case that both
tolerated a probe and silently degraded is scored as the degradation.
"""
from pathlib import Path

from bench.common import BENCH, BenchError, read_json, rel_path, resolve, write_json

LABEL_CLASSES = ("hard-failure", "silent-degradation", "performance-regression", "tolerated",
                 "compatible", "indeterminate")
DYNAMIC_TIERS = ("dynamic-native-only", "dynamic-runsc-diff", "dynamic-kata-diff")

# Scan/doctor emit free-text reasons; codes keep the analysis groupable and stable (BT-05).
REASON_CODES = (
    ("no-image-digest", "input has no oci manifest digest"),
    ("kb-no-coverage", "kb has no verified release coverage"),
    ("kb-stale", "kb snapshot is"),
    ("no-elf-files", "no elf binaries were found"),
    ("static-only", "static-only scan"),
    ("native-only-evidence", "native-only evidence cannot confirm"),
    ("imported-provenance", "execution provenance is user-supplied"),
    ("smoke-coverage-only", "only smoke/startup coverage"),
    ("baseline-failed", "the native baseline did not satisfy"),
    ("guest-trace-incomplete", "guest trace collection is missing"),
    ("nondeterministic-output", "varied within the same runtime"),
    ("digest-mismatch", "digest mismatch"),
)

RULES = (
    {"id": "R1", "class": "hard-failure", "when": "any finding with severity hard-failure (schema forces a dynamic runsc/kata tier)"},
    {"id": "R2", "class": "silent-degradation", "when": "any finding with severity silent-degradation"},
    {"id": "R3", "class": "performance-regression", "when": "any finding with severity performance-regression"},
    {"id": "R4", "class": "tolerated", "when": "dynamic.fallback_observations is non-empty and no R1-R3 finding exists"},
    {"id": "R5", "class": "compatible", "when": "status complete, dynamic tier is runsc/kata diff, no findings above compatibility-risk"},
    {"id": "R6", "class": "indeterminate", "when": "none of the above, including every incomplete or static-only report"},
)


def reason_codes(reasons):
    codes = []
    for reason in reasons or []:
        lowered = str(reason).lower()
        code = next((name for name, needle in REASON_CODES if needle in lowered), "other")
        if code == "other":
            codes.append("other:" + lowered[:60])
        elif code not in codes:
            codes.append(code)
    return sorted(codes)


def predict(report):
    """Return the PRD 6.4 `predicted` block for one report document."""
    findings = report.get("findings") or []
    severities = sorted({finding.get("severity") for finding in findings})
    dynamic = report.get("dynamic") or {}
    tier = dynamic.get("evidence_tier") or "static-only"
    status = report.get("status") or "incomplete"
    reasons = report.get("incomplete_reasons") or []
    codes = reason_codes(reasons)

    if "hard-failure" in severities and tier in ("dynamic-runsc-diff", "dynamic-kata-diff"):
        label = "hard-failure"
    elif "silent-degradation" in severities:
        label = "silent-degradation"
    elif "performance-regression" in severities:
        label = "performance-regression"
    elif dynamic.get("fallback_observations"):
        label = "tolerated"
    elif status == "complete" and tier in ("dynamic-runsc-diff", "dynamic-kata-diff") \
            and severities in ([], ["compatibility-risk"]):
        label = "compatible"
    else:
        label = "indeterminate"
    complete = status == "complete"
    if not complete and label != "indeterminate":
        # An incomplete scan may still hold a real observed failure; keep the class but make
        # the incompleteness explicit so coverage metrics can exclude it if the plan says so.
        codes = codes or ["incomplete-with-observation"]
    return {"class": label, "tier": tier, "complete": complete, "status": status,
            "finding_severities": severities, "incomplete_reason_codes": codes}


def mapping_document():
    return {
        "schema_version": "1.0",
        "title": "SENTRYCHECK report-to-predicted-class mapping (BT-01)",
        "label_classes": list(LABEL_CLASSES),
        "rules": list(RULES),
        "precedence": "first matching rule wins; R6 always matches last",
        "incomplete_policy": "incomplete scans are predicted indeterminate unless a dynamic rule already fired, and are counted in coverage rather than dropped",
        "reason_codes": {code: needle for code, needle in REASON_CODES},
        "inputs_read": ["status", "incomplete_reasons", "findings[].severity",
                        "dynamic.evidence_tier", "dynamic.fallback_observations"],
    }


def publish_mapping(out=None):
    path = Path(out) if out else BENCH / "analysis" / "prediction-map.json"
    return write_json(path, mapping_document())


def iter_reports(paths):
    for item in paths:
        path = Path(item)
        if path.is_dir():
            for found in sorted(path.rglob("report.json")) + sorted(path.rglob("*.report.json")):
                yield found
        elif path.is_file():
            yield path
        else:
            raise BenchError("report path does not exist: %s" % path)


def command_predict(args):
    publish_mapping()
    if args.reports:
        paths = list(iter_reports(args.reports))
    else:
        from bench.store import RunStore
        store = RunStore(args.root)
        paths = []
        for record in store.records():
            report_ref = (record.get("artifacts") or {}).get("report")
            if report_ref:
                paths.append(resolve(report_ref["path"]))
    rows = []
    for path in sorted(paths, key=str):
        try:
            report = read_json(path)
        except (OSError, ValueError) as error:
            raise BenchError("unreadable report %s: %s" % (path, error))
        rows.append({"report": rel_path(path), "predicted": predict(report),
                     "image_digest": report.get("image_digest"), "kb_snapshot_version": report.get("kb_snapshot_version")})
    counts = {}
    for row in rows:
        counts[row["predicted"]["class"]] = counts.get(row["predicted"]["class"], 0) + 1
    print("reports=%d" % len(rows))
    for label in LABEL_CLASSES:
        if counts.get(label):
            print("  %-22s %d" % (label, counts[label]))
    if args.out:
        write_json(args.out, {"schema_version": "1.0", "count": len(rows), "rows": rows})
        print("wrote %s" % args.out)
    return 0
