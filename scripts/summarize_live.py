"""Summarize actual runtime observations without substituting synthetic results."""
import argparse
from datetime import datetime, timezone
import json
from pathlib import Path

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", type=Path, default=Path("artifacts/live-validation"))
    args = parser.parse_args()
    rows = []
    for path in sorted(args.directory.glob("*.report.json")):
        report = json.loads(path.read_text(encoding="utf-8"))
        dynamic = report.get("dynamic") or {}
        rows.append({"case": path.stem.removesuffix(".report"), "image_digest": report["image_digest"], "status": report["status"], "assessment": report["assessment"],
                     "evidence_tier": dynamic.get("evidence_tier", "static-only"), "provenance": dynamic.get("provenance"),
                     "native_exit_codes": [r["exit_code"] for r in dynamic.get("native", [])], "sandbox_exit_codes": [r["exit_code"] for r in dynamic.get("sandbox", [])],
                     "findings": [{"gap_id": f["gap_id"], "severity": f["severity"]} for f in report["findings"]],
                     "incomplete_reasons": report["incomplete_reasons"], "duration_ms": report["duration_ms"]})
    result = {"generated_at": datetime.now(timezone.utc).isoformat(), "scope": "Actual small-workload runtime observations; not a production compatibility corpus or a live Kubernetes test.", "cases": rows}
    (args.directory / "summary.json").write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8", newline="\n")
    for row in rows:
        print(row["case"], row["status"], row["evidence_tier"], "native", row["native_exit_codes"], "sandbox", row["sandbox_exit_codes"])
    # A workflow should not turn green if it could not perform the requested live checks.
    expected = {"baseline": [0, 0, 0], "behavior": [0, 0, 0], "bpf_optional": [0, 0, 0], "io_uring": [42, 42, 42], "io_uring_fallback": [0, 0, 0]}
    valid = len(rows) == len(expected) and all(
        row["case"] in expected and row["status"] == "complete" and row["provenance"] == "locally-executed"
        and row["evidence_tier"] == "dynamic-runsc-diff" and row["native_exit_codes"] == [0, 0, 0]
        and row["sandbox_exit_codes"] == expected[row["case"]]
        and any(f["severity"] == "hard-failure" for f in row["findings"]) == (row["case"] == "io_uring")
        for row in rows)
    return 0 if valid else 2

if __name__ == "__main__":
    raise SystemExit(main())
