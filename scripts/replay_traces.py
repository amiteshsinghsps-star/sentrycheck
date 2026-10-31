"""Reparse saved live traces with the current parser; this does not execute workloads."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import subprocess


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--parser", type=Path, required=True)
    parser.add_argument("--output", type=Path, default=Path("artifacts/review-v03/trace-replay.json"))
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    rows = []
    for directory in ["live-validation", "live-baselines", "live-postgres"]:
        for report_path in sorted((root / "artifacts" / directory).glob("*.report.json")):
            report = json.loads(report_path.read_text(encoding="utf-8"))
            dynamic = report.get("dynamic") or {}
            for runtime in ["native", "sandbox"]:
                for index, run in enumerate(dynamic.get(runtime, [])):
                    # Captures retained by the live scripts use a workspace artifact path.
                    suffix = run["trace_ref"].replace("\\", "/").split("/artifacts/", 1)[1]
                    path = (root / "artifacts" / suffix).resolve()
                    path.relative_to(root / "artifacts")
                    digest = "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()
                    if digest != run["trace_sha256"]:
                        raise ValueError(f"recorded trace digest does not match: {path}")
                    result = subprocess.run([str(args.parser.resolve()), run["trace_kind"], str(path)],
                                            capture_output=True, text=True, encoding="utf-8", check=True)
                    summary = json.loads(result.stdout)
                    old = run["trace_summary"]
                    issues = [key for key in ["event_count", "syscalls", "errors"] if summary[key] != old[key]]
                    for key in ["unfinished_count", "discarded_guest_records", "truncated"]:
                        if summary[key]:
                            issues.append(key)
                    rows.append({"case": report_path.stem.removesuffix(".report"), "runtime": runtime,
                                 "repetition": index, "captured_by_version": report["sentrycheck_version"],
                                 "trace": path.relative_to(root).as_posix(), "trace_sha256": digest,
                                 "summary": summary, "issues": issues})
    result = {"recorded_at": datetime.now(timezone.utc).isoformat(),
              "scope": "Reparse existing trace bytes and compare event/errno counts; not new workload executions or refreshed attestations.",
              "parser_sha256": "sha256:" + hashlib.sha256((root / "crates/sentrycheck-dynamic/src/trace.rs").read_bytes()).hexdigest(),
              "trace_count": len(rows), "status": "passed" if rows and all(not r["issues"] for r in rows) else "failed",
              "traces": rows}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8", newline="\n")
    for row in rows:
        if row["issues"]:
            print(row["case"], row["runtime"], row["repetition"], row["issues"])
    print(result["status"], len(rows), "retained traces,", sum(r["summary"]["event_count"] for r in rows), "events")
    return 0 if result["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
