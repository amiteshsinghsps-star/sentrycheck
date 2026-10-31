"""Evaluate labeled reports by category/evidence tier without inventing ground truth."""
import argparse
from collections import defaultdict
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import make_fixtures

ROOT = Path(__file__).resolve().parents[1]

def metrics(rows):
    groups = defaultdict(lambda: {"tp": 0, "fp": 0, "tn": 0, "fn": 0, "unlabeled": 0, "incomplete": 0, "count": 0})
    for row in rows:
        group = groups[row["category"] + "/" + row["evidence_tier"]]
        group["count"] += 1
        group["incomplete"] += int(row["status"] != "complete")
        expected = row["expected"]
        if expected is None:
            group["unlabeled"] += 1
        else:
            group[("t" if bool(expected) == row["flagged"] else "f") + ("p" if row["flagged"] else "n")] += 1
    for group in groups.values():
        group["precision"] = group["tp"] / (group["tp"] + group["fp"]) if group["tp"] + group["fp"] else None
        group["recall"] = group["tp"] / (group["tp"] + group["fn"]) if group["tp"] + group["fn"] else None
    return dict(groups)

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--suite", choices=["synthetic", "live"], default="synthetic")
    parser.add_argument("--binary", type=Path, default=ROOT / "target" / "debug" / ("sentrycheck.exe" if os.name == "nt" else "sentrycheck"))
    parser.add_argument("--manifest", type=Path, default=ROOT / "corpus" / "manifest.json")
    parser.add_argument("--version", default="20260921.0")
    parser.add_argument("--only", action="append")
    parser.add_argument("--out", type=Path, default=ROOT / "artifacts" / "evaluation")
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)
    if args.suite == "synthetic":
        fixture_root = args.out / "fixtures"
        subprocess.run([sys.executable, str(ROOT / "scripts/make_fixtures.py"), "--out", str(fixture_root)], check=True)
        cases = [
            {"name": scenario, "image": str(fixture_root / "io-uring"), "evidence": str(fixture_root / "traces" / scenario / "evidence.json"), "expected": expected, "category": category, "severity": severity}
            for scenario, expected, category, severity in [
                ("hard-failure", True, "io_uring", "hard-failure"), ("fallback", False, "io_uring", "hard-failure"),
                ("output-diff", True, "behavioral-divergence", "silent-degradation"), ("performance", True, "performance", "performance-regression"),
                ("native-only", False, "io_uring", "hard-failure"), ("native-fails", False, "baseline-failure", "hard-failure")]]
    else:
        if not sys.platform.startswith("linux"):
            raise SystemExit("Live corpus evaluation requires Linux; synthetic traces are never substituted.")
        cases = json.loads(args.manifest.read_text(encoding="utf-8"))["cases"]
    rows = []
    for case in cases:
        if args.only and case["name"] not in args.only:
            continue
        path = args.out / (case["name"] + ".report.json")
        command = [str(args.binary.resolve()), "scan", case["image"], "--version", args.version, "--format", "json", "--output", str(path), "--cache", str(args.out / "cache")]
        if "profile" in case:
            command += ["--profile", case["profile"]]
        if "evidence" in case:
            command += ["--evidence", case["evidence"]]
        started = time.monotonic()
        process = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, encoding="utf-8", timeout=1800)
        duration = time.monotonic() - started
        if process.returncode not in (0, 1, 2):
            raise RuntimeError("scanner crashed: " + process.stderr[-2000:])
        if not process.stdout:
            report = {"status": "incomplete", "findings": [], "dynamic": None, "incomplete_reasons": [process.stderr.strip()]}
        else:
            report = json.loads(process.stdout)
        tier = (report.get("dynamic") or {}).get("evidence_tier", "static-only")
        flagged = any(f["severity"] == case.get("severity", "hard-failure") for f in report["findings"])
        rows.append({"name": case["name"], "category": case["category"], "expected": case.get("expected"), "flagged": flagged, "evidence_tier": tier,
                     "status": report["status"], "image_digest": report.get("image_digest"), "wall_seconds": round(duration, 4), "exit_code": process.returncode,
                     "report": str(path), "incomplete_reasons": report.get("incomplete_reasons", [])})
        print(case["name"], report["status"], "flagged=" + str(flagged), "tier=" + tier)
    result = {"generated_at": datetime.now(timezone.utc).isoformat(), "suite": args.suite,
              "claim_scope": "Synthetic parser/classifier regression ONLY; not live runtime accuracy." if args.suite == "synthetic" else "Profile-bounded live observations; null labels excluded from precision/recall.",
              "cases": rows, "by_category_and_tier": metrics(rows)}
    (args.out / "metrics.json").write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8", newline="\n")
    print("Wrote", args.out / "metrics.json")
    return int(any(row["expected"] is not None and bool(row["expected"]) != row["flagged"] for row in rows))

if __name__ == "__main__":
    raise SystemExit(main())
