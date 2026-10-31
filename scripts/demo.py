"""One-command retained-evidence verification or an explicit live reproduction.

Verification never claims fresh workload execution. Live full mode uses the
existing corpus scripts in new output/work directories and refuses unavailable
prerequisites rather than replaying saved observations.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import math
import os
from pathlib import Path
import shutil
import subprocess
import sys

import benchmark

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_REPORTS = [ROOT / "artifacts/review-v03/final-live/baseline.report.json",
                   ROOT / "artifacts/review-v03/final-live/io_uring.report.json"]
REFERENCE_KEYS = {"trace_ref", "stdout_ref", "stderr_ref", "trace_excerpt_ref"}


def now():
    return datetime.now(timezone.utc).isoformat()


def save(path, value):
    benchmark.write_json(path, value)


def rebase_references(value, mappings):
    """Only explicitly requested artifact-prefix relocation in a derived copy."""
    if isinstance(value, list):
        return [rebase_references(item, mappings) for item in value]
    if not isinstance(value, dict):
        return value
    result = {}
    for key, item in value.items():
        if key in REFERENCE_KEYS and isinstance(item, str):
            for old, new in mappings:
                if item == old or item.startswith(old + "/"):
                    item = str(Path(new) / item[len(old):].lstrip("/"))
                    break
        result[key] = rebase_references(item, mappings)
    return result


def mappings_from(values):
    result = []
    for value in values:
        if "=" not in value:
            raise ValueError("--artifact-prefix must have OLD=NEW form")
        old, new = value.split("=", 1)
        if not old or not new:
            raise ValueError("artifact prefixes cannot be empty")
        result.append((old.rstrip("/"), str(Path(new).resolve())))
    return result


def validate_reports(paths, binary, artifacts_root, out, mappings, fresh=False):
    records = []
    for index, original in enumerate(paths):
        original = original.resolve()
        # Validate original bytes before any explicit portability rewrite.
        original_validation = benchmark.validate_report(original, binary, ROOT)
        report = benchmark.load_json(original)
        checked_path = original
        if mappings:
            report = rebase_references(report, mappings)
            checked_path = out / f"relocated-{index}.report.json"
            save(checked_path, report)
        validation = benchmark.validate_report(checked_path, binary, ROOT, artifacts_root)
        if fresh and (report.get("status") != "complete" or (report.get("dynamic") or {}).get("provenance") != "locally-executed"):
            raise ValueError(f"live reproduction requires complete locally-executed evidence: {original}")
        records.append({"source_report": str(original), "source_report_sha256": original_validation["report_sha256"],
                        "checked_report": str(checked_path), "validation": validation, "scanned_at": report.get("scanned_at"),
                        "original_analyzer_version": report.get("sentrycheck_version"), "status": report.get("status"),
                        "assessment": report.get("assessment"), "image_digest": report.get("image_digest"),
                        "evidence_tier": (report.get("dynamic") or {}).get("evidence_tier", "static-only"),
                        "hard_failure": any(f.get("severity") == "hard-failure" for f in report.get("findings", [])),
                        "artifact_prefix_relocated": bool(mappings), "new_workload_execution": fresh})
    if not records:
        raise ValueError("no reports were selected")
    chosen = next((record for record in records if record["hard_failure"] and Path(record["source_report"]).name == "postgres.report.json"),
                  next((record for record in records if record["hard_failure"]), records[0]))
    render = subprocess.run([str(binary), "report", "render", chosen["checked_report"], "--output", str(out / "report.html")],
                            cwd=ROOT, capture_output=True, text=True, timeout=180)
    if render.returncode:
        raise ValueError("report rendering failed: " + render.stderr[-2000:])
    return records


def available_tool(name):
    path = shutil.which(name)
    if not path:
        raise ValueError(f"required live tool is unavailable: {name}")
    return str(Path(path).resolve())


def existing_parent(path):
    while not path.exists():
        path = path.parent
    return path


def live_preflight(args, binary):
    if not sys.platform.startswith("linux"):
        raise ValueError("live reproduction requires Linux; saved evidence is never substituted")
    if os.geteuid() != 0:
        raise ValueError("the existing live corpus/runtime scripts require a disposable Linux environment with root privileges")
    if not args.full and not args.manifest and not (args.image and args.profile):
        raise ValueError("live mode needs --full, --manifest, or both --image and --profile")
    if args.work_dir is None:
        raise ValueError("live mode requires an explicit new --work-dir")
    work = args.work_dir.resolve()
    if work.exists():
        raise ValueError("--work-dir must be new; existing runtime state is never reused")
    minimum = args.min_free_gib * 2**30
    if not math.isfinite(args.min_free_gib) or args.min_free_gib <= 0:
        raise ValueError("--min-free-gib must be positive")
    for path in [args.out.resolve(), work]:
        free = shutil.disk_usage(existing_parent(path)).free
        if free < minimum:
            raise ValueError(f"live output/work volume has {free / 2**30:.2f} GiB free; requested minimum is {args.min_free_gib:g} GiB: {path}")
    tools = {name: available_tool(name) for name in ["bash", "runc", "strace"]}
    runsc = benchmark.executable(str(args.runsc), ROOT)
    tools["runsc"] = str(runsc)
    if args.full:
        tools.update({name: available_tool(name) for name in ["gcc", "go", "skopeo", "ldd", "runuser"]})
        image = args.postgres_image.resolve() if args.postgres_image else ROOT / "artifacts/live-images/postgres"
        if not (image / "index.json").is_file() and not args.rebuild_postgres:
            raise ValueError("full mode requires an existing --postgres-image OCI layout, or explicit --rebuild-postgres")
        if args.rebuild_postgres:
            tools.update({name: available_tool(name) for name in ["curl", "make", "pkg-config", "bison", "flex"]})
            if subprocess.run([tools["pkg-config"], "--exists", "liburing"], check=False).returncode:
                raise ValueError("PostgreSQL rebuild requires liburing-dev; provision it before launching the demo")
    if args.full or args.include_node:
        for label, path in [("k3s", args.k3s), ("admission", args.admission), ("probe", args.probe)]:
            tools[label] = str(benchmark.executable(str(path), ROOT))
        tools["ip"] = available_tool("ip")
        if Path("/run/k3s/containerd/containerd.sock").exists():
            raise ValueError("existing K3s socket detected; use a disposable environment")
    return {"binary": str(binary), "tools": tools, "work_dir": str(work), "min_free_gib": args.min_free_gib,
            "note": "Free-space threshold is a prerequisite, not an upper bound on image/build/trace storage."}


def execute_stage(name, command, env, out, summary):
    print(f"Running live stage: {name}", flush=True)
    stage = {"name": name, "command": command, "started_at": now()}
    summary["stages"].append(stage)
    save(out / "summary.json", summary)
    with (out / f"{name}.stdout.log").open("wb") as stdout, (out / f"{name}.stderr.log").open("wb") as stderr:
        result = subprocess.run(command, cwd=ROOT, env=env, stdout=stdout, stderr=stderr)
    stage.update({"finished_at": now(), "exit_code": result.returncode,
                  "stdout_sha256": benchmark.digest_file(out / f"{name}.stdout.log"),
                  "stderr_sha256": benchmark.digest_file(out / f"{name}.stderr.log")})
    save(out / "summary.json", summary)
    if result.returncode:
        raise ValueError(f"live stage {name} failed with exit {result.returncode}; inspect its retained logs")


def live(args, binary, out, summary):
    plan = summary["preflight"]
    work = Path(plan["work_dir"])
    work.mkdir(parents=True)
    env = dict(os.environ)
    env.update({"SENTRYCHECK_BIN": str(binary), "SENTRYCHECK_RUNSC": plan["tools"]["runsc"],
                "SENTRYCHECK_TEMP_BASE": str(work / "tmp"), "SENTRYCHECK_LIVE_IMAGES": str(work / "images"),
                "SENTRYCHECK_LIVE_OUTPUT": str(out / "smoke"), "SENTRYCHECK_BASELINES_OUTPUT": str(out / "baselines"),
                "SENTRYCHECK_BASELINES_CACHE": str(work / "baseline-cache"), "SENTRYCHECK_GO_WORKLOAD": str(work / "bin/go-workload"),
                "SENTRYCHECK_POSTGRES_OUTPUT": str(out / "postgres"), "SENTRYCHECK_POSTGRES_CACHE": str(work / "postgres-cache"),
                "SENTRYCHECK_POSTGRES_IMAGE": str(args.postgres_image.resolve() if args.postgres_image else ROOT / "artifacts/live-images/postgres"),
                "SENTRYCHECK_POSTGRES_PACKAGED_IMAGE": str(work / "images/postgres"),
                "SENTRYCHECK_REBUILD_POSTGRES": "1" if args.rebuild_postgres else "0"})
    reports = []
    if args.full:
        for name, script in [("smoke", "live-smoke.sh"), ("baselines", "live-baselines.sh"), ("postgres", "live-postgres.sh")]:
            execute_stage(name, ["bash", str(ROOT / "scripts" / script)], env, out, summary)
        reports = sorted(path for directory in [out / "smoke", out / "baselines", out / "postgres"] for path in directory.glob("*.report.json"))
    else:
        if args.manifest:
            manifest = benchmark.check_manifest(benchmark.load_json(args.manifest))
            if not manifest.get("cases") or any(case["mode"] != "live" for case in manifest["cases"]):
                raise ValueError("live demo manifest must contain live-mode cases")
            if manifest.get("ci_pairs") or manifest.get("historical_reports") or manifest.get("kb_age"):
                raise ValueError("live demo manifest must contain only explicit live scan cases")
        else:
            manifest = {"schema_version": "1.0", "cases": [{"name": "workload", "image": str(args.image), "mode": "live",
                         "cache": "disabled", "warmups": 0, "repetitions": 1, "scan_args": ["--profile", str(args.profile.resolve()),
                         "--runsc-bin", plan["tools"]["runsc"], "--version", "20260921.0"]}]}
        save(out / "live-manifest.json", manifest)
        execute_stage("scans", [sys.executable, str(ROOT / "scripts/benchmark.py"), "run", "--binary", str(binary),
                      "--manifest", str(out / "live-manifest.json"), "--cwd", str(ROOT), "--out", str(out / "scans")], env, out, summary)
        scan_summary = benchmark.load_json(out / "scans/summary.json")
        samples = [json.loads(line) for line in (out / "scans/samples.jsonl").read_text().splitlines()]
        reports = sorted({Path(row["report_path"]) for row in samples if row.get("measurement_valid")})
        summary["scan_measurement_status"] = scan_summary["status"]
    if args.full or args.include_node:
        baseline = out / "baselines/go.report.json" if args.full else args.node_report
        if baseline is None:
            raise ValueError("--include-node without --full requires --node-report from a complete clean live report")
        env.update({"SENTRYCHECK_NODE_OUTPUT": str(out / "node"), "SENTRYCHECK_NODE_TEMP_BASE": str(work / "tmp"),
                    "SENTRYCHECK_NODE_REPORT": str(baseline.resolve()), "SENTRYCHECK_NODE_K3S": plan["tools"]["k3s"],
                    "SENTRYCHECK_NODE_RUNSC": plan["tools"]["runsc"], "SENTRYCHECK_NODE_ADMISSION": plan["tools"]["admission"],
                    "SENTRYCHECK_NODE_PROBE": plan["tools"]["probe"], "SENTRYCHECK_NODE_RECORD": "1",
                    "SENTRYCHECK_NODE_MEASURE": "1" if args.measure_node else "0"})
        execute_stage("node", ["bash", str(ROOT / "scripts/test-node-runtime-live.sh")], env, out, summary)
    return validate_reports(reports, binary, out, out, [], fresh=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=["verify", "live"], default="verify")
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--binary", type=Path, default=ROOT / "bin" / ("sentrycheck.exe" if os.name == "nt" else "sentrycheck-linux"))
    parser.add_argument("--report", type=Path, action="append", help="retained report; repeat to override the v0.3 demo pair")
    parser.add_argument("--artifacts-root", type=Path, default=ROOT)
    parser.add_argument("--artifact-prefix", action="append", default=[], help="explicit OLD=NEW artifact relocation in a derived report copy")
    parser.add_argument("--full", action="store_true", help="fresh smoke, language baselines, PostgreSQL, and real node checks")
    parser.add_argument("--include-node", action="store_true")
    parser.add_argument("--measure-node", action="store_true")
    parser.add_argument("--node-report", type=Path)
    parser.add_argument("--work-dir", type=Path)
    parser.add_argument("--min-free-gib", type=float, default=4)
    parser.add_argument("--manifest", type=Path)
    parser.add_argument("--image")
    parser.add_argument("--profile", type=Path)
    parser.add_argument("--postgres-image", type=Path)
    parser.add_argument("--rebuild-postgres", action="store_true")
    parser.add_argument("--runsc", type=Path, default=ROOT / ".cache/linux/bin/runsc")
    parser.add_argument("--k3s", type=Path, default=ROOT / ".cache/linux/bin/k3s")
    parser.add_argument("--admission", type=Path, default=ROOT / "bin/sentrycheck-admission-linux")
    parser.add_argument("--probe", type=Path, default=ROOT / "bin/sentrycheck-node-probe-linux")
    args = parser.parse_args()
    summary = {"schema_version": "1.0", "status": "running", "mode": args.mode, "started_at": now(), "stages": [],
               "script_sha256": benchmark.digest_file(__file__), "new_workload_execution_requested": args.mode == "live"}
    out = args.out.resolve()
    created_output = False
    try:
        if out.exists():
            raise ValueError("--out must be new; existing evidence is never overwritten")
        binary = benchmark.executable(str(args.binary), Path.cwd())
        summary["scanner"] = benchmark.identity(str(binary), ROOT)
        mappings = mappings_from(args.artifact_prefix)
        if args.mode == "verify":
            if args.full or args.include_node or args.measure_node or args.rebuild_postgres or args.image or args.manifest:
                raise ValueError("live execution options require --mode live; verify mode never executes a workload")
            summary["scope"] = "Revalidation of retained observations and a derived offline viewer; no workload or cluster execution was performed. Original report dates and analyzer versions remain authoritative."
        else:
            if args.report or mappings:
                raise ValueError("retained report/relocation options are not accepted in live mode")
            if args.full and (args.manifest or args.image or args.profile):
                raise ValueError("--full selects its fixed corpus; use a separate invocation for explicit --manifest/--image/--profile")
            summary["preflight"] = live_preflight(args, binary)
            summary["scope"] = "Fresh profile-bounded live reproduction; requires all selected stages to pass. Not a population compatibility or performance claim."
        out.mkdir(parents=True)
        created_output = True
        save(out / "summary.json", summary)
        if args.mode == "verify":
            summary["reports"] = validate_reports(args.report or DEFAULT_REPORTS, binary, args.artifacts_root.resolve(), out, mappings)
        else:
            summary["reports"] = live(args, binary, out, summary)
        summary["status"] = "complete"
    except (OSError, ValueError, KeyError, subprocess.TimeoutExpired, KeyboardInterrupt) as error:
        summary["status"] = "failed"
        summary["error"] = str(error) or type(error).__name__
        print("demo: " + summary["error"], file=sys.stderr)
    finally:
        summary["finished_at"] = now()
        if created_output:
            save(out / "summary.json", summary)
    print(f"Demo {summary['mode']}: {summary['status']}", flush=True)
    return 0 if summary["status"] == "complete" else 2


if __name__ == "__main__":
    raise SystemExit(main())
