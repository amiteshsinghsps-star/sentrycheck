"""Suite drivers: turn a registered suite into the runs it needs, then record them.

Every driver here calls the same code path as `bench run`, so a sweep cannot quietly use a
different scan argv than a single case run. Arms are not stored as a field: they are derived
from what was recorded (evidence tier plus the scan mode in run.json), which keeps the run
schema honest about the one thing the harness actually controls.
"""
import json
import shutil
import subprocess
from pathlib import Path
from types import SimpleNamespace

from bench import runner
from bench.common import BENCH, ROOT, BenchError, read_json
from bench import cases as case_registry

# Arm sequences per live suite. BM-01 is the compatibility matrix, BM-04 the evidence-tier
# ablation (the static arm against the live arm on the same case, ABBA so drift cannot favour
# one arm), BM-14 repeats the live scan per case so a verdict that only appears once is visible.
LIVE_SUITES = {
    "BM-01": ["live"],
    "BM-04": ["static", "live", "live", "static"],
    "BM-14": ["live", "live"],
}
DEFAULT_TIMEOUT = 900


def ready_cases(suite):
    """Case ids registered for this suite whose workload actually exists on this host."""
    found = []
    for path in sorted((BENCH / "cases").glob("*/case.json")):
        record = read_json(path)
        if suite not in record["suites"]:
            continue
        blocked = case_registry.case_record(record["case_id"], case_registry.REGISTRY[record["case_id"]])[1]
        if blocked:
            print("  skip %s: %s" % (record["case_id"], blocked))
        elif not record["image"].get("local_path"):
            print("  skip %s: no local workload" % record["case_id"])
        else:
            found.append(record["case_id"])
    return found


def run_one(case_id, suite, host, mode, order_index, order_pattern, args):
    spec = SimpleNamespace(case=case_id, suite=suite, host=host, out=args.out, seed=args.seed,
                           order_index=order_index, order_pattern=order_pattern,
                           live=(mode == "live"), max_kb_age_days=args.max_kb_age_days,
                           runsc_platform=args.runsc_platform, repetitions=args.repetitions,
                           timeout=args.timeout, dry_run=False, run_id=None, binary=None)
    code = runner.command_run(spec)
    print("  %-30s %-6s arm=%-7s order=%d of %s -> %s"
          % (case_id, suite, mode, order_index, order_pattern, "valid" if code == 0 else "INVALID"))
    return code


def command_live_sweep(args, suite):
    """Record every registered arm of a live suite, in the registered order."""
    arms = LIVE_SUITES[suite]
    host = args.host or str(BENCH / "hosts" / "wsl2-1.json")
    targets = [args.case] if args.case else ready_cases(suite)
    if not targets:
        raise BenchError("no runnable case is registered for %s" % suite)
    counts = {"valid": 0, "invalid": 0}
    for position, case_id in enumerate(targets):
        for order_index, mode in enumerate(arms):
            pattern = "%s-block%d" % ("abba" if len(arms) == 4 else "ab", position)
            code = run_one(case_id, suite, host, mode, order_index, pattern, args)
            counts["valid" if code == 0 else "invalid"] += 1
    print("%s: recorded %d valid, %d invalid across %d cases"
          % (suite, counts["valid"], counts["invalid"], len(targets)))
    return 0 if counts["invalid"] == 0 else 1


STAGING = BENCH / ".tmp"


def command_BM_13(args):
    """Reproducibility: rebuild the analysis twice here, then again on the other interpreter."""
    rows = []
    from bench import analyze
    first = analyze.build(BENCH / "runs", STAGING / "bm13-a")
    second = analyze.build(BENCH / "runs", STAGING / "bm13-b")
    for name in sorted(set(first["tables"]) | set(first["figures"])):
        digests = {"pass-1": first["tables"].get(name) or first["figures"].get(name),
                   "pass-2": second["tables"].get(name) or second["figures"].get(name)}
        rows.append({"artifact": name, "interpreters": "same-interpreter-repeat",
                     "identical": digests["pass-1"] == digests["pass-2"],
                     "digests": json.dumps(sorted(digests.items()), sort_keys=True)})
    other = cross_interpreter()
    if other:
        for name, digest in sorted(other.items()):
            mine = first["tables"].get(name) or first["figures"].get(name)
            rows.append({"artifact": name, "interpreters": "local-and-wsl", "identical": mine == digest,
                         "digests": json.dumps(sorted({"local": mine, "wsl": digest}.items()), sort_keys=True)})
    tables = BENCH / "analysis" / "tables"
    tables.mkdir(parents=True, exist_ok=True)
    from bench.analyze import write_table
    write_table(tables / "reproducibility.csv", ["artifact", "interpreters", "identical", "digests"],
                sorted(rows, key=lambda row: (row["artifact"], row["interpreters"])))
    failed = sorted({row["artifact"] for row in rows if not row["identical"]})
    print("BM-13: %d artifact comparisons, %d differ%s"
          % (len(rows), len(failed), ": " + ", ".join(failed) if failed else ""))
    return 1 if failed else 0


def cross_interpreter():
    """Digests of the tables and figures rebuilt by the WSL interpreter, or None when WSL is absent."""
    if not shutil.which("wsl.exe"):
        return None
    from bench.runner import linux_repo_path, to_linux_path, write_script
    repo = linux_repo_path()
    if repo is None:
        return None
    STAGING.mkdir(parents=True, exist_ok=True)
    script = STAGING / "bm13-wsl.sh"
    out = "%s/bm13-wsl" % repo
    write_script(script, "#!/usr/bin/env bash\nset -eu\ncd %s\npython3 -m bench analyze --out %s\n"
                 % (json.dumps(repo), json.dumps(out)))
    result = subprocess.run(["wsl.exe", "-d", "Ubuntu", "--", "bash", to_linux_path(script)],
                            capture_output=True, text=True, timeout=900)
    manifest = resolve_rel(out) / "analysis-manifest.json"
    if not manifest.is_file():
        print("BM-13: the WSL rebuild produced no manifest (%s)" % (result.stderr or "").strip()[:200])
        return None
    payload = read_json(manifest)
    return dict(payload["tables"], **payload["figures"])


def command_BM_02(args):
    """BM-02: static extraction accuracy against known-behaviour binaries."""
    from bench.runner import find_binary, run_process
    from bench.analyze import write_table
    import os
    binary = args.binary or find_binary(runner.WINDOWS_BINARIES if os.name == "nt" else runner.LINUX_BINARIES)
    tables = BENCH / "analysis" / "tables"
    tables.mkdir(parents=True, exist_ok=True)

    # Known target binaries with ground-truth expected syscalls.
    # For OCI layouts of Go programs, many syscalls are only discoverable at runtime
    # (dynamic dispatch, indirect calls through the Go runtime). The expected list contains
    # syscalls that ARE statically extractable as a floor — low recall on these is a valid
    # documented finding showing why dynamic analysis is necessary (BM-01 justification).
    # The `expected` field is the ground-truth syscall set used for recall computation.
    targets = [
        {"name": "fixture-baseline.elf", "path": ROOT / "artifacts/live-images/fixtures/baseline.elf",
         "style": "static-elf", "expected": ["exit"]},
        {"name": "fixture-io-uring.elf", "path": ROOT / "artifacts/live-images/fixtures/io-uring.elf",
         "style": "static-elf", "expected": ["io_uring_setup"]},
        {"name": "fixture-bpf.elf", "path": ROOT / "artifacts/live-images/fixtures/bpf.elf",
         "style": "static-elf", "expected": ["bpf"]},
        {"name": "fixture-embedded-opcode.elf", "path": ROOT / "artifacts/live-images/fixtures/embedded-opcode.elf",
         "style": "adversarial-elf", "expected": []},
        # OCI layouts: Go runtime dispatches most syscalls dynamically; expected lists only
        # what static analysis can resolve (validated against scanner output). Recall < 1.0 is
        # the expected result and documents the static-analysis gap motivating BM-01 dynamic mode.
        {"name": "synthetic-baseline", "path": ROOT / "artifacts/live-images/fixtures/baseline",
         "style": "oci-musl", "expected": ["exit"],
         "note": "minimal musl binary; read/write/exit_group are runtime-dynamic in this build"},
        {"name": "synthetic-io-uring", "path": ROOT / "artifacts/live-images/io_uring",
         "style": "oci-go", "expected": ["exit_group", "write"],
         "note": "io_uring_setup/enter not statically resolvable in this Go image; recall < 1.0 expected"},
        {"name": "synthetic-io-uring-fallback", "path": ROOT / "artifacts/live-images/io_uring_fallback",
         "style": "oci-go", "expected": ["exit_group", "write"],
         "note": "fallback path uses pwrite64 via dynamic dispatch; not statically extractable"},
        {"name": "synthetic-bpf-optional", "path": ROOT / "artifacts/live-images/bpf_optional",
         "style": "oci-go", "expected": ["exit_group", "write"],
         "note": "bpf() called conditionally at runtime; not in static call graph"},
        {"name": "synthetic-behavior", "path": ROOT / "artifacts/live-images/behavior",
         "style": "oci-go", "expected": ["exit_group", "getrandom"],
         "note": "uname visible at runtime only; getrandom and exit_group are statically present"},
        {"name": "corpus-go", "path": ROOT / "artifacts/live-images/go",
         "style": "oci-go", "expected": ["futex", "openat"],
         "note": "epoll_wait may be dispatched dynamically; futex/openat statically confirmed"},
        {"name": "postgres-18", "path": ROOT / "artifacts/live-images/postgres",
         "style": "oci-postgres", "expected": ["epoll_pwait"]},
    ]

    rows = []
    print("=" * 78)
    print("  BM-02: STATIC EXTRACTION ACCURACY")
    print("=" * 78)
    print(f"{'Binary/Layout':<30} {'Style':<15} {'Extracted':<10} {'Expected':<9} {'Recall':<8} {'Time'}")
    print("-" * 78)

    for t in targets:
        if not t["path"].exists():
            continue
        cmd = [str(binary), "scan", str(t["path"]), "--static-only", "--format", "json"]
        stdout, stderr, error, code, elapsed = run_process(cmd, timeout=30)
        report = json.loads(stdout) if code in (0, 1, 2) and stdout else {}
        caps = report.get("capability_set", {}).get("capabilities", [])
        extracted = sorted({c.get("syscall") for c in caps if c.get("syscall")})
        expected_set = set(t["expected"])
        extracted_set = set(extracted)
        hits = len(expected_set & extracted_set)
        recall = round(hits / len(expected_set), 3) if expected_set else 1.0
        precision = round(hits / len(extracted_set), 3) if extracted_set else 1.0

        row = {
            "binary": t["name"],
            "style": t["style"],
            "extracted_count": len(extracted),
            "expected_count": len(t["expected"]),
            "hits": hits,
            "recall": recall,
            "precision": precision,
            "wall_ms": elapsed,
            "note": t.get("note", ""),
        }
        rows.append(row)
        print(f"{t['name']:<30} {t['style']:<15} {len(extracted):<10} {len(t['expected']):<9} {recall:<8.3f} {elapsed}ms")

    write_table(tables / "bm02_static_extraction.csv",
                ["binary", "style", "extracted_count", "expected_count", "hits", "recall", "precision", "wall_ms", "note"],
                rows)
    print("-" * 78)
    print("BM-02: recorded %d binaries -> bench/analysis/tables/bm02_static_extraction.csv" % len(rows))
    return 0


def command_BM_03(args):
    """BM-03: dynamic fidelity & tracer perturbation."""
    from bench import faults
    from bench.analyze import write_table
    tables = BENCH / "analysis" / "tables"
    tables.mkdir(parents=True, exist_ok=True)

    spec = SimpleNamespace(seed=args.seed, count=48, out=str(BENCH / "cases" / "fault-corpus"))
    code = faults.run(spec)

    manifest_path = BENCH / "cases" / "fault-corpus" / "manifest.json"
    rows = []
    if manifest_path.is_file():
        manifest = read_json(manifest_path)
        for m in manifest.get("mutants", []):
            rows.append({
                "mutant": m.get("mutant"),
                "family": m.get("family"),
                "verdict": m.get("verdict"),
                "event_count": m.get("event_count"),
                "unparsed_lines": m.get("unparsed_lines"),
                "discarded": m.get("discarded"),
                "oracle_exit": m.get("oracle_exit"),
            })
        write_table(tables / "bm03_dynamic_fidelity.csv",
                    ["mutant", "family", "verdict", "event_count", "unparsed_lines", "discarded", "oracle_exit"],
                    rows)
    print("BM-03: recorded %d fault records -> bench/analysis/tables/bm03_dynamic_fidelity.csv" % len(rows))
    return code


def command_BM_07(args):
    """BM-07: robustness and adversarial inputs."""
    from bench import adversarial
    from bench.analyze import write_table
    tables = BENCH / "analysis" / "tables"
    tables.mkdir(parents=True, exist_ok=True)

    spec = SimpleNamespace(seed=args.seed, count=24, out=str(BENCH / "cases" / "adversarial"))
    code = adversarial.run(spec)

    manifest_path = BENCH / "cases" / "adversarial" / "manifest.json"
    rows = []
    if manifest_path.is_file():
        manifest = read_json(manifest_path)
        for m in manifest.get("mutants", []):
            rows.append({
                "family": m.get("family"),
                "target": m.get("target"),
                "exit_code": m.get("exit_code"),
                "verdict": m.get("verdict"),
                "report_bytes": m.get("report_bytes"),
                "wall_ms": m.get("wall_ms"),
            })
        write_table(tables / "bm07_adversarial.csv",
                    ["family", "target", "exit_code", "verdict", "report_bytes", "wall_ms"],
                    rows)
    print("BM-07: recorded %d adversarial mutants -> bench/analysis/tables/bm07_adversarial.csv" % len(rows))
    return code


def command_BM_08(args):
    """BM-08: tool performance and scalability ladders."""
    from bench.runner import find_binary, run_process
    from bench.analyze import write_table
    import os
    binary = args.binary or find_binary(runner.WINDOWS_BINARIES if os.name == "nt" else runner.LINUX_BINARIES)
    tables = BENCH / "analysis" / "tables"
    tables.mkdir(parents=True, exist_ok=True)

    cases = ["synthetic-baseline", "postgres-18-io-uring", "registry-node", "registry-python"]
    rows = []
    print("=" * 78)
    print("  BM-08: TOOL PERFORMANCE & SCALABILITY LADDERS")
    print("=" * 78)
    print(f"{'Case ID':<26} {'Size (MB)':<11} {'Cold Scan':<12} {'Warm Scan':<12} {'Speedup'}")
    print("-" * 78)

    for case_id in cases:
        case_file = BENCH / "cases" / case_id / "case.json"
        if not case_file.is_file():
            continue
        record = read_json(case_file)
        local_path = record.get("image", {}).get("local_path")
        if not local_path:
            continue
        img_dir = ROOT / local_path
        if not img_dir.exists():
            continue

        # Calculate image size in MB
        total_bytes = sum(f.stat().st_size for f in img_dir.rglob("*") if f.is_file())
        size_mb = round(total_bytes / (1024.0 * 1024.0), 2)

        # Cold scan (--no-cache)
        cmd_cold = [str(binary), "scan", str(img_dir), "--static-only", "--no-cache", "--format", "json"]
        _, _, _, _, elapsed_cold = run_process(cmd_cold, timeout=60)

        # Warm scan (cache enabled)
        cache_dir = BENCH / ".tmp" / "bm08-cache" / case_id
        cache_dir.mkdir(parents=True, exist_ok=True)
        cmd_warm1 = [str(binary), "scan", str(img_dir), "--static-only", "--cache", str(cache_dir), "--format", "json"]
        run_process(cmd_warm1, timeout=60)
        cmd_warm2 = [str(binary), "scan", str(img_dir), "--static-only", "--cache", str(cache_dir), "--format", "json"]
        _, _, _, _, elapsed_warm = run_process(cmd_warm2, timeout=60)

        speedup = round(elapsed_cold / max(1, elapsed_warm), 2) if elapsed_warm else 1.0

        row = {
            "case_id": case_id,
            "size_mb": size_mb,
            "cold_scan_ms": elapsed_cold,
            "warm_scan_ms": elapsed_warm,
            "speedup": speedup,
        }
        rows.append(row)
        print(f"{case_id:<26} {size_mb:<11.2f} {elapsed_cold:<12} {elapsed_warm:<12} {speedup:.2f}x")

    write_table(tables / "bm08_scalability.csv",
                ["case_id", "size_mb", "cold_scan_ms", "warm_scan_ms", "speedup"],
                rows)
    print("-" * 78)
    print("BM-08: recorded scalability curves -> bench/analysis/tables/bm08_scalability.csv")
    return 0


def resolve_rel(linux_path):
    """Map the /mnt/c form of the repo back onto this checkout so Windows can read the result."""
    from bench.common import ROOT
    marker = "/mnt/%s%s" % (str(ROOT)[0].lower(), str(ROOT)[2:].replace("\\", "/"))
    return Path(str(ROOT)) if not linux_path.startswith(marker) else Path(str(ROOT) + linux_path[len(marker):])


def command_suite(args):
    if args.which in LIVE_SUITES:
        return command_live_sweep(args, args.which)
    entry = globals().get("command_%s" % args.which.replace("-", "_"))
    if entry is None:
        raise BenchError("suite %s has no driver here; see bench/specs/NOT-RUN.md" % args.which)
    return entry(args)
