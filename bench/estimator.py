"""BH-15: Cost and time estimator per suite.

Computes pre-flight estimations for execution wall-clock time, disk storage footprint,
and peak memory requirements across benchmark suites before launching runs.
"""
from pathlib import Path
from bench.common import BENCH, read_json, rel_path
from bench.store import RunStore
from bench import cases as case_registry
from bench.suites import LIVE_SUITES
from bench.preflight import disk_free_mb

# Empirical default timings and sizes when historical data is absent
DEFAULT_TIMINGS = {
    "native_run_ms": 1500,
    "sandbox_run_ms": 4000,
    "scan_ms": 1000,
    "disk_per_run_mb": 1.5,
    "peak_memory_mb": 128,
}

SUITE_DESCRIPTIONS = {
    "BM-01": "Compatibility accuracy (SentryBench-Core)",
    "BM-02": "Static extraction accuracy (150+ ELF binaries)",
    "BM-03": "Dynamic fidelity & tracer perturbation",
    "BM-04": "Static-versus-dynamic ablation (ABBA)",
    "BM-07": "Robustness and adversarial fuzz corpus",
    "BM-08": "Tool performance and scalability ladders",
    "BM-13": "Reproducibility & provenance two-interpreter rebuild",
    "BM-14": "Replicated scans",
}


def get_historical_profile(root=None):
    store = RunStore(root or (BENCH / "runs"))
    records = store.records(valid_only=True)
    if not records:
        return DEFAULT_TIMINGS

    scan_times = []
    disk_sizes = []
    for r in records:
        timings = r.get("timings_ms", {})
        if timings.get("scan"):
            scan_times.append(timings["scan"])
        resources = r.get("resources", {})
        if resources.get("disk_mb"):
            disk_sizes.append(resources["disk_mb"])

    scan_med = sorted(scan_times)[len(scan_times) // 2] if scan_times else DEFAULT_TIMINGS["scan_ms"]
    disk_med = sorted(disk_sizes)[len(disk_sizes) // 2] if disk_sizes else DEFAULT_TIMINGS["disk_per_run_mb"]

    return {
        "native_run_ms": DEFAULT_TIMINGS["native_run_ms"],
        "sandbox_run_ms": DEFAULT_TIMINGS["sandbox_run_ms"],
        "scan_ms": scan_med,
        "disk_per_run_mb": disk_med,
        "peak_memory_mb": DEFAULT_TIMINGS["peak_memory_mb"],
    }


def estimate_suite(suite, repetitions=3):
    profile = get_historical_profile()
    from bench.suites import ready_cases

    if suite in LIVE_SUITES:
        cases = ready_cases(suite)
        case_count = len(cases)
        arms = LIVE_SUITES[suite]
        runs_count = case_count * len(arms)
        # Each live run involves native + sandbox runs * repetitions + scan
        total_ms = 0
        total_disk_mb = runs_count * profile["disk_per_run_mb"]
        for arm in arms:
            if arm == "live":
                per_run = (profile["native_run_ms"] + profile["sandbox_run_ms"]) * repetitions + profile["scan_ms"]
            else:
                per_run = profile["scan_ms"]
            total_ms += case_count * per_run
    elif suite == "BM-02":
        case_count = 150
        runs_count = 150
        total_ms = case_count * 120  # Fast static extraction per binary
        total_disk_mb = 15.0
    elif suite == "BM-03":
        case_count = 48
        runs_count = 48
        total_ms = case_count * 300
        total_disk_mb = 12.0
    elif suite == "BM-07":
        case_count = 24
        runs_count = 24
        total_ms = case_count * 250
        total_disk_mb = 8.0
    elif suite == "BM-08":
        case_count = 12
        runs_count = 36
        total_ms = 45000
        total_disk_mb = 60.0
    elif suite == "BM-13":
        case_count = 1
        runs_count = 2
        total_ms = 15000
        total_disk_mb = 5.0
    else:
        case_count = 0
        runs_count = 0
        total_ms = 0
        total_disk_mb = 0.0

    total_seconds = round(total_ms / 1000.0, 1)
    return {
        "suite": suite,
        "description": SUITE_DESCRIPTIONS.get(suite, "Custom suite"),
        "case_count": case_count,
        "runs_count": runs_count,
        "estimated_seconds": total_seconds,
        "estimated_minutes": round(total_seconds / 60.0, 2),
        "estimated_disk_mb": round(total_disk_mb, 1),
        "peak_rss_mb": profile["peak_memory_mb"],
    }


def command_estimate(args):
    suites_to_estimate = [args.suite] if args.suite and args.suite != "all" else [
        "BM-01", "BM-02", "BM-03", "BM-04", "BM-07", "BM-08", "BM-13", "BM-14"
    ]

    free_mb = disk_free_mb(BENCH)
    print("=" * 78)
    print("  SENTRYCHECK BENCHMARK COST & TIME ESTIMATOR (BH-15)")
    print("=" * 78)
    print(f"Host Available Disk Space: {free_mb} MB\n")
    print(f"{'Suite':<8} {'Cases':<7} {'Runs':<7} {'Est. Time':<12} {'Est. Disk':<12} {'Peak RSS':<10}")
    print("-" * 78)

    total_time_sec = 0.0
    total_disk_mb = 0.0

    for s in suites_to_estimate:
        est = estimate_suite(s, repetitions=args.repetitions)
        total_time_sec += est["estimated_seconds"]
        total_disk_mb += est["estimated_disk_mb"]
        time_str = f"{est['estimated_seconds']}s ({est['estimated_minutes']}m)" if est["estimated_seconds"] > 60 else f"{est['estimated_seconds']}s"
        print(f"{est['suite']:<8} {est['case_count']:<7} {est['runs_count']:<7} {time_str:<12} {est['estimated_disk_mb']} MB{'':<6} {est['peak_rss_mb']} MB")

    print("-" * 78)
    total_min = round(total_time_sec / 60.0, 1)
    print(f"TOTAL:   —       —       {total_time_sec:.1f}s ({total_min}m)  {total_disk_mb:.1f} MB")
    print("=" * 78)

    if free_mb < total_disk_mb:
        print(f"⚠️ WARNING: Estimated disk requirement ({total_disk_mb:.1f} MB) exceeds available space ({free_mb} MB)!")
        return 1
    return 0

