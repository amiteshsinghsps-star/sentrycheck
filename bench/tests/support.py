"""Shared fixtures: a schema-valid run record and a throwaway store root inside the repo.

The store refuses paths outside the repository, so scratch roots live under bench/.tmp and
are removed by each test; nothing here touches the real bench/runs tree.
"""
import shutil
from pathlib import Path

from bench import BENCH_VERSION
from bench.common import BENCH, sha256_bytes

SCRATCH = BENCH / ".tmp" / "test-scratch"
ZERO = "sha256:" + "0" * 64


def make_record(run_id="r-test-case", case_id="test-case", suite="BM-13", host_id="htest-1", valid=True):
    return {"schema_version": "1.0", "run_id": run_id, "case_id": case_id, "suite": suite,
            "host_id": host_id, "started_at": "2026-10-31T00:00:00Z", "ended_at": "2026-10-31T00:00:01Z",
            "seed": 1, "order_index": 0, "order_pattern": "single",
            "tool": {"name": "sentrycheck", "version": "0.0.0", "git_commit": None, "binary_sha256": ZERO},
            "kb": {"snapshot_version": "test", "sha256": ZERO, "max_age_days": 30},
            "runtime": {"name": "gvisor", "release": "20260921.0", "platform": "systrap", "binary_sha256": ZERO},
            "environment": {"governor": None, "smt": None, "cores": [0, 1], "load_before": 0.5,
                            "free_disk_mb": 10000, "clock_synced": True, "work_root": "repo:bench/.tmp",
                            "host_load_controlled": False},
            "predicted": {"class": "compatible", "tier": "dynamic-runsc-diff", "complete": True,
                          "status": "complete", "finding_severities": [], "incomplete_reason_codes": []},
            "repetitions": {"native_exits": [0], "sandbox_exits": [0], "native_durations_ms": [10],
                            "sandbox_durations_ms": [12]},
            "timings_ms": {"scan": 100, "total": 120},
            "resources": {"peak_rss_mb": 12.5, "disk_mb": None},
            "valid": valid, "invalid_reason": None if valid else "test invalidation",
            "notes": "harness %s fixture" % BENCH_VERSION}


def make_artifacts():
    return {"report.json": b'{"schema_version":"1.0","status":"complete"}',
            "traces/native-0-guest.trace": b"execve(0, 0, 0) = 0\nexit_group(0) = 0\n",
            "traces/sandbox-0-guest.trace": b"execve(0, 0, 0) = 0\nexit_group(0) = 0\n",
            "outputs/native-0-stdout.txt": b"ok\n",
            "logs/scanner-stdout.txt": b"\n"}


def scratch_root(name):
    path = SCRATCH / name
    if path.exists():
        shutil.rmtree(str(path))
    path.mkdir(parents=True, exist_ok=True)
    return path


def cleanup(path):
    shutil.rmtree(str(path), ignore_errors=True)
    parent = Path(path).parent
    if parent.is_dir() and not any(parent.iterdir()):
        shutil.rmtree(str(parent), ignore_errors=True)


def digest(data):
    return sha256_bytes(data)
