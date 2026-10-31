"""Measure SENTRYCHECK commands; retain observations, not invented performance claims.

Python standard library only. See docs/BENCHMARK-METHODOLOGY.md for the manifest
contract, statistical assumptions, cache definitions, and limits on inference.
"""
from __future__ import annotations

import argparse
from collections import Counter, defaultdict
from datetime import date, datetime, timedelta, timezone
import hashlib
from html import escape
import json
import math
import os
from pathlib import Path
import platform
import re
import shutil
import signal
import subprocess
import sys
import threading
import time

SCHEMA = "1.0"
MAX_JSON_BYTES = 128 * 1024 * 1024
NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,79}\Z")
SCAN_OPTIONS = {
    "--runtime", "--version", "--platform", "--profile", "--kb",
    "--max-kb-age-days", "--runc-bin", "--runsc-bin", "--strace-bin", "--fail-on",
}
PATH_OPTIONS = {"--profile", "--kb", "--runc-bin", "--runsc-bin", "--strace-bin"}
SEVERITIES = {"hard-failure", "silent-degradation", "performance-regression", "compatibility-risk"}


def timestamp():
    return datetime.now(timezone.utc).isoformat()


def digest_file(path):
    value = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(chunk)
    return "sha256:" + value.hexdigest()


def load_json(path):
    path = Path(path)
    if path.stat().st_size > MAX_JSON_BYTES:
        raise ValueError(f"JSON input exceeds {MAX_JSON_BYTES} bytes: {path}")
    with path.open(encoding="utf-8-sig") as stream:
        return json.load(stream)


def write_json(path, value):
    Path(path).write_text(json.dumps(value, indent=2, ensure_ascii=False, allow_nan=False) + "\n", encoding="utf-8", newline="\n")


def positive_int(value, field, allow_zero=False):
    if type(value) is not int or value < (0 if allow_zero else 1) or value > 10000:
        raise ValueError(f"{field} must be an integer in {'0' if allow_zero else '1'}..10000")
    return value


def number(value, field, minimum=0):
    if type(value) not in (int, float) or not math.isfinite(value) or value < minimum:
        raise ValueError(f"{field} must be a finite number >= {minimum}")
    return value


def argv(value, field):
    if not isinstance(value, list) or not value or any(not isinstance(v, str) or not v or "\0" in v for v in value):
        raise ValueError(f"{field} must be a nonempty array of nonempty argument strings")
    return value


def valid_name(value):
    if not isinstance(value, str) or not NAME.fullmatch(value) or ".." in value:
        raise ValueError("names must be unique safe identifiers (letters, digits, underscore, dash, dot)")
    return value


def nearest_rank(values, p):
    """Empirical quantile: sorted(values)[ceil(p*n)-1], including finite negatives."""
    if not 0 < p <= 1:
        raise ValueError("quantile must be in (0, 1]")
    if not values:
        return None
    if any(not math.isfinite(v) for v in values):
        raise ValueError("quantile values must be finite")
    return sorted(values)[max(0, math.ceil(p * len(values)) - 1)]


def distribution(values):
    """Conservative DKW quantile bounds; null means no finite sample bound."""
    if not values:
        return {"n": 0, "p50": None, "p95": None, "p99": None, "warnings": ["No eligible measurements."]}
    n = len(values)
    epsilon = math.sqrt(math.log(2 / 0.05) / (2 * n))
    result = {"n": n, "min": min(values), "max": max(values), "mean": sum(values) / n,
              "dkw_95_cdf_epsilon": epsilon,
              "uncertainty_assumption": "IID samples from a stationary distribution; shared-host serial runs may violate this assumption.",
              "warnings": []}
    bounds = {}
    for label, p in [("p50", 0.50), ("p95", 0.95), ("p99", 0.99)]:
        result[label] = nearest_rank(values, p)
        bounds[label] = {"lower": nearest_rank(values, p - epsilon) if p - epsilon > 0 else None,
                         "upper": nearest_rank(values, p + epsilon) if p + epsilon < 1 else None}
        if n * (1 - p) < 5:
            result["warnings"].append(f"{label}: fewer than five expected observations beyond the target quantile; tail estimate is exploratory.")
    result["dkw_95_quantile_bounds"] = bounds
    return result


def wilson(successes, count):
    if count == 0:
        return {"lower": None, "upper": None}
    z = 1.959963984540054
    rate = successes / count
    denominator = 1 + z * z / count
    center = (rate + z * z / (2 * count)) / denominator
    radius = z * math.sqrt(rate * (1 - rate) / count + z * z / (4 * count * count)) / denominator
    return {"lower": max(0.0, center - radius), "upper": min(1.0, center + radius)}


def resolve(value, cwd):
    path = Path(value)
    return path.resolve() if path.is_absolute() else (cwd / path).resolve()


def executable(value, cwd):
    path = resolve(value, cwd)
    found = path if path.is_file() else shutil.which(value)
    if not found:
        raise ValueError(f"executable not found: {value}")
    return Path(found).resolve()


def identity(command, cwd):
    """Record an explicit tool identity, never credentials or the full environment."""
    try:
        path = executable(command, cwd)
        process = subprocess.run([str(path), "--version"], cwd=cwd, capture_output=True, timeout=15)
        return {"path": str(path), "sha256": digest_file(path), "version_exit_code": process.returncode,
                "version_output": (process.stdout + process.stderr).decode("utf-8", "replace")[:4096]}
    except (OSError, ValueError, subprocess.TimeoutExpired) as error:
        return {"requested": command, "available": False, "error": str(error)}


def environment():
    data = {"platform": platform.platform(), "system": platform.system(), "kernel": platform.release(),
            "machine": platform.machine(), "processor": platform.processor(), "logical_cpus": os.cpu_count(),
            "python": sys.version, "clock": vars(time.get_clock_info("perf_counter")),
            "host_load_controlled": False, "os_page_cache_controlled": False,
            "github_actions": os.environ.get("GITHUB_ACTIONS") == "true"}
    if hasattr(os, "getloadavg"):
        data["load_average_at_start"] = list(os.getloadavg())
    if Path("/proc/meminfo").exists():
        data["memory"] = {line.split(":", 1)[0]: line.split(":", 1)[1].strip()
                          for line in Path("/proc/meminfo").read_text().splitlines()
                          if line.startswith(("MemTotal:", "MemAvailable:"))}
    if data["github_actions"]:
        data["github"] = {name: os.environ.get(name) for name in
                          ["GITHUB_REPOSITORY", "GITHUB_SHA", "GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT", "RUNNER_OS", "RUNNER_ARCH"]}
    return data


def check_manifest(manifest):
    if not isinstance(manifest, dict) or manifest.get("schema_version") != SCHEMA:
        raise ValueError("benchmark manifest schema_version must be 1.0")
    names = set()
    for section in ["cases", "historical_reports", "ci_pairs"]:
        values = manifest.get(section, [])
        if not isinstance(values, list):
            raise ValueError(f"{section} must be an array")
        for item in values:
            if not isinstance(item, dict):
                raise ValueError(f"{section} entries must be objects")
            name = valid_name(item.get("name"))
            if name in names:
                raise ValueError(f"duplicate benchmark name: {name}")
            names.add(name)
            if section == "cases":
                if not isinstance(item.get("image"), str) or not item["image"] or item["image"].startswith("-"):
                    raise ValueError("case image must be a nonempty image reference or path")
                if item.get("mode") not in {"static", "live", "native-only"}:
                    raise ValueError("mode must be static, live, or native-only")
                if item.get("cache", "disabled") not in {"disabled", "cold-analyzer", "warm-analyzer"}:
                    raise ValueError("cache must be disabled, cold-analyzer, or warm-analyzer")
                args = item.get("scan_args", [])
                if not isinstance(args, list) or len(args) % 2 or any(not isinstance(v, str) or not v or "\0" in v for v in args):
                    raise ValueError("scan_args must contain option/value pairs")
                keys = args[::2]
                if len(set(keys)) != len(keys) or any(key not in SCAN_OPTIONS for key in keys):
                    raise ValueError("scan_args contains duplicate, managed, or unsupported options; imported evidence is not a live benchmark")
                codes = item.get("expected_exit_codes", [0, 1, 2])
                if not isinstance(codes, list) or not codes or any(type(code) is not int or code not in [0, 1, 2] for code in codes):
                    raise ValueError("expected_exit_codes must contain scanner codes 0, 1, or 2")
            elif section == "ci_pairs":
                argv(item.get("baseline"), "baseline")
                argv(item.get("gate"), "gate")
                if item.get("environment", "local") not in {"local", "github-actions"}:
                    raise ValueError("CI pair environment must be local or github-actions")
                for field in ["baseline_exit_codes", "gate_exit_codes"]:
                    codes = item.get(field, [0])
                    if not isinstance(codes, list) or not codes or any(type(code) is not int for code in codes):
                        raise ValueError(f"{field} must be an integer array")
                if item.get("runner_price_usd_per_minute") is not None:
                    number(item["runner_price_usd_per_minute"], "runner_price_usd_per_minute")
            else:
                if not isinstance(item.get("report"), str) or not item["report"]:
                    raise ValueError("historical report path is required")
                if item.get("clean_label") not in [True, False, None] or type(item.get("clean_label")) not in (bool, type(None)):
                    raise ValueError("clean_label must be boolean or null")
                if item.get("clean_label") is not None and not isinstance(item.get("label_source"), str):
                    raise ValueError("labeled reports require label_source")
                if item.get("clean_label") is not None and not item["label_source"].strip():
                    raise ValueError("label_source cannot be empty")
            if section != "historical_reports":
                positive_int(item.get("repetitions", 20), "repetitions")
                positive_int(item.get("warmups", 1), "warmups", allow_zero=True)
                number(item.get("timeout_seconds", 1800), "timeout_seconds", minimum=0.01)
                if item.get("cache") == "warm-analyzer" and item.get("warmups", 1) == 0:
                    raise ValueError("warm-analyzer requires at least one warmup")
    if type(manifest.get("retain_reports", False)) is not bool:
        raise ValueError("retain_reports must be boolean")
    age = manifest.get("kb_age")
    if age is not None:
        if not isinstance(age, dict) or not isinstance(age.get("snapshot"), str):
            raise ValueError("kb_age requires a snapshot path")
        date.fromisoformat(age["as_of"])
        positive_int(age.get("max_age_days", 30), "max_age_days", allow_zero=True)
        if not isinstance(age.get("ages_days"), list) or not age["ages_days"]:
            raise ValueError("ages_days must be a nonempty array")
        for age_days in age["ages_days"]:
            positive_int(age_days, "ages_days", allow_zero=True)
    if not names and age is None:
        raise ValueError("manifest contains no experiments")
    return manifest


def input_description(image, cwd):
    path = resolve(image, cwd)
    if path.is_file():
        return {"kind": "local-file", "path": str(path), "bytes": path.stat().st_size, "sha256": digest_file(path)}
    if path.is_dir():
        index = path / "index.json"
        metadata = {"kind": "local-oci-layout" if index.is_file() else "local-rootfs", "path": str(path)}
        if index.is_file():
            metadata["index_sha256"] = digest_file(index)
            data = load_json(index)
            layers = []
            for descriptor in data.get("manifests", []):
                digest = descriptor.get("digest", "")
                if re.fullmatch(r"sha256:[0-9a-f]{64}", digest):
                    blob = path / "blobs" / "sha256" / digest[7:]
                    if blob.is_file():
                        value = load_json(blob)
                        if isinstance(value.get("layers"), list):
                            sizes = [v.get("size") for v in value["layers"]]
                            if all(type(size) is int and size >= 0 for size in sizes):
                                layers.append({"manifest_digest": digest, "platform": descriptor.get("platform"),
                                               "layers": len(sizes), "declared_compressed_layer_bytes": sum(sizes)})
            metadata["manifests"] = layers
        return metadata
    return {"kind": "registry-or-archive-reference", "reference": image,
            "note": "Acquisition is included in each timed scan; mutable references are resolved by the scanner."}


def scan_argv(case, binary, cwd, cache, artifacts):
    image = case["image"]
    if resolve(image, cwd).exists():
        image = str(resolve(image, cwd))
    command = [str(binary), "scan", image, "--format", "json", "--cache", str(cache), "--artifacts", str(artifacts)]
    if case["mode"] == "static":
        command.append("--static-only")
    elif case["mode"] == "native-only":
        command.append("--native-only")
    if case.get("cache", "disabled") == "disabled":
        command.append("--no-cache")
    args = case.get("scan_args", [])
    for key, value in zip(args[::2], args[1::2]):
        if key in PATH_OPTIONS and (not key.endswith("-bin") or resolve(value, cwd).is_file()):
            value = str(resolve(value, cwd))
        command.extend([key, value])
    return command


def run_process(command, cwd, stdout, stderr, timeout):
    """No shell; timing excludes report decoding, hashing, and validation."""
    started_at = timestamp()
    started = time.perf_counter_ns()
    timed_out = False
    error = None
    exit_code = None
    with Path(stdout).open("wb") as out, Path(stderr).open("wb") as err:
        try:
            options = {"start_new_session": True} if os.name != "nt" else {"creationflags": subprocess.CREATE_NEW_PROCESS_GROUP}
            process = subprocess.Popen(command, cwd=cwd, stdout=out, stderr=err, **options)
            expired = threading.Event()

            def terminate_tree():
                # Terminate the spawned process tree; an orphaned workload would
                # contaminate subsequent measurements and outlive the harness.
                if process.poll() is not None:
                    return
                expired.set()
                try:
                    if os.name == "nt":
                        subprocess.run(["taskkill", "/PID", str(process.pid), "/T", "/F"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=15)
                    else:
                        os.killpg(process.pid, signal.SIGKILL)
                except (OSError, subprocess.TimeoutExpired):
                    pass
                finally:
                    try:
                        process.kill()
                    except OSError:
                        pass

            # POSIX wait(timeout=...) uses repeated polling/backoff and can add
            # milliseconds to tiny scans. A watchdog preserves a blocking wait.
            watchdog = threading.Timer(timeout, terminate_tree)
            watchdog.daemon = True
            watchdog.start()
            try:
                exit_code = process.wait()
            except KeyboardInterrupt:
                terminate_tree()
                process.wait()
                raise
            finally:
                watchdog.cancel()
            if expired.is_set():
                timed_out = True
                exit_code = None
                error = f"command exceeded {timeout} seconds; spawned process tree was terminated"
        except OSError as failure:
            error = str(failure)
    return {"started_at": started_at, "wall_seconds": (time.perf_counter_ns() - started) / 1e9,
            "exit_code": exit_code, "timed_out": timed_out, "process_error": error}


def validate_report(path, binary, cwd, artifacts_root=None):
    command = [str(binary), "report", "validate", str(path), "--format", "json"]
    if artifacts_root is not None:
        command.extend(["--artifacts-root", str(artifacts_root)])
    process = subprocess.run(command, cwd=cwd, capture_output=True, timeout=180)
    if process.returncode:
        raise ValueError("report semantic/artifact validation failed: " + process.stderr.decode("utf-8", "replace")[-2000:])
    validation = json.loads(process.stdout)
    if validation.get("valid") is not True or validation.get("report_sha256") != digest_file(path):
        raise ValueError("validator did not verify the exact report bytes")
    return validation


def report_metadata(report):
    dynamic = report.get("dynamic") or {}
    observations = []
    for kind in ["native", "sandbox"]:
        for run in dynamic.get(kind, []):
            observations.append({key: run.get(key) for key in
                                 ["runtime", "runtime_version", "exit_code", "timed_out", "duration_ms",
                                  "trace_kind", "trace_sha256", "stdout_sha256", "stderr_sha256", "infrastructure_error"]})
    capabilities = report.get("capability_set") or {}
    return {"scan_status": report.get("status"), "assessment": report.get("assessment"),
            "evidence_tier": dynamic.get("evidence_tier", "static-only"), "provenance": dynamic.get("provenance"),
            "image_digest": report.get("image_digest"), "target_runtime": report.get("target_runtime"),
            "profile_sha256": dynamic.get("profile_sha256"), "sentrycheck_version": report.get("sentrycheck_version"),
            "kb_snapshot_version": report.get("kb_snapshot_version"), "kb_age_days": report.get("kb_age_days"),
            "scanner_duration_ms": report.get("duration_ms"), "cache_hits": capabilities.get("cache_hits"),
            "findings_by_severity": dict(Counter(f.get("severity") for f in report.get("findings", []))),
            "incomplete_reasons": report.get("incomplete_reasons", []), "observations": observations}


def check_scan_outcome(case, report, exit_code):
    options = dict(zip(case.get("scan_args", [])[::2], case.get("scan_args", [])[1::2]))
    fail_on = options.get("--fail-on", "hard-failure")
    if fail_on not in SEVERITIES:
        raise ValueError("invalid --fail-on severity")
    expected = 1 if any(f["severity"] == fail_on for f in report["findings"]) else (0 if report["status"] == "complete" else 2)
    if exit_code != expected:
        raise ValueError(f"exit code {exit_code} contradicts report; expected {expected}")
    if exit_code not in case.get("expected_exit_codes", [0, 1, 2]):
        raise ValueError(f"exit code {exit_code} violates the manifest expectation")
    dynamic = report.get("dynamic")
    if case["mode"] == "static" and dynamic is not None:
        raise ValueError("static benchmark unexpectedly contains dynamic evidence")
    if dynamic and dynamic.get("provenance") != "locally-executed":
        raise ValueError("imported observations cannot count as live execution benchmarks")
    if case["mode"] == "native-only" and dynamic and dynamic.get("sandbox"):
        raise ValueError("native-only benchmark unexpectedly contains sandbox observations")


def append_row(stream, row):
    stream.write(json.dumps(row, ensure_ascii=False, allow_nan=False) + "\n")
    stream.flush()
    os.fsync(stream.fileno())


def run_case(case, binary, cwd, out, raw, retain_reports):
    rows = []
    case_dir = out / case["name"]
    case_dir.mkdir()
    cache_mode = case.get("cache", "disabled")
    for sequence in range(case.get("warmups", 1) + case.get("repetitions", 20)):
        warmup = sequence < case.get("warmups", 1)
        sample = sequence - case.get("warmups", 1)
        label = f"{sequence:05d}"
        cache = case_dir / ("cache-" + label if cache_mode == "cold-analyzer" else "cache")
        report_path = case_dir / (f"report-{label}.json" if retain_reports else "latest-report.json")
        stderr = case_dir / (f"stderr-{label}.log" if retain_reports else "latest-stderr.log")
        command = scan_argv(case, binary, cwd, cache, case_dir / ("artifacts-" + label))
        row = {"kind": "scan", "name": case["name"], "sequence": sequence, "sample": sample,
               "warmup": warmup, "mode": case["mode"], "cache": cache_mode, "command": command,
               "report_path": str(report_path), "report_retention": "all" if retain_reports else "last sample per case only",
               "measurement_valid": False}
        row.update(run_process(command, cwd, report_path, stderr, case.get("timeout_seconds", 1800)))
        try:
            if row["process_error"]:
                raise ValueError(row["process_error"])
            report = load_json(report_path)
            row["report_sha256"] = digest_file(report_path)
            row["validation"] = validate_report(report_path, binary, cwd, out if report.get("dynamic") else None)
            check_scan_outcome(case, report, row["exit_code"])
            row.update(report_metadata(report))
            row["measurement_valid"] = True
        except (OSError, ValueError, KeyError, TypeError, subprocess.TimeoutExpired) as error:
            row["validation_error"] = str(error)
        row["stderr_sha256"] = digest_file(stderr)
        append_row(raw, row)
        rows.append(row)
        print(f"{case['name']} {'warmup' if warmup else sample}: {row['wall_seconds']:.3f}s exit={row['exit_code']} valid={row['measurement_valid']}", flush=True)
    return rows


def run_ci_pair(case, cwd, out, raw):
    if case.get("environment", "local") == "github-actions" and not (
        os.environ.get("GITHUB_ACTIONS") == "true" and os.environ.get("GITHUB_RUN_ID")
    ):
        raise ValueError("a github-actions CI claim requires execution inside GitHub Actions with a run ID")
    rows = []
    case_dir = out / case["name"]
    case_dir.mkdir()
    for sequence in range(case.get("warmups", 1) + case.get("repetitions", 20)):
        order = ["baseline", "gate"] if sequence % 2 == 0 else ["gate", "baseline"]
        row = {"kind": "ci-pair", "name": case["name"], "sequence": sequence,
               "warmup": sequence < case.get("warmups", 1), "order": order,
               "environment": case.get("environment", "local"), "measurement_valid": True,
               "runner_price_usd_per_minute": case.get("runner_price_usd_per_minute")}
        for label in order:
            result = run_process(case[label], cwd, case_dir / f"latest-{label}.stdout", case_dir / f"latest-{label}.stderr", case.get("timeout_seconds", 1800))
            result["command"] = case[label]
            result["stdout_sha256"] = digest_file(case_dir / f"latest-{label}.stdout")
            result["stderr_sha256"] = digest_file(case_dir / f"latest-{label}.stderr")
            row[label] = result
            row["measurement_valid"] &= result["exit_code"] in case.get(label + "_exit_codes", [0]) and not result["process_error"]
        row["delta_seconds"] = row["gate"]["wall_seconds"] - row["baseline"]["wall_seconds"]
        rate = case.get("runner_price_usd_per_minute")
        row["prorated_cost_delta_usd"] = row["delta_seconds"] / 60 * rate if rate is not None else None
        append_row(raw, row)
        rows.append(row)
        print(f"{case['name']} pair {sequence}: delta={row['delta_seconds']:.3f}s valid={row['measurement_valid']}", flush=True)
    return rows


def historical_incidence(items, binary, cwd):
    rows = []
    hashes = set()
    for item in items:
        path = resolve(item["report"], cwd)
        validation = validate_report(path, binary, cwd, resolve(item["artifacts_root"], cwd) if item.get("artifacts_root") else None)
        if validation["report_sha256"] in hashes:
            raise ValueError("duplicate historical report would inflate the incidence denominator")
        hashes.add(validation["report_sha256"])
        report = load_json(path)
        metadata = report_metadata(report)
        eligible = item.get("clean_label") is True and metadata["scan_status"] == "complete" and metadata["provenance"] == "locally-executed"
        rows.append({"name": item["name"], "report": str(path), "report_sha256": validation["report_sha256"],
                     "validation": validation, "clean_label": item.get("clean_label"), "label_source": item.get("label_source"),
                     "eligible": eligible, "scanned_at": report.get("scanned_at"), **metadata})
    eligible = [row for row in rows if row["eligible"]]
    risk = sum(bool(row["findings_by_severity"].get("compatibility-risk")) for row in eligible)
    hard = sum(bool(row["findings_by_severity"].get("hard-failure")) for row in eligible)
    return {"scope": "Historical complete reports with caller-supplied clean labels. Convenience-sample report incidence, not population false-positive rate or a new noise experiment.",
            "label_independence_verified": False, "reports": rows, "eligible_reports": len(eligible),
            "risk_positive_reports": risk, "hard_failure_positive_reports": hard,
            "risk_incidence": risk / len(eligible) if eligible else None,
            "wilson_95_interval": wilson(risk, len(eligible)),
            "interval_assumption": "Independent Bernoulli sampling; correlated profiles and a selected corpus do not establish a population rate."}


def kb_age_policy(config, cwd):
    path = resolve(config["snapshot"], cwd)
    snapshot = load_json(path)
    as_of = date.fromisoformat(config["as_of"])
    created = date.fromisoformat(snapshot["created_at"][:10])
    if as_of < created:
        raise ValueError("KB age simulation cannot begin before this snapshot existed")
    entries = snapshot["entries"]
    dates = [(date.fromisoformat(entry["first_observed"]), date.fromisoformat(entry["last_verified"])) for entry in entries]
    if any(first > last or last > as_of for first, last in dates):
        raise ValueError("KB entry dates are inconsistent with the frozen as_of date")
    threshold = config.get("max_age_days", 30)
    rows = []
    for days in sorted(set(config["ages_days"])):
        simulated = as_of + timedelta(days=days)
        fresh_entries = sum((simulated - last).days <= threshold for _, last in dates)
        snapshot_age = (simulated - created).days
        rows.append({"elapsed_days": days, "simulated_date": simulated.isoformat(), "snapshot_age_calendar_days": snapshot_age,
                     "snapshot_accepted_by_age_policy": snapshot_age <= threshold, "entry_count": len(entries),
                     "entries_with_recent_verification": fresh_entries,
                     "entry_recency_fraction": fresh_entries / len(entries) if entries else None})
    return {"scope": "Frozen-snapshot verification-recency/age-policy simulation. No accuracy, recall, or compatibility decay is estimated.",
            "snapshot": str(path), "snapshot_sha256": digest_file(path), "snapshot_version": snapshot["snapshot_version"],
            "source_commit": snapshot.get("source_commit"), "as_of": as_of.isoformat(), "max_age_days": threshold,
            "date_resolution": "Calendar UTC dates; the scanner uses elapsed timestamp days, so boundary hours may differ.", "rows": rows}


def summarize(rows):
    groups = defaultdict(list)
    excluded = []
    for row in rows:
        if row["warmup"]:
            continue
        if not row["measurement_valid"]:
            excluded.append({key: row.get(key) for key in ["kind", "name", "sequence", "wall_seconds", "validation_error", "process_error"]})
            continue
        key = (row["kind"], row["name"], row.get("mode"), row.get("cache"), row.get("scan_status"), row.get("evidence_tier"),
               row.get("image_digest"), row.get("profile_sha256"), row.get("kb_snapshot_version"), json.dumps(row.get("target_runtime"), sort_keys=True))
        groups[key].append(row)
    result = []
    for key, samples in groups.items():
        kind, name, mode, cache, status, tier, image_digest, profile_digest, kb_snapshot, target = key
        value = {"kind": kind, "name": name, "mode": mode, "cache": cache, "scan_status": status, "evidence_tier": tier,
                 "image_digest": image_digest, "profile_sha256": profile_digest, "kb_snapshot_version": kb_snapshot, "target_runtime": json.loads(target)}
        if kind == "scan":
            value["wall_seconds"] = distribution([sample["wall_seconds"] for sample in samples])
            value["exit_codes"] = dict(Counter(sample["exit_code"] for sample in samples))
            value["cache_hits"] = [sample["cache_hits"] for sample in samples]
        else:
            value["paired_delta_seconds"] = distribution([sample["delta_seconds"] for sample in samples])
            value["baseline_seconds"] = distribution([sample["baseline"]["wall_seconds"] for sample in samples])
            value["gate_seconds"] = distribution([sample["gate"]["wall_seconds"] for sample in samples])
            value["environment"] = samples[0]["environment"]
            value["runner_price_usd_per_minute"] = samples[0]["runner_price_usd_per_minute"]
            value["cost_scope"] = "Optional caller-declared prorated price; not a bill, excludes billing rounding, free quotas, storage, and concurrent jobs."
        result.append(value)
    return {"groups": result, "excluded_invalid_measurements": excluded, "warmup_attempts": sum(row["warmup"] for row in rows),
            "measured_attempts": sum(not row["warmup"] for row in rows), "invalid_attempts_including_warmups": sum(not row["measurement_valid"] for row in rows)}


def svg_chart(path, title, labels, series, unit):
    """Small standalone bars; labels escaped, no external resources or JS."""
    if not labels:
        return
    width, left, top = 960, 320, 70
    row_height = max(48, 22 * len(series) + 10)
    height = top + row_height * len(labels) + 45
    maximum = max((value for _, values, _ in series for value in values if value is not None), default=1) or 1
    parts = [f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}" role="img">',
             f'<title>{escape(title)}</title><rect width="100%" height="100%" fill="#f9faf7"/>',
             f'<text x="24" y="30" font-family="sans-serif" font-size="19" fill="#183c3a">{escape(title)}</text>']
    for index, label in enumerate(labels):
        y = top + index * row_height
        parts.append(f'<text x="24" y="{y + 14}" font-family="sans-serif" font-size="12">{escape(label)}</text>')
        for offset, (name, values, color) in enumerate(series):
            value = values[index]
            if value is None:
                continue
            bar = max(0, value) / maximum * (width - left - 155)
            line_y = y + offset * 22
            parts.append(f'<rect x="{left}" y="{line_y}" width="{bar:.2f}" height="15" fill="{color}"/>')
            parts.append(f'<text x="{left + bar + 7:.2f}" y="{line_y + 12}" font-family="sans-serif" font-size="11">{escape(name)} {value:.3f} {escape(unit)}</text>')
    parts.append('</svg>')
    Path(path).write_text("\n".join(parts) + "\n", encoding="utf-8", newline="\n")


def markdown(summary, out):
    lines = ["# SENTRYCHECK benchmark observations", "", f"Generated at {summary['finished_at']}.", "",
             "These are measured observations for the recorded machine, binary, inputs, profiles, and cache policy. They do not establish production latency, compatibility guarantees, or population false-positive rates.", "",
             "Raw samples: [samples.jsonl](samples.jsonl). Exact manifest, tool identities, environment, validation results, and quantile uncertainty: [summary.json](summary.json).", "",
             "Timing includes scanner process startup, acquisition when requested, analysis, tracing/runtime startup for live scans, and JSON serialization. It excludes subsequent report validation and hashing. Warmups are recorded but excluded from distributions.", "",
             "## Scan latency", "", "Empirical nearest-rank percentiles; incomplete scans remain explicitly separated. Small-sample tail estimates are exploratory.", "",
             "| Case / mode / cache | Status / evidence | n | p50 (s) | p95 (s) | p99 (s) |", "| --- | --- | ---: | ---: | ---: | ---: |"]
    scans = [group for group in summary["measurements"]["groups"] if group["kind"] == "scan"]
    for group in scans:
        stats = group["wall_seconds"]
        lines.append(f"| {group['name']} / {group['mode']} / {group['cache']} | {group['scan_status']} / {group['evidence_tier']} | {stats['n']} | {stats['p50']:.6f} | {stats['p95']:.6f} | {stats['p99']:.6f} |")
    for group in scans:
        stats = group["wall_seconds"]
        for warning in stats["warnings"]:
            lines.append(f"\n{group['name']}: {warning}\n")
    if scans:
        labels = [f"{g['name']} (n={g['wall_seconds']['n']})" for g in scans]
        svg_chart(out / "latency.svg", "Observed scan latency (empirical percentiles)", labels,
                  [(p, [g["wall_seconds"][p] for g in scans], color) for p, color in [("p50", "#227c78"), ("p95", "#a96920"), ("p99", "#963f38")]], "s")
        lines.extend(["", "![Observed latency percentiles](latency.svg)"])
    else:
        lines.extend(["", "No valid scan-latency measurements were supplied."])
    lines.extend(["", "All confidence bounds in summary.json are conservative DKW bounds conditional on IID stationary samples. An unbounded tail is stored as null; shared-host repeated measurements may violate the IID assumption. No finite confidence bound is invented.", "",
                  f"Invalid attempts including warmups: {summary['measurements']['invalid_attempts_including_warmups']}. They remain in raw data and are excluded from percentile summaries.", "", "## CI cost delta", ""])
    pairs = [g for g in summary["measurements"]["groups"] if g["kind"] == "ci-pair"]
    for group in pairs:
        stats = group["paired_delta_seconds"]
        lines.append(f"- {group['name']}: {group['environment']}, {stats['n']} alternating-order paired samples; median added time {stats['p50']:.6f} seconds. Caller-declared USD/min rate: {group['runner_price_usd_per_minute']}. This is not a billing statement.")
    if not pairs:
        lines.append("Not measured. Local scanner timings are not presented as a GitHub Actions cost delta.")
    lines.extend(["", "## Historical clean-label risk incidence", ""])
    incidence = summary.get("historical_incidence")
    if incidence:
        lines.append(f"{incidence['risk_positive_reports']} of {incidence['eligible_reports']} eligible reports contained a compatibility-risk finding; {incidence['hard_failure_positive_reports']} contained a hard-failure finding. Labels and report hashes are recorded in summary.json.")
        lines.append(incidence["scope"])
        lines.append("No concurrent multi-tenant noise experiment was performed by this report-only analysis. Caller-provided labels have not been independently adjudicated by the benchmark harness.")
    else:
        lines.append("Not measured; no independently labeled clean population is inferred from an absence of scanner failures.")
    lines.extend(["", "## Frozen KB age policy", ""])
    age = summary.get("kb_age_policy")
    if age:
        lines.extend([age["scope"], "", "| Elapsed days | Snapshot accepted by age policy | Recently verified entries |", "| ---: | --- | ---: |"])
        for row in age["rows"]:
            lines.append(f"| {row['elapsed_days']} | {row['snapshot_accepted_by_age_policy']} | {row['entries_with_recent_verification']} / {row['entry_count']} |")
        svg_chart(out / "kb-age-policy.svg", "Frozen KB entry verification recency (not detection accuracy)",
                  [f"+{r['elapsed_days']} calendar days" for r in age["rows"]],
                  [("recent", [r["entry_recency_fraction"] * 100 if r["entry_recency_fraction"] is not None else None for r in age["rows"]], "#227c78")], "%")
        lines.extend(["", "![KB age policy, not accuracy decay](kb-age-policy.svg)"])
    else:
        lines.append("Not measured. Accuracy decay requires historical runtime releases and independently labeled outcomes, not merely entry dates.")
    lines.extend(["", "## Node overhead and unmeasured scope", "", "Steady-state node-probe/canary/CRI CPU and resident memory are not inferred from scanner time. This harness does not claim that measurement. Dedicated node resource sampling with and without the probe, fixed poll intervals, and retained raw samples is required.", "",
                  "Cold-analyzer means a new ELF cache, not a cold OS page cache or fresh registry cache. Warm-analyzer requires a recorded warmup. Existing host load, virtualization, debug/release build choice, registry traffic, and tracer overhead can materially affect results.", ""])
    (out / "BENCHMARKS.md").write_text("\n".join(lines), encoding="utf-8", newline="\n")


def run(args):
    manifest_path = args.manifest.resolve()
    manifest = check_manifest(load_json(manifest_path))
    cwd = args.cwd.resolve() if args.cwd else manifest_path.parent
    binary = executable(str(args.binary), Path.cwd())
    if not cwd.is_dir():
        raise ValueError("--cwd must be an existing directory")
    out = args.out.resolve()
    if out.exists():
        raise ValueError("--out must be a new directory; existing benchmark evidence is never overwritten")
    # Resolve identities and inputs outside measured intervals.
    runtime_names = {"runc", "runsc", "strace"}
    for case in manifest.get("cases", []):
        pairs = dict(zip(case.get("scan_args", [])[::2], case.get("scan_args", [])[1::2]))
        runtime_names.update(value for key, value in pairs.items() if key.endswith("-bin"))
    summary = {"schema_version": SCHEMA, "started_at": timestamp(), "status": "running", "manifest": manifest,
               "manifest_sha256": digest_file(manifest_path), "manifest_path": str(manifest_path), "cwd": str(cwd),
               "benchmark_script_sha256": digest_file(__file__), "scanner": identity(str(binary), cwd),
               "tools": [identity(tool, cwd) for tool in sorted(runtime_names)], "environment": environment(),
               "inputs": {case["name"]: input_description(case["image"], cwd) for case in manifest.get("cases", [])},
               "retained_reports": "all" if manifest.get("retain_reports", False) else "last sample per case only; earlier hashes/metadata remain in samples.jsonl"}
    summary["explicit_input_files"] = {}
    for case in manifest.get("cases", []):
        pairs = dict(zip(case.get("scan_args", [])[::2], case.get("scan_args", [])[1::2]))
        for key in ["--profile", "--kb"]:
            if key in pairs:
                path = resolve(pairs[key], cwd)
                summary["explicit_input_files"][str(path)] = {"sha256": digest_file(path), "bytes": path.stat().st_size}
    if "sha256" not in summary["scanner"]:
        raise ValueError("could not identify scanner binary")
    out.mkdir(parents=True)
    write_json(out / "summary.json", summary)
    rows = []
    with (out / "samples.jsonl").open("x", encoding="utf-8", newline="\n") as raw:
        try:
            for case in manifest.get("cases", []):
                rows.extend(run_case(case, binary, cwd, out, raw, manifest.get("retain_reports", False)))
            for case in manifest.get("ci_pairs", []):
                rows.extend(run_ci_pair(case, cwd, out, raw))
            if manifest.get("historical_reports"):
                summary["historical_incidence"] = historical_incidence(manifest["historical_reports"], binary, cwd)
            if manifest.get("kb_age"):
                summary["kb_age_policy"] = kb_age_policy(manifest["kb_age"], cwd)
            summary["status"] = "complete" if all(row["measurement_valid"] for row in rows) else "completed-with-invalid-measurements"
        except (OSError, ValueError, KeyError, TypeError, subprocess.TimeoutExpired, KeyboardInterrupt) as error:
            summary["status"] = "failed"
            summary["error"] = str(error) or type(error).__name__
        finally:
            # Also recover flushed rows if a later sample aborted run_case before
            # it could return its in-memory list.
            raw.flush()
            with (out / "samples.jsonl").open(encoding="utf-8") as recorded:
                rows = [json.loads(line) for line in recorded if line.strip()]
            summary["scanner_sha256_at_finish"] = digest_file(binary)
            if summary["scanner_sha256_at_finish"] != summary["scanner"]["sha256"]:
                summary["status"] = "failed"
                summary["error"] = "scanner binary changed during the experiment; measurements must not be attributed to one binary"
            summary["finished_at"] = timestamp()
            summary["measurements"] = summarize(rows)
            summary["raw_samples_sha256"] = digest_file(out / "samples.jsonl")
            write_json(out / "summary.json", summary)
            markdown(summary, out)
    print(f"Wrote {out / 'BENCHMARKS.md'} ({summary['status']})", flush=True)
    return 0 if summary["status"] == "complete" else 2


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    measure = commands.add_parser("run", help="run only the explicit experiments in a manifest")
    measure.add_argument("--manifest", type=Path, required=True)
    measure.add_argument("--binary", type=Path, required=True)
    measure.add_argument("--out", type=Path, required=True)
    measure.add_argument("--cwd", type=Path, help="working directory and base for manifest paths (default: manifest directory)")
    args = parser.parse_args()
    try:
        return run(args)
    except (OSError, ValueError, KeyError, TypeError) as error:
        print(f"benchmark: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
