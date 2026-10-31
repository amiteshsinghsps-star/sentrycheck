"""Linux process-tree observations for an idle K3s window and a periodic probe.

Counts sampled own-process CPU ticks and sums per-process RSS. These are not
unique physical memory, a whole-node profiler, or a billing estimate.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import math
import os
from pathlib import Path
import platform
import signal
import subprocess
import sys
import time


def now():
    return datetime.now(timezone.utc).isoformat()


def digest(path):
    value = hashlib.sha256()
    with Path(path).open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            value.update(block)
    return "sha256:" + value.hexdigest()


def save(path, value):
    Path(path).write_text(json.dumps(value, indent=2, allow_nan=False) + "\n", encoding="utf-8", newline="\n")


def parse_stat(text, page_size):
    closing = text.rfind(")")
    opening = text.find("(")
    if opening < 1 or closing <= opening:
        raise ValueError("invalid /proc stat record")
    fields = text[closing + 2:].split()
    if len(fields) < 22:
        raise ValueError("short /proc stat record")
    return {"pid": int(text[:opening].strip()), "name": text[opening + 1:closing], "state": fields[0],
            "ppid": int(fields[1]), "process_group": int(fields[2]), "session": int(fields[3]),
            "cpu_ticks": int(fields[11]) + int(fields[12]), "start_ticks": int(fields[19]),
            "rss_sum_bytes": max(0, int(fields[21])) * page_size}


def proc_table(proc_root, page_size):
    rows, missing = {}, 0
    for path in proc_root.iterdir():
        if not path.name.isdigit():
            continue
        try:
            row = parse_stat((path / "stat").read_text(), page_size)
            rows[row["pid"]] = row
        except (OSError, ValueError, IndexError):
            missing += 1
    return rows, missing


def key(row):
    return (row["pid"], row["start_ticks"])


def identify(pid, proc_root, page_size):
    row = parse_stat((proc_root / str(pid) / "stat").read_text(), page_size)
    try:
        path = (proc_root / str(pid) / "exe").resolve(strict=True)
        row["executable"] = str(path)
        row["executable_sha256"] = digest(path)
    except OSError:
        row["executable"] = None
    return row


def select_processes(table, roots, remembered):
    """Follow PPID trees, dedicated root sessions, and previously seen identities."""
    selected = set()
    sessions = set()
    for root in roots:
        current = table.get(root["pid"])
        if current is None or key(current) != key(root) or current["state"] == "Z":
            raise ValueError(f"measurement root exited or PID was reused: {root['pid']}")
        selected.add(current["pid"])
        # Only include a session when this root created it. This prevents an
        # ordinary shell session from accidentally including unrelated work.
        if root["session"] == root["pid"]:
            sessions.add(root["session"])
    for row in table.values():
        if key(row) in remembered or row["session"] in sessions:
            selected.add(row["pid"])
    changed = True
    while changed:
        changed = False
        for row in table.values():
            if row["ppid"] in selected and row["pid"] not in selected:
                selected.add(row["pid"])
                changed = True
    rows = [table[pid] for pid in sorted(selected)]
    remembered.update(key(row) for row in rows)
    return rows


def read_probe(path):
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
        return {field: value.get(field) for field in ["checkedAt", "state", "healthy", "verified", "node", "architecture",
                "handler", "runtime", "runtimeType", "expectedVersion", "observedVersion", "canaryID", "canaryState"]}
    except (OSError, ValueError):
        # The Go tool replaces this file without an atomic rename. A transient
        # partial read is explicitly missing data, not an unhealthy node claim.
        return None


def healthy(report):
    return report is not None and report.get("state") == "canary-verified" and report.get("healthy") is True and report.get("verified") is True


def sample_window(name, roots, seconds, interval, raw_path, proc_root, page_size, ticks_per_second, probe_report=None):
    remembered, previous_cpu = set(), {}
    started_wall, started = now(), time.monotonic()
    start_boot = float((proc_root / "uptime").read_text().split()[0])
    cumulative_cpu = 0.0
    weighted_rss = 0.0
    last_elapsed, last_rss = None, None
    peak_rss = 0
    seen_reports = {}
    missing_reports = 0
    samples, unavailable_records = 0, 0
    with raw_path.open("x", encoding="utf-8") as stream:
        while True:
            iteration_started = time.monotonic()
            table, missed = proc_table(proc_root, page_size)
            selected = select_processes(table, roots, remembered)
            elapsed = time.monotonic() - started
            delta_ticks = 0
            for row in selected:
                identity = key(row)
                if identity in previous_cpu:
                    delta_ticks += max(0, row["cpu_ticks"] - previous_cpu[identity])
                elif row["start_ticks"] / ticks_per_second >= start_boot:
                    # This process was born within the window; all of its own
                    # CPU to first observation belongs to the current window.
                    delta_ticks += row["cpu_ticks"]
                previous_cpu[identity] = row["cpu_ticks"]
            delta_cpu = delta_ticks / ticks_per_second
            cumulative_cpu += delta_cpu
            rss = sum(row["rss_sum_bytes"] for row in selected)
            peak_rss = max(peak_rss, rss)
            if last_elapsed is not None:
                weighted_rss += (elapsed - last_elapsed) * (last_rss + rss) / 2
            report = read_probe(probe_report) if probe_report else None
            if probe_report:
                if report is None:
                    missing_reports += 1
                elif report.get("checkedAt"):
                    seen_reports.setdefault(report["checkedAt"], {"first_observed_elapsed_seconds": elapsed, **report})
            row = {"window": name, "sample": samples, "observed_at": now(), "elapsed_seconds": elapsed,
                   "cpu_delta_seconds": delta_cpu, "cpu_cumulative_seconds": cumulative_cpu,
                   "rss_sum_bytes": rss, "process_count": len(selected), "processes": selected,
                   "unreadable_proc_records": missed, "probe_report": report,
                   "observer_iteration_seconds": time.monotonic() - iteration_started}
            stream.write(json.dumps(row, allow_nan=False) + "\n")
            stream.flush()
            unavailable_records += missed
            samples += 1
            last_elapsed, last_rss = elapsed, rss
            if elapsed >= seconds:
                break
            time.sleep(min(max(0.0, interval - (time.monotonic() - iteration_started)), seconds - elapsed))
        os.fsync(stream.fileno())
    result = {"name": name, "started_at": started_wall, "finished_at": now(), "requested_seconds": seconds,
              "observed_seconds": last_elapsed, "sample_count": samples, "requested_sample_interval_seconds": interval,
              "observed_own_process_cpu_seconds": cumulative_cpu,
              "average_cores_observed": cumulative_cpu / last_elapsed,
              "average_cpu_percent_one_core_observed": cumulative_cpu / last_elapsed * 100,
              "time_weighted_mean_rss_sum_bytes": weighted_rss / last_elapsed,
              "peak_sampled_rss_sum_bytes": peak_rss, "distinct_process_identities": len(remembered),
              "unreadable_proc_records_total": unavailable_records, "raw_path": str(raw_path), "raw_sha256": digest(raw_path),
              "roots": roots}
    if probe_report:
        result["probe_reports_observed"] = list(seen_reports.values())
        result["missing_or_partial_probe_report_samples"] = missing_reports
        result["all_observed_reports_healthy"] = bool(seen_reports) and all(healthy(report) for report in seen_reports.values())
    return result


def stop_probe(process):
    if process is None:
        return None
    if process.poll() is None:
        process.send_signal(signal.SIGTERM)
        try:
            process.wait(timeout=30)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=10)
            return {"exit_code": process.returncode, "forced": True}
    return {"exit_code": process.returncode, "forced": False}


def markdown(summary, out):
    lines = ["# Node-probe process observations", "", f"Status: **{summary['status']}**. Recorded at {summary['finished_at']}.", "",
             "Two sequential windows on one disposable node. CPU is observed own-process CPU from sampled processes. RSS is the sum of each process's resident pages, including shared-page double counting. These are neither unique physical memory nor an independently controlled causal estimate.", "",
             "| Window | Seconds | Samples | Observed CPU seconds | Mean observed cores | Time-weighted RSS sum (MiB) | Peak sampled RSS sum (MiB) |",
             "| --- | ---: | ---: | ---: | ---: | ---: | ---: |"]
    for window in summary.get("windows", []):
        lines.append(f"| {window['name']} | {window['observed_seconds']:.3f} | {window['sample_count']} | {window['observed_own_process_cpu_seconds']:.3f} | {window['average_cores_observed']:.4f} | {window['time_weighted_mean_rss_sum_bytes'] / 2**20:.3f} | {window['peak_sampled_rss_sum_bytes'] / 2**20:.3f} |")
    if "difference" in summary:
        difference = summary["difference"]
        lines.extend(["", f"Active minus idle observed mean CPU: {difference['average_cores_observed']:.4f} cores. Active minus idle time-weighted RSS **sum**: {difference['time_weighted_mean_rss_sum_bytes'] / 2**20:.3f} MiB.",
                      "This difference includes time-varying K3s activity and allocator/cache retention, not only the probe. Negative differences are preserved."])
    lines.extend(["", "Short-lived children that start and exit between polls can be completely missed. CPU after a process's last sample and before exit is also missed. Parent child-CPU fields are excluded to avoid double counting. Per-process start times distinguish PID reuse. Dedicated sessions and remembered descendants retain visibility after ordinary reparenting; unrelated services and kernel work are outside scope.", "",
                  "The sampler has an observer effect. One idle-then-active pair does not establish a stable population mean or statistical confidence interval. Repeat in counterbalanced order on fresh nodes for a stronger estimate. Probe shutdown/cancellation is outside the active measurement window.", "",
                  "Exact roots, executable hashes, probe states, sample intervals, environment, and raw JSONL hashes are in [summary.json](summary.json). Raw windows are [idle.jsonl](idle.jsonl) and [active.jsonl](active.jsonl).", ""])
    if summary.get("error"):
        lines.append("Failure: " + summary["error"])
    (out / "NODE-BENCHMARK.md").write_text("\n".join(lines), encoding="utf-8", newline="\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--server-pid", type=int, required=True)
    parser.add_argument("--seconds", type=float, default=60)
    parser.add_argument("--sample-interval", type=float, default=0.2)
    parser.add_argument("--warmup-timeout", type=float, default=90)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--probe-report", type=Path, required=True)
    parser.add_argument("probe_command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    if not sys.platform.startswith("linux"):
        parser.error("Linux /proc is required; another platform is not substituted")
    for field in ["seconds", "sample_interval", "warmup_timeout"]:
        value = getattr(args, field)
        if not math.isfinite(value) or value <= 0:
            parser.error(f"{field} must be finite and positive")
    if args.sample_interval < 0.05 or args.seconds < args.sample_interval:
        parser.error("sample interval must be >= 0.05 seconds and fit inside the window")
    command = args.probe_command[1:] if args.probe_command[:1] == ["--"] else args.probe_command
    if not command:
        parser.error("a periodic probe command after -- is required")
    out = args.out.resolve()
    if out.exists():
        parser.error("--out must be a new directory; measurements are not overwritten")
    if args.probe_report.exists():
        parser.error("--probe-report must be new; stale health evidence is refused")
    out.mkdir(parents=True)
    args.probe_report = args.probe_report.resolve()
    args.probe_report.parent.mkdir(parents=True, exist_ok=True)
    proc_root = Path("/proc")
    page_size = os.sysconf("SC_PAGE_SIZE")
    ticks = os.sysconf("SC_CLK_TCK")
    summary = {"schema_version": "1.0", "status": "running", "started_at": now(), "windows": [],
               "probe_command": command, "benchmark_script_sha256": digest(__file__),
               "environment": {"platform": platform.platform(), "kernel": platform.release(), "logical_cpus": os.cpu_count(),
                               "page_size": page_size, "clock_ticks_per_second": ticks},
               "scope": "Sampled process-tree CPU and sum of per-process RSS on one disposable node; not unique memory or a causal population estimate."}
    process = None
    def interrupt(_signal, _frame):
        raise KeyboardInterrupt("node measurement interrupted")
    signal.signal(signal.SIGTERM, interrupt)
    save(out / "summary.json", summary)
    try:
        server = identify(args.server_pid, proc_root, page_size)
        if server["session"] != server["pid"]:
            raise ValueError("server must lead its dedicated session (start the disposable K3s with setsid)")
        print(f"Measuring idle K3s for {args.seconds:g}s", flush=True)
        summary["windows"].append(sample_window("idle", [server], args.seconds, args.sample_interval, out / "idle.jsonl", proc_root, page_size, ticks))
        with (out / "probe.stdout.log").open("wb") as stdout, (out / "probe.stderr.log").open("wb") as stderr:
            process = subprocess.Popen(command, stdout=stdout, stderr=stderr, start_new_session=True)
            deadline = time.monotonic() + args.warmup_timeout
            while time.monotonic() < deadline:
                if process.poll() is not None:
                    raise ValueError(f"periodic probe exited during warmup: {process.returncode}")
                report = read_probe(args.probe_report)
                if healthy(report):
                    summary["warmup_report"] = report
                    break
                if report is not None:
                    raise ValueError(f"periodic probe warmup is unhealthy: {report.get('state')}")
                time.sleep(0.2)
            else:
                raise ValueError("periodic probe did not publish a healthy warmup report before timeout")
            probe = identify(process.pid, proc_root, page_size)
            print(f"Measuring K3s plus healthy periodic probe for {args.seconds:g}s", flush=True)
            summary["windows"].append(sample_window("active", [server, probe], args.seconds, args.sample_interval, out / "active.jsonl", proc_root, page_size, ticks, args.probe_report))
            active = summary["windows"][-1]
            if not active["all_observed_reports_healthy"]:
                raise ValueError("an observed probe report was unhealthy during the active window")
            if len(active["probe_reports_observed"]) < 2:
                raise ValueError("active window did not observe at least two completed periodic probes")
            summary["status"] = "complete"
    except (OSError, ValueError, KeyboardInterrupt) as error:
        summary["status"] = "failed"
        summary["error"] = str(error) or type(error).__name__
    finally:
        summary["probe_shutdown"] = stop_probe(process)
        if summary["probe_shutdown"] and (summary["probe_shutdown"]["forced"] or summary["probe_shutdown"]["exit_code"] != 0):
            summary["status"] = "failed"
            summary["error"] = "periodic probe did not shut down cleanly; inspect captured logs"
        if len(summary["windows"]) == 2:
            idle, active = summary["windows"]
            summary["difference"] = {field: active[field] - idle[field] for field in ["average_cores_observed", "time_weighted_mean_rss_sum_bytes"]}
        summary["finished_at"] = now()
        for name in ["probe.stdout.log", "probe.stderr.log"]:
            if (out / name).exists():
                summary[name + "_sha256"] = digest(out / name)
        save(out / "summary.json", summary)
        markdown(summary, out)
    print(f"Node measurement {summary['status']}: {out / 'summary.json'}", flush=True)
    return 0 if summary["status"] == "complete" else 2


if __name__ == "__main__":
    raise SystemExit(main())
