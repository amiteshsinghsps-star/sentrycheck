"""BH-04 run driver: execute one case and record every byte it produced.

Static scans run on the host's own scanner binary. Live scans are delegated to a generated
LF shell script because they need Linux, and the script stages its work in the ext4 home
rather than on /mnt/c: 9p breaks symlink handling and the scanner refuses to clean up a
rootfs mounted from it. The same script runs unchanged when the harness itself is already
on Linux, which is what makes a cross-interpreter reproducibility claim (BM-13) testable.

Report bytes are stored exactly as the tool emitted them. Rewriting the absolute refs a
report contains would change the digest that the evidence tier exists to guarantee, so the
harness keeps the pristine bytes and binds them by digest in run.json instead.
"""
import json
import os
import shutil
import subprocess
import time
from pathlib import Path

from bench import BENCH_VERSION
from bench.common import (BENCH, ROOT, BenchError, now_iso, quantize, read_json, rel_path, resolve,
                          sha256_file)
from bench import cases as case_registry
from bench import predict
from bench import preflight
from bench.store import RunStore

STAGE = BENCH / ".tmp"
PRODUCT_KB_AGE_DAYS = 30
WINDOWS_BINARIES = ("target/debug/sentrycheck.exe", "bin/sentrycheck.exe")
LINUX_BINARIES = ("target/x86_64-unknown-linux-gnu/debug/sentrycheck", "bin/sentrycheck-linux")
RUNSC = ".cache/linux/bin/runsc"
# runsc resolves its sidecar companions relative to its own directory and refuses to create the
# sandbox under --sidecar-usage-policy STRICT when they are missing, so the release tree that
# holds gvisor_sentry has to travel with the binary.
GVISOR_BIN = ".cache/linux/bin/gvisor-bin"
WSL_DISTRO = "Ubuntu"
# gVisor spawns its gofer with fork/exec /proc/self/exe, which an unprivileged WSL user cannot do here,
# so live runs execute as root inside the distro and say so in the record.
WSL_USER = "root"
LIVE_WORK_BASE = "/var/tmp"


def find_binary(candidates, required=True):
    for relative in candidates:
        path = ROOT / relative
        if path.is_file() and path.stat().st_size > 0:
            return path
    if required:
        raise BenchError("no scanner binary found among %s; build it first" % ", ".join(candidates))
    return None


def linux_repo_path():
    """The repository as the Linux side sees it, or None if it is not mountable."""
    text = str(ROOT).replace("\\", "/")
    if len(text) >= 2 and text[1] == ":":
        return "/mnt/%s%s" % (text[0].lower(), text[2:])
    return text if Path(text).is_dir() else None


def to_linux_path(value):
    text = str(value).replace("\\", "/")
    if len(text) >= 2 and text[1] == ":":
        return "/mnt/%s%s" % (text[0].lower(), text[2:])
    return text


def tool_identity(binary):
    version = None
    try:
        done = subprocess.run([str(binary), "--version"], capture_output=True, text=True, timeout=60,
                              encoding="utf-8", errors="replace")
        first = (done.stdout or done.stderr).strip().splitlines()
        parts = first[0].split() if first else []
        version = parts[1] if len(parts) > 1 else (parts[0] if parts else None)
    except (OSError, subprocess.TimeoutExpired):
        version = None
    # The repository has no commit checked out, so a git identity would be invented data.
    return {"name": "sentrycheck", "version": version or "unknown", "git_commit": None,
            "binary_sha256": sha256_file(binary)}


def kb_identity(max_age_days):
    snapshot = ROOT / "kb" / "snapshot.json"
    if not snapshot.is_file():
        raise BenchError("kb/snapshot.json is missing; the knowledge base identity cannot be recorded")
    data = read_json(snapshot)
    return {"snapshot_version": data.get("snapshot_version") or "unknown",
            "sha256": sha256_file(snapshot), "max_age_days": int(max_age_days)}


def runtime_identity(name, release, binary, platform_name):
    return {"name": name, "release": release, "platform": platform_name,
            "binary_sha256": sha256_file(binary) if binary else None}


def scan_argv(scanner, image, profile, cache, artifacts, report, runsc=None, release=None,
              max_age_days=PRODUCT_KB_AGE_DAYS, mode="static"):
    argv = [str(scanner), "scan", str(image), "--profile", str(profile), "--format", "json",
            "--output", str(report), "--cache", str(cache), "--artifacts", str(artifacts),
            "--max-kb-age-days", str(int(max_age_days)), "--no-cache"]
    if release:
        argv += ["--version", str(release)]
    if runsc:
        argv += ["--runsc-bin", str(runsc)]
    if mode == "static":
        argv.append("--static-only")
    elif mode == "native-only":
        argv.append("--native-only")
    return argv


def run_process(argv, timeout):
    started = time.perf_counter()
    try:
        done = subprocess.run(argv, capture_output=True, timeout=timeout, encoding="utf-8", errors="replace")
    except subprocess.TimeoutExpired:
        return "", "", "timed out after %ds" % timeout, None, int(round((time.perf_counter() - started) * 1000))
    return (done.stdout or ""), (done.stderr or ""), None, done.returncode, \
        int(round((time.perf_counter() - started) * 1000))


def live_script(work, repo, stage, argv, copy_in, host_record=None):
    """Shell text: stage inputs into the work root, observe the environment, scan, copy back."""
    quoted = " ".join(json.dumps(str(part)) for part in argv)
    lines = ["#!/usr/bin/env bash", "set -u",
             'repo=%s' % json.dumps(repo),
             'stage=%s' % json.dumps(str(stage)),
             'WORK=%s' % json.dumps(work),
             'rm -rf "$WORK"', 'mkdir -p "$WORK/artifacts" "$WORK/cache"',
             'mkdir -p "$stage"']
    for source, target, kind in copy_in:
        flag = "-rL" if kind in ("dir", "bindir") else "-L"
        lines.append('cp %s "$repo/%s" "$WORK/%s" || { echo "staging failed for %s" >&2; exit 20; }' % (flag, source, target, source))
        # Windows checkouts and 9p copies can lose the executable bit; staged binaries must run.
        chmod = {"file": "+x", "bindir": "-R +x"}.get(kind)
        if chmod:
            lines.append('chmod %s "$WORK/%s" 2>/dev/null || true' % (chmod, target))
    if host_record:
        # Disk, load and mount type belong to the host that executes the scan, so the observation
        # runs here rather than on the driving machine. It sits outside the timed region.
        lines.append('if command -v python3 >/dev/null 2>&1; then (cd "$repo" && python3 -m bench preflight --json'
                     ' --host %s --work-root "$WORK") > "$WORK/preflight.json" 2> "$WORK/preflight.err" || true; fi'
                     % json.dumps(host_record))
    lines += ['cd "$WORK" || exit 21',
              # /proc/uptime is CLOCK_BOOTTIME, so a WSL wall-clock step cannot make a duration
              # negative; date +%s%3N did, and a negative duration fails the run contract.
              'start=$(awk \'{printf "%d", $1*1000}\' /proc/uptime)',
              'if [ -x /usr/bin/time ]; then',
              '  /usr/bin/time -f "%%M %%x" -o "$WORK/time.txt" %s > "$WORK/stdout.txt" 2> "$WORK/stderr.txt"' % quoted,
              'else',
              '  %s > "$WORK/stdout.txt" 2> "$WORK/stderr.txt"' % quoted,
              'fi',
              'code=$?',
              'end=$(awk \'{printf "%d", $1*1000}\' /proc/uptime)',
              'printf "%s %s %s\\n" "$code" "$start" "$end" > "$WORK/status.txt"',
              'echo "$(id -u) $(id -un) $(uname -r)" > "$WORK/identity.txt"',
              'cp -r "$WORK/artifacts" "$stage/artifacts" 2>/dev/null || true',
              'for name in stdout.txt stderr.txt status.txt time.txt report.json identity.txt preflight.json; do',
              '  cp "$WORK/$name" "$stage/$name" 2>/dev/null || true',
              'done',
              'exit 0']
    return "\n".join(lines) + "\n"


def execute_live(argv, copy_in, stage, timeout, use_wsl, host_record=None):
    """Run the live script either through wsl.exe or directly when already on Linux."""
    repo = linux_repo_path()
    if repo is None:
        raise BenchError("live execution needs the repository reachable from a Linux mount")
    work = "%s/bench-work/%s" % (LIVE_WORK_BASE, stage.name)
    if stage.exists():
        shutil.rmtree(str(stage), ignore_errors=True)
    stage.mkdir(parents=True, exist_ok=True)
    script = stage / "live.sh"
    write_script(script, live_script(work, repo, to_linux_path(stage) if use_wsl else str(stage), argv, copy_in,
                                     host_record))
    invocation = (["wsl.exe", "-d", WSL_DISTRO, "-u", WSL_USER, "--", "bash", to_linux_path(script)] if use_wsl
                  else ["bash", str(script)])
    started = time.perf_counter()
    try:
        done = subprocess.run(invocation, capture_output=True, timeout=timeout, encoding="utf-8", errors="replace")
    except subprocess.TimeoutExpired:
        return {}, "live driver timed out after %ds" % timeout, None
    total = int(round((time.perf_counter() - started) * 1000))
    stderr = (done.stderr or "").replace("\r\n", "\n") if done is not None else "no wsl.exe"
    payload = {}
    for name in ("report.json", "stdout.txt", "stderr.txt", "time.txt", "status.txt", "identity.txt", "preflight.json"):
        path = stage / name
        if path.is_file():
            payload[name] = path.read_bytes() if name == "report.json" else path.read_text(encoding="utf-8", errors="replace")
    if "status.txt" not in payload:
        return payload, "live driver produced no status file; %s" % (stderr.strip()[:400] or "no output"), total
    code, start, end = payload["status.txt"].split()
    payload["scan_ms"] = int(end) - int(start)
    payload["exit_code"] = int(code)
    payload["driver_ms"] = total
    return payload, None, total


def write_script(path, text):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="\n") as handle:
        handle.write(text)


def collect_artifacts(stage):
    """Map the scanner artifact tree onto repo-safe names with their digests computed later."""
    found = {}
    root = stage / "artifacts"
    if not root.is_dir():
        return found
    for path in sorted(root.rglob("*"), key=lambda item: item.as_posix()):
        if not path.is_file():
            continue
        parts = path.relative_to(root).as_posix().split("/")
        mode = next((part.split("-")[0] for part in parts
                     if part.startswith("native-") or part.startswith("sandbox-")), None)
        index = next((int(part.rsplit("-", 1)[1]) for part in parts
                      if part.startswith(("native-", "sandbox-"))), 0)
        label = "%s-%d" % (mode, index) if mode else "scan"
        name = path.name
        if name.endswith(".trace"):
            key = "traces/%s-%s" % (label, name)
        elif mode and name in ("stdout.txt", "stderr.txt") and label != "scan":
            key = "outputs/%s-%s" % (label, name)
        else:
            key = "logs/%s-%s" % (label, name)
        if key in found:
            key = "logs/%s-%s" % (label, "/".join(parts[-2:]))
        found[key] = path
    return found


def repetitions_from(report):
    dynamic = (report or {}).get("dynamic") or {}
    native, sandbox = dynamic.get("native") or [], dynamic.get("sandbox") or []
    return {"native_exits": [item.get("exit_code") for item in native],
            "sandbox_exits": [item.get("exit_code") for item in sandbox],
            "native_durations_ms": [int(item.get("duration_ms") or 0) for item in native],
            "sandbox_durations_ms": [int(item.get("duration_ms") or 0) for item in sandbox]}


TIMING_SUITES = ("BM-08", "BM-09")


def preflight_summary(result):
    """The part of a preflight report a record has to carry: the verdict and the failed ids."""
    if not result:
        return None
    return {"live_capable": bool(result.get("live_capable")),
            "timing_capable": bool(result.get("timing_capable")),
            "failed": sorted(result.get("failed") or [])}


def preflight_refusal(summary, suite):
    """Why the environment cannot support this suite, or None when it can."""
    if summary is None:
        return "preflight did not run on the executing host, so the environment is unverified"
    budget = ["live_capable", "timing_capable"] if suite in TIMING_SUITES else ["live_capable"]
    if not all(summary[key] for key in budget):
        return "preflight refused %s (%s failed: %s)" % (suite, "+".join(budget), ", ".join(summary["failed"]) or "none listed")
    return None


def local_preflight(host, work_root):
    try:
        return preflight.check(host_record=host, work_root=work_root)
    except BenchError as error:
        return {"live_capable": False, "timing_capable": False, "failed": ["preflight-error"],
                "checks": [{"id": "preflight-error", "status": "fail", "detail": str(error)}]}


def profile_repetitions(path):
    """The workload repetition count belongs to the profile document, not to a CLI knob."""
    try:
        import tomllib
        with open(path, "rb") as handle:
            return int(tomllib.load(handle).get("repetitions") or 1)
    except (OSError, TypeError, ValueError):
        return None


def environment_block(host, work_root, preflight=None):
    cpu, storage = host.get("cpu") or {}, host.get("storage") or {}
    load, clock = host.get("load_average") or {}, host.get("clock") or {}
    return {"governor": cpu.get("governor"), "smt": cpu.get("smt"),
            "cores": list(range(int(cpu.get("cores") or 0))), "load_before": load.get("one"),
            "free_disk_mb": storage.get("free_mb"), "clock_synced": clock.get("synced"),
            "work_root": work_root, "host_load_controlled": bool(host.get("host_load_controlled", False)),
            "preflight": preflight_summary(preflight)}


def build_record(case, host, suite, seed, order_index, order_pattern, tool, kb, runtime, environment,
                 report_payload, timings, valid, invalid_reason, notes, run_id=None):
    prediction = predict.predict(report_payload) if report_payload else None
    return {"schema_version": "1.0", "run_id": run_id or "r-%s-%s-%s" % (case["case_id"], suite.replace("-", "").lower(),
            time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())),
            "case_id": case["case_id"], "suite": suite, "host_id": host["host_id"],
            "started_at": timings["started_at"], "ended_at": timings["ended_at"], "seed": int(seed),
            "order_index": int(order_index), "order_pattern": order_pattern, "tool": tool, "kb": kb,
            "runtime": runtime, "environment": environment, "predicted": prediction,
            "repetitions": repetitions_from(report_payload),
            "timings_ms": {"scan": timings.get("scan_ms"), "total": timings.get("total_ms")},
            "resources": {"peak_rss_mb": timings.get("peak_rss_mb"), "disk_mb": None},
            "valid": bool(valid), "invalid_reason": invalid_reason, "notes": notes}


def load_host(path):
    record = read_json(resolve(path) if not Path(path).is_absolute() else path)
    return record


def command_run(args):
    case = case_registry.load(args.case)
    host = load_host(args.host)
    store = RunStore(args.out or BENCH / "runs")
    max_age = args.max_kb_age_days if args.max_kb_age_days is not None else PRODUCT_KB_AGE_DAYS
    live = bool(args.live)
    use_wsl = live and not Path("/proc/version").exists()
    stage = STAGE / ("stage-%s" % args.case)
    profile = ROOT / case["profile"]["path"]
    pinned_repetitions = profile_repetitions(profile)
    if pinned_repetitions is not None and int(args.repetitions) != pinned_repetitions:
        # scan.rs compares the completed runs against profile.repetitions and offers no override, so
        # accepting a different number here would record a knob that was never turned.
        raise BenchError("profile %s pins repetitions=%d; the harness cannot ask for %d"
                         % (rel_path(profile), pinned_repetitions, int(args.repetitions)))
    if not case["image"].get("local_path"):
        raise BenchError("case %s has no local workload; run bench fetch to pin it first" % case["case_id"])
    image = ROOT / case["image"]["local_path"]
    release = case["runtime"]["release"]
    started_at = now_iso()
    started = time.perf_counter()
    timings = {"started_at": started_at, "ended_at": started_at, "scan_ms": None, "total_ms": None, "peak_rss_mb": None}
    if args.dry_run:
        print(json.dumps({"live": live, "workload": case["image"]["local_path"],
                          "argv": scan_argv("<scanner>", image, profile, "<cache>", "<artifacts>", "<report>",
                                            "<runsc>" if live else None, release, max_age,
                                            "live" if live else "static")}, indent=2))
        return 0
    report_bytes, stdout, stderr, exit_code = None, "", "", None
    infrastructure_failure, payload, environment = None, {}, None
    if live:
        copy_in = [(rel_path(find_binary(LINUX_BINARIES)), "scanner", "file"),
                   (case["profile"]["path"], "profile.toml", "file"),
                   (case["image"]["local_path"], "image", "dir"),
                   (RUNSC, "runsc", "file"),
                   (GVISOR_BIN, "gvisor-bin", "bindir")]
        argv = scan_argv("$WORK/scanner", "$WORK/image", "$WORK/profile.toml", "$WORK/cache",
                         "$WORK/artifacts", "$WORK/report.json", "$WORK/runsc", release, max_age, "live")
        payload, failure, driver_ms = execute_live(argv, copy_in, stage, timeout=args.timeout, use_wsl=use_wsl,
                                                   host_record=rel_path(args.host))
        timings["total_ms"] = driver_ms
        if payload.get("preflight.json"):
            try:
                environment = json.loads(payload["preflight.json"])
            except ValueError:
                environment = None
        if failure:
            report_bytes, infrastructure_failure = None, "live scan failed: %s" % failure[:400]
        else:
            report_bytes = payload.get("report.json")
            stdout, stderr = payload.get("stdout.txt", ""), payload.get("stderr.txt", "")
            exit_code = payload.get("exit_code")
            timings["scan_ms"], timings["total_ms"] = payload.get("scan_ms"), payload.get("driver_ms")
    else:
        scanner = find_binary(WINDOWS_BINARIES if os.name == "nt" else LINUX_BINARIES)
        argv = scan_argv(scanner, image, profile, stage / "cache", stage / "artifacts", stage / "report.json",
                         None, release, max_age, "static")
        stdout, stderr, error, exit_code, timings["scan_ms"] = run_process(argv, timeout=args.timeout)
        timings["total_ms"] = timings["scan_ms"]
        report_bytes = (stage / "report.json").read_bytes() if (stage / "report.json").is_file() else None
        if error:
            report_bytes, infrastructure_failure = None, "static scan error: %s" % error[:400]
        environment = local_preflight(host, stage)
    if "time.txt" in payload and payload["time.txt"].split():
        try:
            timings["peak_rss_mb"] = quantize(int(payload["time.txt"].split()[0]) / 1024.0)
        except ValueError:
            pass
    report_payload = json.loads(report_bytes.decode("utf-8")) if report_bytes else None
    # valid describes whether the *measurement* happened: a timeout, a missing report or a
    # schema-violating report invalidates the run. An incomplete *status* is a real result of
    # the tool's evidence policy, so it is recorded and scored as such, never discarded.
    valid, invalid_reason = infrastructure_failure is None, infrastructure_failure
    if report_payload is None:
        valid, invalid_reason = False, infrastructure_failure or "scan produced no report (exit %s)" % exit_code
    elif report_payload.get("schema_version") is None:
        valid, invalid_reason = False, "report has no schema_version; not a scanner report"
    # BH-05: an environment that cannot support the suite invalidates the measurement, it does not
    # delete the attempt. The record and its bytes stay in the store so the refusal is auditable.
    refusal = preflight_refusal(preflight_summary(environment), args.suite)
    if refusal:
        valid, invalid_reason = False, "; ".join([reason for reason in (invalid_reason, refusal) if reason])
    artifacts = {}
    if report_bytes:
        artifacts["report.json"] = report_bytes
    for key, path in collect_artifacts(stage).items():
        artifacts[key] = path
    if environment is not None:
        artifacts["logs/preflight.json"] = json.dumps(environment, indent=2, sort_keys=True).encode("utf-8")
    if stdout:
        artifacts["logs/scanner-stdout.txt"] = stdout.encode("utf-8")
    if stderr:
        artifacts["logs/scanner-stderr.txt"] = stderr.encode("utf-8")
    timings["ended_at"] = now_iso()
    identity = (payload.get("identity.txt") or "").strip()
    scanner_binary = find_binary(LINUX_BINARIES) if live else argv[0]
    record = build_record(case, host, args.suite, args.seed, args.order_index, args.order_pattern,
                          tool_identity(scanner_binary), kb_identity(max_age),
                          runtime_identity(case["runtime"]["name"], release,
                                            ROOT / RUNSC if live else None,
                                            (args.runsc_platform or case["runtime"]["platform"]) if live else None),
                          environment_block(host, "linux:%s/bench-work" % LIVE_WORK_BASE if live else "repo:bench/.tmp",
                                            environment),
                          report_payload, timings, valid, invalid_reason,
                          "harness %s; %s scan; exit=%s; max_kb_age_days=%d; order=%s; report_status=%s%s" % (
                              BENCH_VERSION, "live" if live else "static-only", exit_code, max_age,
                              args.order_pattern or "single",
                              (report_payload or {}).get("status", "absent"),
                              "; executed as %s" % identity if identity else ""), run_id=args.run_id)
    directory = store.put(record, artifacts)
    shutil.rmtree(str(stage), ignore_errors=True)
    print("run %s -> %s (%s)" % (record["run_id"], rel_path(directory),
                                 "valid" if valid else "INVALID: %s" % invalid_reason))
    return 0 if valid else 1

