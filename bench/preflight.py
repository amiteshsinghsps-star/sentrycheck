"""BH-05 preflight: refuse to record a measurement the environment cannot support.

A failed check does not delete the attempt; it marks the run invalid with a reason and the
record stays in the store. Silently dropping invalid runs is how a benchmark ends up
reporting a survivorship sample, and PRD principle 5 requires the incomplete-scan rate to
be visible.
"""
import json
import os
import shutil
from pathlib import Path

from bench.common import BENCH, ROOT, BenchError, read_json, sha256_file

INSTALL_MANIFEST = ROOT / ".cache" / "linux" / "bin" / "install-manifest.json"
DEFAULT_MIN_FREE_MB = 4096
DEFAULT_MAX_LOAD_RATIO = 0.35
# The live driver stages runsc and its sidecar tree; the rest of the release (checkpointgofer,
# metric server, containerd shim) is never executed by a benchmark run, so it is not checked.
RUNTIME_COMPONENTS = ("runsc", "gvisor-bin/gvisor_sentry")


def disk_free_mb(path=BENCH):
    try:
        return int(shutil.disk_usage(path).free / 1048576)
    except OSError:
        return 0


def _load_pins(path):
    if not Path(path).exists():
        return None
    try:
        return read_json(path)
    except (OSError, ValueError) as error:
        raise BenchError("runtime install manifest at %s is unreadable: %s" % (path, error))


def bare_digest(value):
    """Upstream pins are bare hex while the harness hashes to a prefixed form."""
    text = str(value)
    return text.split(":", 1)[1] if text.startswith("sha256:") else text


def check(host_record=None, min_free_mb=DEFAULT_MIN_FREE_MB, max_load_per_core=DEFAULT_MAX_LOAD_RATIO,
          manifest=INSTALL_MANIFEST, work_root=None):
    """Return {"ok": bool, "checks": [{id,status,detail}]} using the PRD 4.1 factors."""
    host_record = host_record or {}
    work_root = str(work_root or (host_record.get("storage") or {}).get("work_root") or BENCH)
    if max_load_per_core is None:
        max_load_per_core = DEFAULT_MAX_LOAD_RATIO
    checks = []

    def add(check_id, ok, detail):
        checks.append({"id": check_id, "status": "pass" if ok else "fail", "detail": detail})

    try:
        free_mb = int(shutil.disk_usage(work_root).free / 1048576)
        add("free-disk", free_mb >= min_free_mb, "%d MiB free at %s, minimum %d MiB" % (free_mb, work_root, min_free_mb))
    except OSError:
        # Not fatal here: the harness may be recording a run for a host it cannot see. The
        # check still fails, so a suite driver on the wrong machine cannot score a run silently.
        add("free-disk", False, "work root %s is not reachable from this machine (host_id=%s); run preflight "
            "on the host that executes the suite" % (work_root, host_record.get("host_id")))

    one = (host_record.get("load_average") or {}).get("one")
    cores = (host_record.get("cpu") or {}).get("cores") or os.cpu_count() or 1
    if one is None:
        add("host-load", False, "load average unobservable on this host; timing suites are invalid here")
    else:
        ratio = one / float(cores)
        add("host-load", ratio <= max_load_per_core, "load1 %.3f across %d cores is %.3f per core, budget %.2f"
            % (one, cores, ratio, max_load_per_core))

    synced = (host_record.get("clock") or {}).get("synced")
    add("clock", synced is not False, "NTP synchronization reported as %s" % ("unknown" if synced is None else ("on" if synced else "off")))

    pins = _load_pins(manifest)
    if pins is None:
        add("runtime-checksums", False, "no pinned runtime manifest at %s" % manifest)
    else:
        # gVisor resolves its sidecar relative to the runsc binary and refuses to create the
        # sandbox under --sidecar-usage-policy STRICT when it is absent, so the live driver stages
        # gvisor-bin beside runsc and both digests have to hold. One check, so a caller sees a
        # single runtime verdict rather than a row per component.
        components = pins.get("components") or {}
        tools = host_record.get("tools") or []
        manifest_dir = Path(str(manifest)).parent
        problems, verified = [], []
        for name, expected in sorted(components.items()):
            if name not in RUNTIME_COMPONENTS:
                continue
            staged = manifest_dir / name
            recorded = next((item for item in tools if item["name"] == name.split("/")[-1]), None) or {}
            digest = sha256_file(staged) if staged.is_file() else recorded.get("sha256")
            if not expected:
                problems.append("%s has no pinned digest" % name)
            elif not digest:
                problems.append("%s is absent (pinned release %s)" % (name, pins.get("version")))
            elif bare_digest(digest) != bare_digest(expected):
                problems.append("%s digest %s does not match pinned %s" % (name, digest[:19], expected[:12]))
            else:
                verified.append("%s %s" % (name, digest[:19]))
        if problems:
            add("runtime-checksums", False, "; ".join(problems))
        else:
            add("runtime-checksums", True, "%s match pinned release %s" % (", ".join(verified), pins.get("version")))

    storage = host_record.get("storage") or {}
    filesystem = storage.get("filesystem")
    # Judge every root the run could stage into: the recorded host path is captured separately from
    # the one the caller is about to use, and a 9p share is unusable either way.
    candidates = [str(path) for path in (work_root, storage.get("work_root")) if path and str(path).startswith("/mnt/")]
    if candidates:
        add("work-root", False, "work root %s is a Windows share mount (9p): symlinks break and it is too slow "
                               "for timing" % ", ".join(dict.fromkeys(candidates)))
    else:
        judged = str(work_root)
        add("work-root", True, "work root %s is on %s" % (judged, filesystem or "local filesystem"))

    failed = sorted(entry["id"] for entry in checks if entry["status"] == "fail")
    # Load and clock observability constrain timing claims only. PRD principle 4 keeps
    # performance apart from compatibility, so a noisy host must not invalidate a correct
    # dynamic-diff observation, and a silent host must not silently become a timing result.
    blocking = {"free-disk", "runtime-checksums", "work-root"}
    timing_blocking = blocking | {"host-load", "clock"}

    def capable(budget):
        return not [entry for entry in checks if entry["id"] in budget and entry["status"] != "pass"]

    return {"ok": not failed, "live_capable": capable(blocking), "timing_capable": capable(timing_blocking),
            "failed": failed, "checks": sorted(checks, key=lambda entry: entry["id"]),
            "min_free_mb": min_free_mb, "max_load_per_core": max_load_per_core}


def command_preflight(args):
    host_record = read_json(args.host) if args.host else None
    result = check(host_record=host_record, min_free_mb=args.min_free_mb, max_load_per_core=args.max_load,
                   work_root=args.work_root)
    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        for entry in result["checks"]:
            print("%-18s %s  %s" % (entry["id"], entry["status"].upper(), entry["detail"]))
        print("preflight: %s (live=%s timing=%s)" % ("ready" if result["ok"] else "NOT ready",
                                                    "yes" if result["live_capable"] else "no",
                                                    "yes" if result["timing_capable"] else "no"))
    return 0 if result["ok"] else 1
