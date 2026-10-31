"""BH-03 host profiler: record the environment a measurement was taken in.

PRD section 4.1 lists the factors that must be recorded. Anything this host does not
expose is stored as null with the reason in notes, never guessed: a fabricated
"governor=performance" is worse than an honest absence, because reviewers price
environmental control into every timing claim.
"""
import glob
import os
from pathlib import Path
import platform
import shutil
import socket
import subprocess
import time

from bench.common import BENCH, ROOT, now_iso, quantize, sha256_bytes, sha256_file, write_json

DEFAULT_TOOLS = ("sentrycheck", "runc", "runsc", "strace", "docker", "gcc", "go", "python3")

# Tools the repo pins locally are not on PATH; finding them by checksum is the whole point of
# BH-05 preflight, so look in the known locations before declaring a tool absent.
CANDIDATES = {
    "sentrycheck": ["bin/sentrycheck-linux", "bin/sentrycheck", "target/debug/sentrycheck", "target/debug/sentrycheck.exe",
                    "target/release/sentrycheck", "target/release/sentrycheck.exe"],
    "runsc": [".cache/linux/bin/runsc"],
    "containerd-shim-runsc-v1": [".cache/linux/bin/containerd-shim-runsc-v1"],
}


def _first_line(text):
    for line in (text or "").splitlines():
        if line.strip():
            return line.strip()[:200]
    return None


def tool_identity(name, explicit=None):
    """Path, content digest and version string for a tool, or nulls if it is absent."""
    candidates = []
    if explicit:
        candidates.append(explicit)
    elif name == "sentrycheck" and os.environ.get("SENTRYCHECK_BIN"):
        candidates.append(os.environ["SENTRYCHECK_BIN"])
    path = next((c for c in candidates if c and Path(c).is_file()), None) or shutil.which(name)
    if not path:
        for relative in CANDIDATES.get(name, []):
            if os.name == "nt" and relative.endswith("-linux"):
                continue
            if os.name != "nt" and relative.endswith(".exe"):
                continue
            candidate = ROOT / relative
            if candidate.is_file():
                path = str(candidate)
                break
    entry = {"name": name, "path": path, "sha256": None, "version": None}
    if not path:
        return entry
    target = Path(path)
    if not target.is_file():
        return entry
    try:
        entry["sha256"] = sha256_file(target)
    except OSError:
        return entry
    try:
        result = subprocess.run([path, "--version"], capture_output=True, text=True, timeout=20,
                                encoding="utf-8", errors="replace")
        entry["version"] = _first_line(result.stdout or result.stderr)
    except (OSError, subprocess.SubprocessError):
        entry["version"] = None
    return entry


def _read(path):
    try:
        return Path(path).read_text(encoding="utf-8", errors="replace").strip()
    except OSError:
        return None


def _systat(path):
    """Return the raw string if readable, else None; no defaults."""
    return _read(path)


def _clock():
    """Wall clock plus NTP state where observable; synced stays null when it is not."""
    synced = None
    if shutil.which("timedatectl"):
        try:
            result = subprocess.run(["timedatectl", "show", "-p", "NTPSynchronized", "--value"],
                                    capture_output=True, text=True, timeout=10, encoding="utf-8")
            if result.returncode == 0:
                synced = result.stdout.strip().lower() == "yes"
        except (OSError, subprocess.SubprocessError):
            synced = None
    return {"timezone": time.tzname[0], "synced": synced, "unix_now": int(time.time())}


def collect(host_id=None, tools=None, work_root=None):
    system = platform.system()
    notes = []
    clock = _clock()
    governor = smt = topology = numa = thp = None
    machine_id = None
    load = {"one": None, "five": None, "fifteen": None}
    is_wsl = None
    nested_kvm = None
    cpu_model = None
    threads_per_core = None
    total_mb = None
    filesystem = None
    device = None
    work_root = str(work_root or BENCH)

    if system == "Linux":
        proc = Path("/proc/cpuinfo").read_text(encoding="utf-8", errors="replace") if Path("/proc/cpuinfo").exists() else ""
        for line in proc.splitlines():
            if line.startswith("model name"):
                cpu_model = line.split(":", 1)[1].strip()
                break
        machine_id = _read("/etc/machine-id") or _read("/var/lib/dbus/machine-id")
        release = _read("/proc/sys/kernel/osrelease") or ""
        is_wsl = "microsoft" in release.lower()
        nested_kvm = Path("/dev/kvm").exists()
        siblings = sorted({s for s in (_systat(p) for p in glob.glob("/sys/devices/system/cpu/cpu*/topology/thread_siblings_list")) if s})
        if siblings:
            topology = ";".join(siblings)[:400]
            smt = "smt" if any("," in s or "-" in s for s in siblings) else "single-thread"
        else:
            notes.append("thread_siblings_list absent: SMT state unknown on this host")
        governors = sorted({g for g in (_systat(p) for p in glob.glob("/sys/devices/system/cpu/cpu*/cpufreq/scaling_governor")) if g})
        governor = governors[0] if len(governors) == 1 else (governors[0] if governors else None)
        if not governors:
            notes.append("cpufreq sysfs absent: CPU frequency governor not controllable/observable (typical under WSL2 or a cloud VM)")
        elif len(governors) > 1:
            notes.append("per-core governors differ (%s); recorded the first only" % ",".join(governors))
        nodes = glob.glob("/sys/devices/system/node/node*")
        numa = str(len(nodes)) if nodes else "1"
        thp = _systat("/sys/kernel/mm/transparent_hugepage/enabled")
        try:
            one, five, fifteen = os.getloadavg()
            load = {"one": quantize(one, 3), "five": quantize(five, 3), "fifteen": quantize(fifteen, 3)}
        except OSError:
            notes.append("load average unavailable")
        try:
            total_mb = int(_read("/proc/meminfo").split("kB")[0].split(":")[1]) // 1024
        except (AttributeError, ValueError, IndexError):
            notes.append("meminfo unreadable")
        stat = os.statvfs(work_root)
        free_mb = int(stat.f_bavail * stat.f_frsize / 1048576)
        try:
            with open("/proc/self/mountinfo", encoding="utf-8", errors="replace") as handle:
                best = ""
                for line in handle:
                    parts = line.rstrip("\n").split(" - ")
                    if len(parts) != 2:
                        continue
                    left, right = parts[0].split(), parts[1].split()
                    if len(left) < 6 or len(right) < 2:
                        continue
                    target, fstype, source = left[4], right[0], right[1]
                    # "/" is a prefix of every path already; appending another slash would never match.
                    covered = work_root == target or (target != "/" and work_root.startswith(target + "/")) \
                        or (target == "/" and work_root.startswith("/"))
                    if covered and len(target) > len(best):
                        best, filesystem, device = target, fstype, source
        except OSError:
            notes.append("mountinfo unreadable: filesystem layering unknown")
    elif system == "Windows":
        notes.append("Windows host: /sys and /proc controls do not exist; timing suites must be run against a Linux host record")
        load = {"one": None, "five": None, "fifteen": None}
        free_mb = int(shutil.disk_usage(work_root).free / 1048576)
        total_mb = None
        notes.append("total memory not readable without a platform call; recorded as null")
    else:
        free_mb = int(shutil.disk_usage(work_root).free / 1048576)
        total_mb = None

    cores = os.cpu_count()
    uname = platform.uname()
    derived = "|".join([machine_id or socket.gethostname(), system, uname.machine, str(cpu_model), str(cores)])
    stable = "h" + sha256_bytes(derived.encode("utf-8")).split(":")[1][:12]
    record = {
        "schema_version": "1.0",
        "host_id": host_id or stable,
        "recorded_at": now_iso(),
        "platform": system,
        "os_release": (uname.release if system != "Linux" else (_read("/etc/os-release") or "").split("\n")[0].strip('NAME="') or uname.release)[:200],
        "kernel": "%s %s" % (uname.system, uname.version[:120]),
        "architecture": uname.machine,
        "cpu": {
            "model": cpu_model,
            "cores": cores,
            "threads_per_core": threads_per_core,
            "governor": governor,
            "smt": smt,
            "turbo": None,
            "pinning": None,
        },
        "memory": {"total_mb": total_mb, "swap": None, "transparent_hugepage": thp},
        "numa": numa,
        "storage": {"work_root": work_root, "filesystem": filesystem, "free_mb": free_mb, "device": device},
        "network": None,
        "clock": clock,
        "load_average": load,
        "virtualization": {"is_wsl": is_wsl, "nested_kvm": nested_kvm, "provider": None},
        "tools": [tool_identity(name) for name in (tools or DEFAULT_TOOLS)],
        "host_load_controlled": False,
        "notes": " ".join(notes + (["topology=%s" % topology] if topology else [])),
    }
    return record


def save(record, out):
    write_json(out, record)
    return Path(out)


def command_hostinfo(args):
    from bench import schemas
    record = collect(host_id=args.host_id, tools=args.tools, work_root=args.work_root)
    schemas.check("host", record, record["host_id"])
    path = save(record, args.out)
    print("hostinfo %s -> %s" % (record["host_id"], path))
    absent = [key for key, value in (("governor", record["cpu"]["governor"]), ("smt", record["cpu"]["smt"]),
                                     ("load", record["load_average"]["one"]), ("filesystem", record["storage"]["filesystem"]),
                                     ("clock_synced", record["clock"]["synced"])) if value is None]
    if absent:
        print("unobservable controls (recorded null, not guessed): %s" % ", ".join(absent))
    missing = [t["name"] for t in record["tools"] if not t["sha256"]]
    if missing:
        print("tools absent: %s" % ", ".join(missing))
    return 0
