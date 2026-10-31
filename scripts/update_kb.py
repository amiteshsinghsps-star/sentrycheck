"""Build an auditable KB from gVisor's syscall tables at an immutable release commit.

Python standard library only. Unknown source formats fail closed; no live table is
silently assigned to a historical version. The output is validated again by Rust.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import urllib.request

BASE = "https://api.github.com/repos/google/gvisor"
# Constructor semantics are as important as the table's call sites. Review a
# changed upstream implementation before assigning its support level or errno
# behavior to a release. This hash is from release-20260921.0 at 26f3455a4cb9.
REVIEWED_CONSTRUCTOR_HASHES = {
    "abd165f016b9d026b06425ddb8f78224a3b351a617f17b9a7e2f481a6b49915d",
}

def download(url):
    request = urllib.request.Request(url, headers={"User-Agent": "sentrycheck-kb/0.1"})
    with urllib.request.urlopen(request, timeout=45) as response:
        data = response.read(4 * 1024 * 1024 + 1)
    if len(data) > 4 * 1024 * 1024:
        raise ValueError("source exceeds size budget")
    return data

def release_commit(version):
    obj = json.loads(download(BASE + "/git/ref/tags/release-" + version))["object"]
    for _ in range(4):
        if obj["type"] == "commit":
            return obj["sha"]
        if obj["type"] != "tag":
            break
        obj = json.loads(download(BASE + "/git/tags/" + obj["sha"]))["object"]
    raise ValueError("could not resolve release tag to a commit")

def build(version, commit, source, prose, now, constructors):
    if not re.fullmatch(r"\d{8}\.\d+", version) or not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise ValueError("invalid release or commit")
    constructor_hash = hashlib.sha256(constructors).hexdigest()
    if constructor_hash not in REVIEWED_CONSTRUCTOR_HASHES:
        raise ValueError("syscall constructor source changed; review support and CapError semantics before updating the KB")
    text = source.decode("utf-8")
    revision_url = "https://github.com/google/gvisor/blob/" + commit + "/pkg/sentry/syscalls/linux/linux64.go"
    citation = {"title": "gVisor release-" + version + " syscall table", "url": revision_url,
                "source_revision": commit, "retrieved_at": now}
    entries = []
    support = []
    architecture = None
    seen = set()
    for line_number, line in enumerate(text.splitlines(), 1):
        if line.startswith("var AMD64 ="):
            architecture = "amd64"
        elif line.startswith("var ARM64 ="):
            architecture = "arm64"
        match = re.match(r'\s*(\d+):\s*syscalls\.(\w+)\("(\w+)"(.*)', line)
        if not match or architecture is None:
            if architecture is not None and re.match(r"\s*\d+\s*:", line):
                raise ValueError("unrecognized syscall table row at line " + str(line_number))
            continue
        number, factory, syscall, rest = match.groups()
        if (architecture, number) in seen:
            raise ValueError("duplicate syscall in source")
        seen.add((architecture, number))
        if factory in ("Supported", "SupportedPoint"):
            status = "full"
        elif factory in ("PartiallySupported", "PartiallySupportedPoint"):
            status = "partial"
        elif factory in ("Error", "ErrorWithEvent", "CapError"):
            status = "unimplemented"
        else:
            raise ValueError("unrecognized syscall constructor " + factory)
        quoted = re.findall(r'"((?:\\.|[^"\\])*)"', rest)
        detail = next((q for q in quoted if q and not q.startswith("gvisor.dev/")), "")
        errno = re.search(r"linuxerr\.(\w+)", rest)
        if factory == "CapError":
            capability = re.search(r"linux\.(CAP_[A-Z0-9_]+)", rest)
            if capability is None:
                raise ValueError("CapError capability argument requires review")
            detail = (detail + " " if detail else "") + "Unimplemented: returns EPERM without " + capability.group(1) + "; returns ENOSYS with that capability. Granting the capability does not enable an implementation."
        elif status == "full":
            detail = "Fully Supported."
        elif not detail:
            if errno:
                detail = "Returns " + errno.group(1) + "."
            else:
                raise ValueError("missing support note or error for " + syscall)
        support.append({"architecture": architecture, "number": int(number), "syscall": syscall,
                        "status": status, "detail": detail, "source_line": line_number})
        if status == "full":
            continue
        category = "io_uring" if syscall.startswith("io_uring") else "ebpf" if syscall == "bpf" else "syscall"
        entries.append({"id": "gap-gvisor-" + architecture + "-" + syscall.replace("_", "-"),
                        "runtime": "gvisor", "runtime_versions": [version], "architectures": [architecture],
                        "category": category, "status": status,
                        "description": syscall + ": " + detail + " Arguments and runtime configuration matter; a reference alone is not an incompatibility.",
                        "syscalls": [syscall], "syscall_numbers": [int(number)],
                        "subsystems": [category] if category in ("io_uring", "ebpf") else [],
                        "severity_class": "silent-degradation" if syscall == "bpf" else "hard-failure",
                        "first_observed": now[:10], "last_verified": now[:10],
                        "citation": dict(citation, url=revision_url + "#L" + str(line_number)),
                        "applicability": "release-pinned"})
    if len(support) < 600 or set(s["architecture"] for s in support) != {"amd64", "arm64"}:
        raise ValueError("unexpected gVisor source layout: incomplete architecture tables")
    prose_text = prose.decode("utf-8")
    normalized_prose = " ".join(prose_text.split())
    if "resource *accounting*, resource *limits* are not enforced within the sandbox." not in normalized_prose:
        raise ValueError("cgroup caveat must be reviewed: source text changed")
    docs_citation = {"title": "gVisor release-" + version + " application compatibility", "url": "https://github.com/google/gvisor/blob/" + commit + "/g3doc/user_guide/compatibility.md",
                     "source_revision": commit, "retrieved_at": now}
    entries.append({"id": "gap-gvisor-cgroup-limits", "runtime": "gvisor", "runtime_versions": [version],
                    "architectures": ["amd64", "arm64"], "category": "cgroup", "status": "behavioral-divergence",
                    "description": "In-sandbox cgroup accounting does not imply enforcement of limits between processes in the same sandbox. Host cgroups can still limit the sandbox as a whole.",
                    "syscalls": [], "syscall_numbers": [], "subsystems": ["cgroup"],
                    "severity_class": "silent-degradation", "first_observed": now[:10], "last_verified": now[:10],
                    "citation": docs_citation, "applicability": "release-pinned"})
    # These entries describe observed differences, not pre-existing release-wide defects.
    generic = [
        ("gap-observed-workload-failure", "unresolved", "hard-failure", "Native workload succeeds and sandbox workload fails under the same profile. This establishes an observed failure, not its root cause.", "https://gvisor.dev/docs/user_guide/compatibility/"),
        ("gap-observed-output-divergence", "behavioral-divergence", "silent-degradation", "Declared deterministic output assertions differ between native and sandbox execution. Undeclared state and resource semantics are not compared.", "https://gvisor.dev/docs/user_guide/compatibility/"),
        ("gap-observed-filesystem-divergence", "filesystem", "hard-failure", "A sandbox-only ENOENT/ENOTDIR/ELOOP error accompanies workload failure. Gofer attribution requires further investigation.", "https://gvisor.dev/docs/user_guide/filesystem/"),
        ("gap-observed-performance-regression", "performance", "performance-regression", "Repeated elapsed-time samples exceed the profile threshold. These timings include startup and tracing overhead; netstack attribution is not established.", "https://gvisor.dev/docs/architecture_guide/performance/"),
        ("gap-runtime-isolation-mismatch", "runtime-isolation", "silent-degradation", "Requested isolation differs from verified runtime health or observed sandbox state. Standard Kubernetes reports unsupported runtime handlers as failures; it does not specify a silent fallback to runc.", "https://kubernetes.io/docs/concepts/containers/runtime-class/"),
    ]
    for identifier, category, severity, description, url in generic:
        entries.append({"id": identifier, "runtime": "any", "runtime_versions": [], "architectures": [],
                        "category": category, "status": "observational", "description": description,
                        "syscalls": [], "syscall_numbers": [], "subsystems": [], "severity_class": severity,
                        "first_observed": now[:10], "last_verified": now[:10], "applicability": "observational",
                        "citation": {"title": "Observation interpretation and scope", "url": url, "source_revision": None, "retrieved_at": now}})
    return {"schema_version": "1.0", "snapshot_version": now[:10] + "/gvisor-" + version,
            "created_at": now, "created_at_unix": int(datetime.fromisoformat(now.replace("Z", "+00:00")).timestamp()),
            "runtime_releases": {"gvisor": [version], "kata": []}, "source_commit": commit,
            "source_hashes": {"linux64.go": hashlib.sha256(source).hexdigest(), "compatibility.md": hashlib.sha256(prose).hexdigest(), "syscalls.go": constructor_hash},
            "syscall_support": support, "entries": entries, "runtime_fallback_rules": [],
            "notes": ["No unbounded release ranges are inferred.", "No version-specific library fallback rules have yet been verified.",
                      "Kata has observational comparison support only; no release support matrix.",
                      "The PRD's unnamed post-mortem and issue are not used as evidence.",
                      "Constructor support and CapError errno semantics were reviewed at https://github.com/google/gvisor/blob/" + commit + "/pkg/sentry/syscalls/syscalls.go; a changed source hash requires review."]}

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version")
    parser.add_argument("--out", type=Path, default=Path("kb/snapshot.json"))
    parser.add_argument("--offline-source", type=Path)
    parser.add_argument("--offline-constructors", type=Path, help="Pinned syscalls.go source; defaults to release-syscalls.txt in --offline-source")
    parser.add_argument("--commit")
    args = parser.parse_args()
    version = args.version
    if not version:
        version = json.loads(download(BASE + "/releases/latest"))["tag_name"].removeprefix("release-")
    if not re.fullmatch(r"\d{8}\.\d+", version):
        raise ValueError("expected gVisor version YYYYMMDD.N")
    if args.offline_source:
        commit = args.commit
        source = (args.offline_source / "release-amd64.txt").read_bytes()
        prose = (args.offline_source / "release-compatibility.txt").read_bytes()
        constructors = (args.offline_constructors or args.offline_source / "release-syscalls.txt").read_bytes()
    else:
        commit = release_commit(version)
        root = "https://raw.githubusercontent.com/google/gvisor/" + commit
        source = download(root + "/pkg/sentry/syscalls/linux/linux64.go")
        prose = download(root + "/g3doc/user_guide/compatibility.md")
        constructors = download(root + "/pkg/sentry/syscalls/syscalls.go")
    snapshot = build(version, commit, source, prose, datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"), constructors)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    temporary = args.out.with_suffix(".tmp")
    temporary.write_text(json.dumps(snapshot, indent=2, ensure_ascii=False) + "\n", encoding="utf-8", newline="\n")
    temporary.replace(args.out)
    print("Wrote", args.out, "with", len(snapshot["entries"]), "cited entries at", commit)

if __name__ == "__main__":
    main()
