"""Case registry (PRD v2 section 6.3) built only from artifacts that exist on this host.

A case record is a claim about reproducible input, so every digest here is read back from
disk. A case whose workload image has not been built is reported as blocked and never
written: an empty registry entry would silently become an empty benchmark cell later.
"""
from pathlib import Path

from bench.common import BENCH, ROOT, BenchError, read_json, rel_path, sha256_file, write_json
from bench import schemas

ADDED_IN = "bench-0.1"

# case_id -> registry seed. `layout`/`reference` say where the input actually lives;
# suites/host_classes/expected_interfaces are the PRD section 6.3 planning fields.
REGISTRY = {
    "synthetic-baseline": dict(
        license="Apache-2.0 (workload source authored in this repository; statically linked C)",
        group="synthetic", layout="artifacts/live-images/fixtures/baseline",
        profile="profiles/synthetic.toml", suites=["BM-01", "BM-04", "BM-13", "BM-14"],
        host_classes=["wsl2-ext4", "linux-bare"], expected_interfaces=["read", "write", "exit_group"],
        tags=["baseline", "deterministic", "positive-control"], split="development",
        notes="Deterministic fixture expected to be compatible in both runtimes; the control case."),
    "synthetic-required-io-uring": dict(
        license="Apache-2.0 (workload source authored in this repository; statically linked C)",
        group="synthetic", layout="artifacts/live-images/io_uring",
        profile="profiles/synthetic.toml", suites=["BM-01", "BM-02", "BM-04", "BM-14"],
        host_classes=["wsl2-ext4", "linux-bare"], expected_interfaces=["io_uring_setup", "io_uring_enter"],
        tags=["io_uring", "required", "negative-control"], split="validation",
        notes="Requires io_uring; gVisor denies it, so the sandbox must fail rather than degrade silently."),
    "synthetic-optional-io-uring": dict(
        license="Apache-2.0 (workload source authored in this repository; statically linked C)",
        group="synthetic", layout="artifacts/live-images/io_uring_fallback",
        profile="profiles/synthetic.toml", suites=["BM-01", "BM-04", "BM-14"],
        host_classes=["wsl2-ext4", "linux-bare"], expected_interfaces=["io_uring_setup", "pwrite64"],
        tags=["io_uring", "fallback"], split="validation",
        notes="Attempts io_uring then falls back; tolerated, so a prediction of hard failure here is a false positive."),
    "synthetic-optional-bpf": dict(
        license="Apache-2.0 (workload source authored in this repository; statically linked C)",
        group="synthetic", layout="artifacts/live-images/bpf_optional",
        profile="profiles/synthetic.toml", suites=["BM-01", "BM-04", "BM-14"],
        host_classes=["wsl2-ext4", "linux-bare"], expected_interfaces=["bpf"],
        tags=["ebpf", "optional"], split="validation",
        notes="Optional BPF probe; completion is asserted, unavailability is tolerated."),
    "synthetic-behavior-divergence": dict(
        license="Apache-2.0 (workload source authored in this repository; statically linked C)",
        group="synthetic", layout="artifacts/live-images/behavior",
        profile="profiles/synthetic.toml", suites=["BM-01", "BM-03", "BM-04", "BM-14"],
        host_classes=["wsl2-ext4", "linux-bare"], expected_interfaces=["uname", "getrandom"],
        tags=["output-diff", "silent-degradation"], split="validation",
        notes="Prints a value that differs under the sandbox, so the only usable evidence is a stdout diff."),
    "baseline-go": dict(
        license="Apache-2.0 (workload source in corpus/go; Go runtime is BSD-3-Clause)",
        group="application", layout="artifacts/live-images/go", profile="profiles/go.toml",
        suites=["BM-01", "BM-04", "BM-08", "BM-14"], host_classes=["wsl2-ext4", "linux-bare"],
        expected_interfaces=["futex", "epoll_wait", "openat"], tags=["go", "static-binary", "baseline"],
        split="development", notes="Corpus Go binary: file I/O, hashing and goroutines."),
    "postgres-18-io-uring": dict(
        license="PostgreSQL License (image built from source on this host; not redistributed)",
        group="application", layout="artifacts/live-images/postgres",
        profile="profiles/postgres-io-uring.toml", suites=["BM-01", "BM-04", "BM-08", "BM-14"],
        host_classes=["wsl2-ext4", "linux-bare"],
        expected_interfaces=["io_uring_setup", "io_uring_enter", "epoll_pwait"],
        tags=["postgres", "io_uring", "privileged-user", "large-rootfs"], split="test",
        notes="PostgreSQL 18 built with liburing; io_method=io_uring is mandatory in the profile command."),
    "registry-python": dict(
        license="see bench/datasets/*/license-manifest.json; not redistributed",
        group="registry", reference="docker.io/library/python:3.12-slim", profile="profiles/python.toml",
        suites=["BM-01", "BM-04", "BM-11"], host_classes=["wsl2-ext4", "linux-bare"],
        expected_interfaces=["epoll_create1", "futex", "openat"], tags=["registry", "baseline", "cpython"],
        split="development",
        notes="Public registry image; the amd64 digest must be pinned by bench fetch before scoring."),
    "registry-node": dict(
        license="see bench/datasets/*/license-manifest.json; not redistributed",
        group="registry", reference="docker.io/library/node:22-alpine", profile="profiles/node.toml",
        suites=["BM-01", "BM-04", "BM-11"], host_classes=["wsl2-ext4", "linux-bare"],
        expected_interfaces=["epoll_wait", "getrandom", "openat"], tags=["registry", "baseline", "musl"],
        split="development",
        notes="Alpine/musl baseline; the amd64 digest must be pinned by bench fetch before scoring."),
    "cilium-ebpf-optional": dict(
        group="application", reference=None, profile="profiles/cilium-ebpf.toml",
        license="Apache-2.0 (cilium/ebpf is Apache-2.0; image not built on this host)",
        suites=["BM-01", "BM-04"], host_classes=["linux-bare"], expected_interfaces=["bpf"],
        tags=["ebpf", "go", "needs-build"], split="reserve",
        notes="Workload image is built by scripts/build-v05-lab.sh; no image exists on this host, so the case is blocked."),
}


def _layout_manifest(layout):
    index = layout / "index.json"
    if not index.is_file():
        raise BenchError("OCI layout %s has no index.json" % rel_path(layout))
    descriptors = read_json(index).get("manifests", [])
    if len(descriptors) != 1:
        raise BenchError("expected exactly one manifest in %s, found %d" % (rel_path(layout), len(descriptors)))
    descriptor = descriptors[0]
    digest = descriptor["digest"]
    blob = layout / "blobs" / "sha256" / digest.split(":", 1)[1]
    if not blob.is_file():
        raise BenchError("manifest blob %s is missing from %s" % (digest, rel_path(layout)))
    if sha256_file(blob) != digest:
        raise BenchError("manifest blob digest does not match its own filename in %s" % rel_path(layout))
    manifest = read_json(blob)
    layers = manifest.get("layers", [])
    for layer in layers:
        path = layout / "blobs" / "sha256" / layer["digest"].split(":", 1)[1]
        if not path.is_file():
            raise BenchError("layer %s is not stored in %s" % (layer["digest"], rel_path(layout)))
    return descriptor, manifest, layers


def pin_for(reference):
    """The recorded pin for a registry reference, or None.

    Read from bench/images/pins.json rather than from the registry, so a case never becomes ready or
    blocked again because a mutable tag moved underneath it.
    """
    if not reference:
        return None
    from bench.fetch import load_pins
    return load_pins().get(str(reference))


def case_record(case_id, seed):
    pin = pin_for(seed.get("reference"))
    # `profile` is the execution profile document (the TOML the scanner is given), `image`
    # is the workload; kind/path under profile describe how the workload input is supplied.
    record = {"schema_version": "1.0", "case_id": case_id, "group": seed["group"],
              "image": {"reference": seed.get("reference"), "local_path": seed.get("layout"), "digest": None,
                        "source_url": (pin or {}).get("source_url"),
                        "license": None, "architecture": "amd64", "media_type": None, "layer_digests": []},
              "profile": {"kind": "command", "path": seed["profile"],
                          "sha256": sha256_file(ROOT / seed["profile"]), "coverage_notes": ""},
              "runtime": {"name": "gvisor", "release": "20260921.0", "platform": "systrap", "flags": []},
              "suites": seed["suites"], "host_classes": seed["host_classes"],
              "expected_interfaces": seed["expected_interfaces"], "label": None,
              "split": seed["split"], "tags": seed["tags"], "added_in": ADDED_IN,
              "retired_in": None, "notes": seed["notes"]}
    layout = seed.get("layout") or (pin["layout"] if pin and pin.get("layers_stored") else None)
    if layout:
        directory = ROOT / layout
        if not directory.is_dir():
            return record, "blocked: workload layout %s does not exist on this host" % layout
        descriptor, manifest, layers = _layout_manifest(directory)
        if not layers:
            return record, "blocked: layout %s stores no layers" % layout
        record["profile"].update({"kind": "oci-layout",
                                  "coverage_notes": "workload input is the local OCI layout %s (index %s); "
                                                    "no registry or daemon is contacted" % (layout, rel_path(directory / "index.json"))})
        record["image"].update({"local_path": layout, "digest": descriptor["digest"],
                                "media_type": descriptor.get("mediaType"),
                                "architecture": (descriptor.get("platform") or {}).get("architecture", "amd64"),
                                "layer_digests": [layer["digest"] for layer in layers],
                                "license": seed["license"],
                                "source_url": (pin or {}).get("source_url")})
        return record, None
    if seed.get("reference"):
        record["profile"].update({"kind": "oci-ref",
                                  "coverage_notes": "registry reference; digest is unpinned until bench fetch resolves it"})
        return record, "blocked: registry digest not pinned; run bench fetch %s" % seed["reference"]
    return record, "blocked: no workload image available"


def registry_status():
    rows = []
    for case_id, seed in sorted(REGISTRY.items()):
        _, blocker = case_record(case_id, seed)
        rows.append({"case_id": case_id, "group": seed["group"], "suites": seed["suites"], "blocked": blocker})
    return rows


def write_case(case_id, record):
    directory = BENCH / "cases" / case_id
    write_json(directory / "case.json", record)
    return directory


def load(case_id):
    path = BENCH / "cases" / case_id / "case.json"
    if not path.is_file():
        raise BenchError("case %s is not registered; run bench cases import-corpus" % case_id)
    record = read_json(path)
    schemas.check("case", record, case_id)
    return record


def all_cases(suite=None):
    out = []
    for path in sorted((BENCH / "cases").glob("*/case.json")) if (BENCH / "cases").exists() else []:
        record = read_json(path)
        if suite is None or suite in record.get("suites", []):
            out.append(record)
    return out


def validate_submission(path):
    """BH-13: Validate an external community case submission file."""
    sub_path = Path(path)
    if not sub_path.is_file():
        raise BenchError("submission file not found: %s" % path)
    record = read_json(sub_path)
    case_id = record.get("case_id", "")
    if not case_id or not case_id.replace("-", "").isalnum() or case_id != case_id.lower():
        raise BenchError("case_id must be non-empty lowercase alphanumeric with hyphens, got: %r" % case_id)
    # Check schema
    schemas.check("case", record, case_id)
    # PRD Section 7 & 13 governance rules
    if record.get("split") == "test":
        raise BenchError("community submissions cannot self-assign to the frozen 'test' split; must be 'development' or 'validation'")
    if not record.get("image", {}).get("license") or record["image"]["license"] in ("unknown", ""):
        raise BenchError("image.license is required and must declare an explicit redistribution/use license")
    if not record.get("expected_interfaces"):
        raise BenchError("expected_interfaces must list at least one interface/syscall expected by the case")
    return True


def command_cases(args):
    if args.action == "validate-submission":
        if not getattr(args, "file", None):
            raise BenchError("validate-submission requires --file <submission.json>")
        validate_submission(args.file)
        print("BH-13 submission %s is VALID and conforms to benchmark governance rules." % args.file)
        return 0
    if args.action == "list":
        for row in registry_status():
            print("%-32s %-11s %-2s %s" % (row["case_id"], row["group"], len(row["suites"]),
                                           row["blocked"] or "ready"))
        return 0
    if args.action == "validate":
        paths = sorted((BENCH / "cases").glob("*/case.json"))
        failures = []
        for path in paths:
            record = read_json(path)
            try:
                schemas.check("case", record, record.get("case_id", "?"))
            except BenchError as error:
                failures.append("%s: %s" % (rel_path(path), str(error).splitlines()[0]))
        print("cases=%d invalid=%d" % (len(paths), len(failures)))
        for failure in failures:
            print("  FAIL %s" % failure)
        return 1 if failures else 0
    written, blocked = [], []
    for case_id, seed in sorted(REGISTRY.items()):
        record, blocker = case_record(case_id, seed)
        if blocker:
            blocked.append((case_id, blocker))
            continue
        schemas.check("case", record, case_id)
        write_case(case_id, record)
        written.append(case_id)
    print("imported %d cases from the corpus and retained OCI layouts" % len(written))
    for case_id in written:
        print("  wrote bench/cases/%s/case.json" % case_id)
    for case_id, blocker in blocked:
        print("  blocked %s: %s" % (case_id, blocker))
    return 0
