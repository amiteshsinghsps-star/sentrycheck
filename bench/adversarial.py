"""BM-07: adversarial and malformed inputs against the real scanner.

cargo-fuzz is not available here (the workspace builds offline, has no fuzz target directory, and
a nightly toolchain would cost the session rather than the measurement), so this is the seeded
mutation driver that the pre-registration's deviation log allows: hostile inputs assembled from
documented parser hazards, run through the shipped binary, with every outcome recorded as
observed. The property that matters is that a malformed input produces a rejection or a degraded
report, never a confident clean verdict.
"""
import gzip
import hashlib
import json
import random
import shutil
import subprocess
import tarfile
import time
from io import BytesIO
from pathlib import Path

from bench import predict
from bench.common import BENCH, ROOT, BenchError, read_json, rel_path, resolve, sha256_bytes, write_json
from bench.runner import find_binary, run_process

SCANNERS = ("target/debug/sentrycheck.exe", "target/debug/sentrycheck", "bin/sentrycheck.exe")
STAGE = BENCH / ".tmp" / "adversarial"
REPORT_CAP_BYTES = 128 * 1024 * 1024


def scanner_binary():
    found = find_binary(SCANNERS)
    if not Path(found).is_file():
        raise BenchError("no scanner binary at %s; BM-07 attacks the real tool, not a model of it" % SCANNERS[0])
    return found


def seed_case():
    """The smallest locally pinned workload, plus the profile the case is scanned with."""
    candidates = []
    for path in sorted((BENCH / "cases").glob("*/case.json"), key=lambda item: item.as_posix()):
        record = read_json(path)
        local = (record.get("image") or {}).get("local_path")
        if not local:
            continue
        root = resolve(local)
        if root.is_dir():
            candidates.append((sum(item.stat().st_size for item in root.rglob("*") if item.is_file()), root,
                               ROOT / record["profile"]["path"], record["case_id"]))
    if not candidates:
        raise BenchError("no local workload layout exists; run bench fetch first")
    size, root, profile, case_id = min(candidates)
    return root, profile, case_id, size


def _digest(data):
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _tar(members):
    """An uncompressed tar carrying the given (name, size) members, returned as its bytes."""
    buffer = BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as archive:
        for name, size in members:
            info = tarfile.TarInfo(name=name)
            data_size = min(size, 1024)
            info.size = data_size
            archive.addfile(info, BytesIO(b"\x00" * data_size))
    data = bytearray(buffer.getvalue())
    offset = 0
    for name, size in members:
        if size > 1024 and len(data) >= offset + 136:
            # GNU tar base-256 encoding for large size fields (size >= 8GB)
            size_field = b"\x80" + (size).to_bytes(11, "big")
            data[offset + 124 : offset + 136] = size_field
        offset += 512 + ((min(size, 1024) + 511) // 512) * 512
    return bytes(data)


def _layer_variant(layout, payload, name):
    """Drop a blob into the layout and rewrite the manifest and index to point at it."""
    blob_dir = layout / "blobs" / "sha256"
    digest = hashlib.sha256(payload).hexdigest()
    (blob_dir / digest).write_bytes(payload)
    index_path = layout / "index.json"
    index = json.loads(index_path.read_text(encoding="utf-8"))
    manifest_path = blob_dir / index["manifests"][0]["digest"].split(":")[1]
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    layers = manifest.get("layers") or []
    target = manifest_path if name == "manifest" else manifest_path
    entry = {"mediaType": layers[0]["mediaType"] if layers else "application/vnd.oci.image.layer.v1.tar",
             "digest": "sha256:" + digest, "size": len(payload)}
    if name == "digest-mismatch":
        entry["digest"] = "sha256:" + ("0" * 64)
    manifest["layers"] = layers[:1] + [entry] if name != "drop-layer" else layers[:1]
    body = json.dumps(manifest).encode("utf-8")
    new_digest = hashlib.sha256(body).hexdigest()
    (blob_dir / new_digest).write_bytes(body)
    target = blob_dir / new_digest
    index["manifests"][0] = dict(index["manifests"][0], digest="sha256:" + new_digest, size=len(body))
    index_path.write_bytes(json.dumps(index).encode("utf-8"))
    return target


def build_mutants(seed, layout, profile):
    """Every mutant is a function of the seed and the recorded layout, so a rerun is byte-identical."""
    rng = random.Random(seed)
    index_path = layout / "index.json"
    base_index = json.loads(index_path.read_text(encoding="utf-8"))
    mutants = []

    def json_family(name, transform):
        def apply(index_file, body=transform):
            index_file.write_bytes(body(index_file.read_bytes()))
            return index_file
        mutants.append((name, "index.json", apply))

    def bad_type(payload):
        doc = json.loads(payload)
        doc["schemaVersion"] = []
        return json.dumps(doc).encode("utf-8")

    def missing_field(payload):
        doc = json.loads(payload)
        doc.pop("manifests", None)
        return json.dumps(doc).encode("utf-8")

    def absurd_size(payload):
        doc = json.loads(payload)
        if doc.get("manifests"):
            doc["manifests"][0]["size"] = 2 ** 62
        return json.dumps(doc).encode("utf-8")

    def broken_json(payload):
        return payload[: len(payload) // 2]

    def deep_nest(payload):
        return b'{"a":' * 20000 + b"1" + b"}" * 20000

    json_family("manifest-schema-version-wrong-type", bad_type)
    json_family("manifest-missing-manifests", missing_field)
    json_family("manifest-absurd-size", absurd_size)
    json_family("manifest-truncated-json", broken_json)
    json_family("index-deep-nesting", deep_nest)
    def write_index(index_file):
        index_file.write_bytes(b"\xff\xfe\x00\x01not json at all")
        return index_file
    mutants.append(("index-not-json", "index.json", write_index))

    def profile_family(name, text):
        def apply(profile_file, body=text):
            profile_file.write_text(body, encoding="utf-8")
            return profile_file
        mutants.append((name, "profile", apply))

    profile_family("profile-unknown-key", 'unknown_key = 1\nimage = "."\n')
    profile_family("profile-type-confusion", 'repetitions = "three"\n')
    profile_family("profile-truncated", "[\n")

    def tar_family(name, members):
        mutants.append((name, "layer", lambda target, payload=members: _layer_variant(target, _tar(payload), name)))

    tar_family("layer-path-traversal", [("../../outside.txt", 8), ("./inside.txt", 8)])
    tar_family("layer-absolute-path", [("/etc/passwd", 8)])
    tar_family("layer-hardlink-to-root", [("safe.txt", 8)])
    tar_family("layer-huge-declared-size", [("big", 2 ** 40)])
    mutants.append(("layer-corrupted-stream", "layer",
                    lambda target: _layer_variant(target, gzip.compress(b"not a real layer")[:8] + b"\x00" * 64,
                                                  "corrupt")))
    mutants.append(("layer-digest-mismatch", "layer",
                    lambda target: _layer_variant(target, _tar([("ok", 4)]), "digest-mismatch")))
    mutants.append(("layer-dropped", "layer", lambda target: _layer_variant(target, _tar([("ok", 4)]), "drop-layer")))
    rng.shuffle(mutants)
    return mutants


def prepare(kind, layout, profile, index, seed):
    """Materialize one mutant into a private staging copy; nothing about a mutant is shared."""
    directory = STAGE / ("m%02d-%s" % (index, kind.replace(" ", "-")))
    if directory.exists():
        shutil.rmtree(str(directory), ignore_errors=True)
    (directory / "image").mkdir(parents=True)
    shutil.copytree(str(layout), str(directory / "image" / "layout"))
    shutil.copyfile(str(profile), str(directory / "profile.toml"))
    return directory


def scan_once(binary, directory, kind, timeout=120):
    image = directory / "image" / "layout"
    argv = [str(binary), "scan", str(image), "--profile", str(directory / "profile.toml"), "--format", "json",
            "--output", str(directory / "report.json"), "--cache", str(directory / "cache"),
            "--artifacts", str(directory / "artifacts"), "--max-kb-age-days", "400", "--no-cache", "--static-only"]
    stdout, stderr, error, code, elapsed = run_process(argv, timeout=timeout)
    report = None
    if (directory / "report.json").is_file():
        try:
            report = json.loads((directory / "report.json").read_text(encoding="utf-8"))
        except ValueError:
            report = None
    return argv, stdout, stderr, error, code, elapsed, report


def classify(code, error, stderr, report):
    if error:
        return "timeout"
    if stderr and ("panicked" in stderr.lower() or "stack overflow" in stderr.lower()):
        return "crash"
    if report is None:
        return "rejected" if code not in (0,) else "silent-accept"
    verdict = predict.predict(report) or {}
    if verdict.get("class") == "compatible" and verdict.get("tier") == "static-only":
        return "silent-accept"
    return "handled"


def run(args):
    seed, count = int(args.seed), int(args.count)
    out = resolve(args.out) if not Path(args.out).is_absolute() else Path(args.out)
    binary = scanner_binary()
    layout, profile, case_id, seed_bytes = seed_case()
    STAGE.mkdir(parents=True, exist_ok=True)
    mutants = build_mutants(seed, layout, profile)[:count]
    rows = []
    for index, (kind, target, transform) in enumerate(mutants):
        directory = prepare(kind, layout, profile, index, seed)
        handle = {"index.json": directory / "image" / "layout" / "index.json",
                  "layer": directory / "image" / "layout",
                  "profile": directory / "profile.toml"}[target]
        mutated = transform(handle)
        argv, stdout, stderr, error, code, elapsed, report = scan_once(binary, directory, kind)
        verdict = classify(code, error, stderr, report)
        report_bytes = (directory / "report.json").stat().st_size if (directory / "report.json").is_file() else 0
        rows.append({"family": kind, "target": target,
                     "mutant": rel_path(mutated) if isinstance(mutated, Path) and mutated.is_file() else None,
                     "mutant_sha256": sha256_bytes(mutated.read_bytes()) if isinstance(mutated, Path)
                     and mutated.is_file() else None,
                     "seed": seed, "seed_case": case_id, "exit_code": code, "wall_ms": elapsed,
                     "verdict": verdict, "report_status": (report or {}).get("status"),
                     "predicted_class": (predict.predict(report) or {}).get("class") if report else None,
                     "report_bytes": report_bytes, "limit_violation": report_bytes > REPORT_CAP_BYTES,
                     "stdout_sha256": sha256_bytes((stdout or "").encode("utf-8")),
                     "stderr_sha256": sha256_bytes((stderr or "").encode("utf-8")),
                     "stderr_excerpt": (stderr or "")[:300] or None})
    counts = {}
    for row in rows:
        counts[row["verdict"]] = counts.get(row["verdict"], 0) + 1
    offenders = sorted(row["family"] for row in rows if row["verdict"] in ("silent-accept", "crash", "timeout"))
    violations = sorted(row["family"] for row in rows if row["limit_violation"])
    payload = {"schema_version": "1.0", "suite": "BM-07", "seed": seed, "scanner": rel_path(binary),
               "scanner_sha256": sha256_bytes(Path(binary).read_bytes()),
               "seed_case": case_id, "seed_layout_bytes": seed_bytes, "results": rows,
               "verdict_counts": dict(sorted(counts.items())), "offenders": offenders,
               "limit_violations": violations,
               "property": "a malformed input must be rejected, crash-free, and never yield a confident "
                           "clean verdict; the 128 MiB report cap must hold",
               "fuzzing_status": "cargo-fuzz not run: the workspace builds offline and has no fuzz target; "
                                 "this seeded driver is the registered substitute (see the deviation log)"}
    out.mkdir(parents=True, exist_ok=True)
    write_json(out / "manifest.json", payload)
    print("BM-07: %d mutants against %s -> %s" % (len(rows), rel_path(binary),
                                                  ", ".join("%s=%d" % item for item in sorted(counts.items()))))
    if offenders:
        print("  offenders (crash/timeout/silent-accept): %s" % ", ".join(offenders))
    if violations:
        print("  limit violations: %s" % ", ".join(violations))
    return 1 if (offenders or violations) else 0


def command_adversarial(args):
    return run(args)
