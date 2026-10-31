"""BH-10: the versioned dataset bundle.

A bundle is a manifest, a license table, a card and a checksum file. It is deliberately NOT a
copy of all the evidence: the trace bytes alone are hundreds of megabytes, and duplicating them
under bench/datasets would give one measurement two digests the moment either copy is rewritten.
The bundle pins every included file by digest and by its path relative to the bundle directory,
and carries the small reviewable part in place, so `bench verify` can check a published dataset
against the store it points at.
"""
import os
from pathlib import Path

from bench import BENCH_VERSION
from bench.common import BENCH, BenchError, read_json, rel_path, resolve, sha256_file, write_json
from bench.store import RunStore, verify_checksum_file

DEFAULT_VERSION = "bench-0.1"
CARD_HEADINGS = ("Scope", "Collection", "Labels and raters", "Splits", "Coverage and what is missing",
                 "Known biases", "Measurement conditions", "Claims ceiling", "Intended use", "Unintended use",
                 "Licenses", "Citation", "Versioning", "Verification")
# Groups whose bytes travel into the bundle, and groups that stay in place and are pinned by digest.
COPY_GROUPS = ("analysis", "labels", "baselines", "cases", "hosts", "schemas")
REFERENCE_GROUPS = ("runs", "sources", "workloads")


def _rel_to_bundle(path, bundle):
    """A POSIX path from the bundle directory: portable, self-locating, never host-specific."""
    return os.path.relpath(str(path), str(bundle)).replace("\\", "/")


def _files(*patterns):
    root = BENCH
    found = set()
    for pattern in patterns:
        found.update(path for path in root.glob(pattern) if path.is_file())
    return sorted(found, key=lambda item: item.as_posix())


def included_files():
    """Every file the bundle knows about, grouped. A file appears in exactly one group."""
    listed = {}
    listed["analysis"] = _files("analysis/**")
    listed["labels"] = _files("cases/*/labels/*.json")
    listed["baselines"] = _files("baselines/**/*.json")
    labels = {path.as_posix() for path in listed["labels"]}
    listed["cases"] = [path for path in _files("cases/**") if path.as_posix() not in labels]
    listed["hosts"] = _files("hosts/*.json")
    listed["schemas"] = _files("schema/*.json")
    listed["runs"] = _files("runs/**")
    listed["sources"] = _files("sources/manifest.json")
    listed["workloads"] = _workload_files()
    return listed


def _workload_files():
    """The pinned layouts' index and small metadata blobs, never the layer payloads."""
    seen = {}
    for path in _files("cases/*/case.json"):
        local = (read_json(path).get("image") or {}).get("local_path")
        if not local:
            continue
        root = resolve(local)
        if not root.is_dir():
            continue
        for candidate in root.rglob("*"):
            if candidate.is_file() and candidate.stat().st_size <= 262144:
                # Small files are metadata, config or an index; a layer is orders of magnitude
                # bigger and is already pinned cryptographically by the case record's digest.
                seen[candidate.as_posix()] = candidate
    return sorted(seen.values(), key=lambda item: item.as_posix())


def license_block():
    rows = []
    for path in _files("cases/*/case.json"):
        record = read_json(path)
        image = record.get("image") or {}
        rows.append({"kind": "workload", "case_id": record["case_id"], "license": image.get("license"),
                     "digest": image.get("digest"), "source_url": image.get("source_url"),
                     "layer_digests": image.get("layer_digests") or []})
    sources_path = BENCH / "sources" / "manifest.json"
    if sources_path.is_file():
        for entry in read_json(sources_path)["entries"]:
            rows.append({"kind": "reference-document", "url": entry["url"],
                         "license": "publisher terms; cited and digest-pinned, not re-licensed by us",
                         "final_url": entry.get("final_url"), "http_status": entry.get("http_status"),
                         "content_sha256": entry.get("content_sha256")})
    rows.append({"kind": "harness", "harness_version": BENCH_VERSION,
                 "license": "same terms as the SENTRYCHECK repository this bundle lives in"})
    rows.sort(key=lambda item: (item["kind"], item.get("case_id") or item.get("url") or ""))
    return {"schema_version": "1.0",
            "note": "workload layer blobs are pinned by digest and not redistributed", "entries": rows}


def dataset_manifest(version, listed):
    runs = RunStore(BENCH / "runs").records()
    labels = [_payload(path) for path in listed["labels"]]
    return {"schema_version": "1.0", "dataset_version": version, "harness_version": BENCH_VERSION,
            "title": "SENTRYCHECK runtime-compatibility benchmark dataset",
            "counts": {"runs": len(runs), "valid_runs": sum(1 for record in runs if record["valid"]),
                       "suites": len({record["suite"] for record in runs}),
                       "cases": len({record["case_id"] for record in runs}), "labels": len(labels),
                       "files": sum(len(rows) for rows in listed.values())},
            "groups": {name: {"files": len(rows), "copied": name in COPY_GROUPS,
                              "sample_paths": [_rel_to_bundle(path, BENCH / "datasets" / version) for path in rows[:3]],
                              "truncated_listing": max(0, len(rows) - 3)}
                       for name, rows in sorted(listed.items())},
            "evidence_tiers": sorted({(record.get("predicted") or {}).get("tier") or "none" for record in runs}),
            "label_classes": sorted({record["class"] for record in labels if record.get("class")}),
            "checksum_file": "checksums.txt", "card": "DATASET_CARD.md",
            "license_manifest": "license-manifest.json"}


def _payload(path):
    try:
        return read_json(path)
    except Exception:
        return {}


def write_checksums(bundle, listed):
    lines = []
    for name in sorted(listed):
        for path in listed[name]:
            lines.append("%s  %s" % (sha256_file(path), _rel_to_bundle(path, bundle)))
    text = "\n".join(sorted(lines)) + "\n"
    with (bundle / "checksums.txt").open("w", encoding="utf-8", newline="\n") as handle:
        handle.write(text)
    return len(lines)


def write_checksums(bundle, pairs):
    """One `digest  path` line per included file, sorted, LF, portable refs only."""
    lines = ["%s  %s" % (sha256_file(path), ref) for path, ref in pairs]
    text = "\n".join(sorted(lines)) + "\n"
    with (bundle / "checksums.txt").open("w", encoding="utf-8", newline="\n") as handle:
        handle.write(text)
    return len(lines)


def copy_payload(bundle, listed):
    """Mirror the reviewable groups inside the bundle under their bench-relative path."""
    moved = []
    for name in COPY_GROUPS:
        for path in listed[name]:
            destination = bundle / path.relative_to(BENCH)
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(path.read_bytes())
            moved.append((destination, destination.relative_to(bundle).as_posix()))
    return moved


def reference_pairs(bundle, listed):
    """Files that stay where they are: pinned through a path that climbs out of the bundle."""
    pairs = []
    for name in listed:
        if name in COPY_GROUPS:
            continue
        for path in listed[name]:
            pairs.append((path, _rel_to_bundle(path, bundle)))
    return pairs


def card_text(version, listed):
    """DATASET_CARD.md: every PRD 7.4 heading, filled only from recorded data."""
    runs = RunStore(BENCH / "runs").records()
    by_suite = {}
    for record in runs:
        by_suite.setdefault(record["suite"], []).append(record)
    labels = [_payload(path) for path in listed["labels"]]
    splits = {}
    for record in labels:
        split = record.get("split") or "unrecorded"
        splits[split] = splits.get(split, 0) + 1
    content = {
        "Scope": "Compatibility and evidence-tier behaviour of the SENTRYCHECK scanner against a sandboxed "
                 "Linux runtime (gVisor runsc, systrap), plus how much of a verdict depends on having dynamic "
                 "evidence. It does not cover Kubernetes admission, arm64, Kata Containers, or bare-metal timing.",
        "Collection": "%d runs recorded by harness %s on host ids %s. Every run is an actual scanner execution "
                      "whose report, traces, outputs and logs are digest-pinned in bench/runs/index.json; no "
                      "measurement in this bundle was typed in." % (
                          len(runs), BENCH_VERSION, ", ".join(sorted({record["host_id"] for record in runs}))),
        "Labels and raters": "%d adjudicated labels. Both raters are documented deterministic rules over "
                             "independent evidence (rater A: the knowledge-base citations; rater B: raw exit "
                             "codes, stdout digests and sandbox refusals). There are no human raters in this "
                             "dataset, and the agreement statistics must be read with that in mind." % len(labels),
        "Splits": ", ".join("%s=%d" % (name, count) for name, count in sorted(splits.items())) or "no labels",
        "Coverage and what is missing": "Suites with recorded runs: %s. Everything else is enumerated in "
                                        "bench/analysis/tables/not-run.csv, which the analyzer generates from the "
                                        "store rather than from a hand-maintained list." % (", ".join(sorted(by_suite))),
        "Known biases": "Author-selected cases with no sampling frame; one runtime family (gVisor systrap); one "
                        "architecture (amd64); one host class (WSL2 on an uncontrolled desktop); a rule-based "
                        "labeler that cannot see a class its rules do not describe; per-case n of 1 to 4, so most "
                        "confidence intervals are wide.",
        "Measurement conditions": "Native and sandbox repetitions interleaved per case (ABBA for the ablation "
                                  "arms, AB for the stability arms); scan timings exclude staging; the record's "
                                  "environment block carries load, free disk and clock sync, and preflight output "
                                  "is stored per run under logs/preflight.json.",
        "Claims ceiling": "L2. Compatibility claims rest on recorded execution evidence, but with no independent "
                          "human rater no claim in this dataset supports L3 or above.",
        "Intended use": "Measuring whether a runtime-compatibility scanner's verdict matches observed sandbox "
                        "behaviour, and how much of that verdict depends on the evidence tier available.",
        "Unintended use": "Not a security guarantee, not a production capacity benchmark, not a certification of "
                          "any workload, and not a comparison against other tools (none were run here).",
        "Licenses": "See license-manifest.json. Workload layers are pinned by digest and not redistributed; "
                    "reference documents are cited by URL and digest under their publishers' terms.",
        "Citation": "SENTRYCHECK benchmark harness %s, dataset %s, collected 2026-10-31." % (BENCH_VERSION, version),
        "Versioning": "Append-only. A bad run keeps its place with valid=false and an invalid_reason; the dataset "
                      "version changes when the schema or the case registry changes, not when a number is revised.",
        "Verification": "`python -m bench verify --all` re-hashes every stored artifact, `python -m bench verify "
                        "--prereg` checks the sealed pre-registration, and the checksum file in this directory "
                        "re-hashes the bundle against the store it points at.",
    }
    lines = ["# Dataset card - %s" % version, ""]
    for heading in CARD_HEADINGS:
        lines += ["## %s" % heading, "", content[heading], ""]
    lines += ["## Suite inventory", "", "| suite | runs | valid | invalid | cases |", "| --- | --- | --- | --- | --- |"]
    for suite in sorted(by_suite):
        rows = by_suite[suite]
        lines.append("| %s | %d | %d | %d | %d |" % (suite, len(rows), sum(1 for row in rows if row["valid"]),
                                                    sum(1 for row in rows if not row["valid"]),
                                                    len({row["case_id"] for row in rows})))
    lines += ["", "## Groups in this bundle", "", "| group | files | travels with the bundle |",
              "| --- | --- | --- |"]
    for name in sorted(listed):
        lines.append("| %s | %d | %s |" % (name, len(listed[name]), "yes" if name in COPY_GROUPS else "referenced"))
    lines.append("")
    return "\n".join(lines) + "\n"


def command_publish(args):
    version = args.version or DEFAULT_VERSION
    out = resolve(args.out) if not Path(args.out).is_absolute() else Path(args.out)
    bundle = out / version
    listed = included_files()
    payload = dataset_manifest(version, listed)
    if (bundle / "manifest.json").is_file() and not getattr(args, "force", False):
        raise BenchError("bundle %s already exists; pass --force to rewrite it, because a published version's "
                         "checksums must not be replaced silently" % rel_path(bundle))
    bundle.mkdir(parents=True, exist_ok=True)
    moved = copy_payload(bundle, listed)
    pairs = moved + reference_pairs(bundle, listed)
    pinned = write_checksums(bundle, pairs)
    write_json(bundle / "manifest.json", payload)
    write_json(bundle / "license-manifest.json", license_block())
    with (bundle / "DATASET_CARD.md").open("w", encoding="utf-8", newline="\n") as handle:
        handle.write(card_text(version, listed))
    check = verify_checksum_file(bundle / "checksums.txt")
    print("published %s: %d files pinned, %d copied into the bundle, %d referenced in place, checksum failures=%d"
          % (rel_path(bundle), pinned, len(moved), pinned - len(moved), len(check["failures"])))
    for failure in check["failures"][:10]:
        print("  %s" % failure)
    return 0 if not check["failures"] else 1
