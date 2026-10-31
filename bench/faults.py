"""BM-03: trace fault injection against the real parser.

The property under test is not "does the parser survive junk" but "does junk ever look like
evidence". A corrupted trace may legitimately produce a shorter, degraded summary; it must never
produce a summary that is indistinguishable from the clean one, because that is the path by which
a scanner reports compatibility it never observed. The oracle here is the workspace's own parser,
`trace_summary`, not a reimplementation.
"""
import json
import random
import subprocess
from pathlib import Path

from bench.common import BENCH, BenchError, read_json, rel_path, resolve, sha256_file, write_json
from bench.runner import find_binary

ORACLES = ("target/debug/examples/trace_summary.exe", "target/debug/examples/trace_summary")
FORMATS = ("strace-guest", "runsc-guest")
BASELINE_EVENTS = "baseline_event_count"
# Each family is a byte- or line-level mutation of a recorded trace, named for the hazard it probes.
FAMILIES = ("truncate-tail", "drop-events", "forged-task-name", "injected-quote-marker", "overlong-line",
            "non-utf8-bytes", "zeroed-head", "absurd-tid")


def oracle_binary():
    found = find_binary(ORACLES)
    if not Path(found).is_file():
        raise BenchError("the trace parser oracle %s is not built; run cargo build --offline --example "
                         "trace_summary before BM-03" % ORACLES[0])
    return found


def source_traces(limit=6):
    """Recorded traces from the store, oldest first, so the corpus is seeded by real evidence."""
    paths = [path for path in sorted((BENCH / "runs").rglob("*.trace"), key=lambda item: item.as_posix())
             if path.is_file()]
    if not paths:
        raise BenchError("no recorded trace exists in bench/runs; BM-03 mutates real evidence, not samples")
    return paths[:limit] if limit else paths


def mutate(data, family, rng):
    """One mutation of one family. Pure and seeded: same input plus seed gives same bytes."""
    lines = data.split(b"\n")
    if family == "truncate-tail":
        return data[:max(0, len(data) - rng.randint(1, min(40, len(data) or 1)))]
    if family == "drop-events":
        keep = [line for line in lines if line.strip()]
        for _ in range(rng.randint(1, 5)):
            if keep:
                keep.pop(rng.randrange(len(keep)))
        return b"\n".join(keep) + b"\n"
    if family == "forged-task-name":
        return _replace_line(lines, rng, lambda line: b"bogus-task-name " + line.split(b" ", 1)[-1])
    if family == "injected-quote-marker":
        quote_indices = [i for i, line in enumerate(lines) if b'"' in line]
        if quote_indices:
            picked = rng.choice(quote_indices)
            lines = list(lines)
            lines[picked] = lines[picked].replace(b'"', b'"\'"$(`\\', 1)
            return b"\n".join(lines)
        return _replace_line(lines, rng, lambda line: line + b' "unbalanced\'"$(`\\')
    if family == "overlong-line":
        # Well past the documented bounded-read limit, so a compliant reader must refuse, not swallow.
        return data + b"\n" + b"9 " + b"x" * (2 * 1024 * 1024) + b"(2) = 0\n"
    if family == "non-utf8-bytes":
        position = rng.randrange(max(1, len(data)))
        return data[:position] + b"\xff\xfe\x80" + data[position:]
    if family == "zeroed-head":
        return b"\x00" * min(64, len(data)) + data[min(64, len(data)):]
    if family == "absurd-tid":
        return _replace_line(lines, rng, lambda line: b"99999999999999999999 " + line.split(b" ", 1)[-1])
    raise BenchError("unknown fault family %s" % family)


def _replace_line(lines, rng, transform):
    index = [i for i, line in enumerate(lines) if line.strip()]
    if not index:
        return b"\n".join(lines)
    picked = rng.choice(index)
    lines = list(lines)
    lines[picked] = transform(lines[picked])
    return b"\n".join(lines)


def build_corpus(seed, count, out):
    """Write `count` mutants, spread over the families and the recorded sources."""
    rng = random.Random(seed)
    sources = source_traces()
    out.mkdir(parents=True, exist_ok=True)
    entries = []
    for position in range(count):
        family = FAMILIES[position % len(FAMILIES)]
        source = sources[position % len(sources)]
        data = source.read_bytes()
        payload = mutate(data, family, rng)
        name = "%03d-%s.trace" % (position, family)
        target = out / name
        target.write_bytes(payload)
        entries.append({"mutant": rel_path(target), "family": family, "source_trace": rel_path(source),
                        "source_sha256": sha256_file(source), "sha256": sha256_file(target),
                        "seed": seed, "bytes": len(payload)})
    return entries


def summarize(binary, path, timeout=120):
    """Run the parser the way the tool does; return (exit code, parsed summary or None, stderr)."""
    argv = [str(binary), "strace-guest", str(path)]
    try:
        done = subprocess.run(argv, capture_output=True, timeout=timeout, encoding="utf-8", errors="replace")
    except subprocess.TimeoutExpired:
        return None, None, "timed out after %ds" % timeout
    text = (done.stdout or "").strip()
    try:
        return done.returncode, json.loads(text), (done.stderr or "").strip()
    except ValueError:
        return done.returncode, None, (done.stderr or "").strip()[:400]


def classify(summary, baseline):
    """degraded = the parser noticed; silent-accept = it did not, which is the failure this suite is for."""
    if summary is None:
        return "rejected"
    events = summary.get("event_count") or 0
    unparsed = summary.get("unparsed_lines") or 0
    discarded = summary.get("discarded_guest_records") or 0
    if summary.get("truncated") or unparsed or discarded:
        return "degraded-flagged"
    if baseline is not None and events < baseline:
        return "degraded-shorter"
    return "silent-accept"


def run(args):
    seed, count = int(args.seed), int(args.count)
    out = resolve(args.out) if not Path(args.out).is_absolute() else Path(args.out)
    binary = oracle_binary()
    entries = build_corpus(seed, count, out)
    baselines = {}
    rows = []
    for entry in entries:
        source = entry["source_trace"]
        if source not in baselines:
            code, summary, _error = summarize(binary, resolve(source))
            baselines[source] = (summary or {}).get("event_count") if summary else None
        code, summary, error = summarize(binary, resolve(entry["mutant"]))
        verdict = classify(summary, baselines[source])
        rows.append(dict(entry, oracle_exit=code, verdict=verdict, event_count=(summary or {}).get("event_count"),
                         unparsed_lines=(summary or {}).get("unparsed_lines"),
                         discarded=(summary or {}).get("discarded_guest_records"),
                         truncated=bool((summary or {}).get("truncated")), oracle_error=error or None))
    counts = {}
    for row in rows:
        counts[row["verdict"]] = counts.get(row["verdict"], 0) + 1
    offenders = sorted(row["mutant"] for row in rows if row["verdict"] == "silent-accept")
    manifest = {"schema_version": "1.0", "suite": "BM-03", "seed": seed, "families": list(FAMILIES),
                "oracle": {"path": rel_path(binary), "sha256": sha256_file(binary)},
                "mutants": rows, "verdict_counts": dict(sorted(counts.items())),
                "silent_accepts": offenders,
                "property": "a mutated trace must never be summarized identically to the recorded one",
                "limitation": "this suite exercises the trace parser oracle. It does not re-run the full scan "
                              "pipeline per mutant, so an end-to-end false-compatible verdict is out of scope "
                              "here and is reported as such rather than assumed away."}
    write_json(out / "manifest.json", manifest)
    print("BM-03: %d mutants over %d families -> %s" % (len(rows), len(FAMILIES),
                                                        ", ".join("%s=%d" % item for item in sorted(counts.items()))))
    if offenders:
        print("  FAIL silent-accept (parser could not tell the mutant from the record): %s" % ", ".join(offenders))
    return 1 if offenders else 0


def command_faults(args):
    return run(args)
