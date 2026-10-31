# Benchmark methodology

`scripts/benchmark.py` measures actual command executions and emits raw samples,
validated report identities, descriptive statistics, standalone SVG charts, and a
generated `BENCHMARKS.md`. It uses the Python standard library. It never substitutes
synthetic timings for an unavailable runtime, and it does not convert old report
durations into newly measured scanner latency.

Run it only after building and testing the scanner. Stop unrelated builds and
benchmarks first. An otherwise ordinary shared CI runner is useful as an adoption
example, but its measurements remain specific to that runner and host load.

```sh
python scripts/benchmark.py run \
  --binary bin/sentrycheck-linux \
  --manifest benchmarks/manifest.json \
  --cwd . \
  --out artifacts/benchmarks-2026-09-26
```

The Windows command uses `bin/sentrycheck.exe`. Live scans require Linux and the
configured runtimes. `--out` must name a **new directory**: the script refuses to
overwrite an existing experiment. Paths inside the manifest resolve relative to
the manifest directory, or relative to `--cwd` when supplied. The binary path is
resolved relative to the shell's current directory.

The harness exits `0` when every requested experiment completed and every scanner
measurement passed validation. It exits `2` for invalid measurements, malformed
configuration, or interrupted experiments. A successful harness run containing
static scans does **not** mean the workloads are compatible: static scanner exit
`2` is an expected, valid observation. A hard-failure finding normally produces
scanner exit `1`, which also remains a valid measurement when expected by the
manifest. The harness independently checks the report/exit-code contract.

## Manifest

This example runs new measurements; all numbers shown here are configuration,
not benchmark results. Use already acquired, digest-bound OCI layouts when the
question is analyzer overhead rather than registry acquisition.

```json
{
  "schema_version": "1.0",
  "retain_reports": false,
  "cases": [
    {
      "name": "small-static-warm",
      "image": "artifacts/live-images/baseline",
      "mode": "static",
      "cache": "warm-analyzer",
      "warmups": 1,
      "repetitions": 30,
      "timeout_seconds": 120,
      "scan_args": ["--version", "20260921.0"],
      "expected_exit_codes": [2]
    },
    {
      "name": "required-uring-live",
      "image": "artifacts/live-images/io_uring",
      "mode": "live",
      "cache": "disabled",
      "warmups": 1,
      "repetitions": 10,
      "timeout_seconds": 300,
      "scan_args": [
        "--runtime", "gvisor",
        "--version", "20260921.0",
        "--profile", "profiles/synthetic.toml",
        "--runc-bin", ".cache/linux/bin/runc",
        "--runsc-bin", ".cache/linux/bin/runsc"
      ],
      "expected_exit_codes": [1]
    }
  ]
}
```

Names must be unique safe identifiers. `mode` is `static`, `live`, or
`native-only`; it describes the requested invocation, while the resulting status
and evidence tier are recorded separately. An unavailable runtime is never counted
as a completed live comparison. Multiple runtimes can be benchmarked as separate
explicit cases; the current harness does not claim a three-way aggregate latency
by adding independently measured scans.

`scan_args` consists of option/value pairs. It accepts `--runtime`, `--version`,
`--platform`, `--profile`, `--kb`, `--max-kb-age-days`, `--runc-bin`, `--runsc-bin`,
`--strace-bin`, and `--fail-on`. The harness owns format, artifact, output, mode,
and cache arguments. Imported `--evidence` is deliberately excluded from execution
benchmarks. `expected_exit_codes` defaults to `[0, 1, 2]`; use a narrower explicit
expectation when the corpus has independent ground truth. Each case defaults to
20 measurements, one warmup, and a 1,800-second command timeout.

`retain_reports: false`, the default, keeps only the last full report/stderr per
case. Every earlier report's SHA-256, condensed observations, measured time,
command, and validation result remain in `samples.jsonl`. Set it to `true` to
retain every full report. Earlier full reports cannot be recovered from their
hashes; use full retention when archival replay of every sample is required.
Live trace/output artifacts are retained in separate per-sample directories in
either mode. Large profiles can consume substantial disk space. No existing
cache, evidence directory, or benchmark result is deleted automatically.

## What is timed and verified

The measured interval runs from process launch through scanner exit, using
`time.perf_counter_ns()`. It includes acquisition for registry/archive inputs,
image parsing, analysis, runtime/tracer startup, the declared profile invocations,
and JSON serialization/output. The harness writes stdout directly to a report
file; it does not buffer a second large report copy just to measure it.

After each interval, `sentrycheck report validate` verifies semantic consistency
and the exact report hash. Dynamic reports additionally use `--artifacts-root`
to check captured artifact hashes and parse consistency. Validation, hashing,
input/tool identity collection, and chart generation are outside the reported
scanner interval. They still consume wall time for the entire benchmark job and
can affect subsequent OS page-cache state. Their exclusion is explicit: the
scanner benchmark is not the total benchmark-harness job duration.

Raw samples record scanner exit codes, timeouts, errors, complete/incomplete
status, evidence tier, runtime versions, image/profile/report hashes, KB snapshot,
cache hits, findings by severity, and condensed execution observations. The
summary identifies the scanner binary, benchmark script, manifest, explicitly
supplied profiles/KB files, discovered runtime binaries, kernel, CPU count,
Python/clock details, and available host-load metadata. Discovery of a runtime
binary is not proof that a workload executed inside it; that claim depends on the
validated report observations. Signature authentication is a separate operation.

The scanner binary is hashed again at the end. If it changed during measurement,
the experiment is marked failed. Do not rebuild the scanner or alter inputs while
measuring. Different image/profile/KB/runtime identities and evidence/status
classes are summarized separately rather than silently pooled.

Invalid attempts remain in the append-only JSONL, with their measured elapsed
time and error, but are excluded from successful-scan percentile summaries. The
generated document reports the invalid-attempt count. Warmups are also retained
and explicitly excluded. A partially completed experiment writes `status: failed`
instead of leaving an old success marker. Timeouts terminate the launched process
tree; runtimes with externally managed resources may still require their normal
runtime cleanup and inspection before another experiment.

## Cache and sample design

| Mode | Definition | What it does not establish |
| --- | --- | --- |
| `disabled` | Scanner receives `--no-cache` for ELF results | Cold OS page cache or absence of runtime/registry caches |
| `cold-analyzer` | Each sample receives a new, empty analyzer cache directory | A cold filesystem or newly booted node |
| `warm-analyzer` | One persistent analyzer cache with at least one recorded warmup | Every ELF is cached; inspect reported `cache_hits` |

OS caches are not flushed, because doing so changes the machine globally and is
often unavailable on CI. Image size metadata for a local OCI layout uses the
manifest's declared compressed layer bytes and layer count; it is not an estimate
of resident memory or unpacked rootfs size. The scanner verifies the actual image
digests during each scan. Multi-platform OCI index descriptors without direct
layer lists remain unmeasured in that size field.

Cases execute sequentially, in manifest order. This avoids deliberately competing
workloads but does not eliminate time/order effects or unrelated host contention.
For publication, repeat the entire manifest in counterbalanced order on several
fresh runner allocations, retain the raw runs, distinguish debug and release
binaries, and report the runner/hardware and acquisition policy. A few local
measurements can support a reproduction example; they cannot support an all-CI
performance claim.

## Percentiles and uncertainty

The empirical percentile is the **nearest-rank quantile**:
`sort(samples)[ceil(p * n) - 1]`. The summary publishes `n`, minimum, maximum,
mean, p50, p95, and p99. For a small sample, p95 or p99 can equal the maximum;
that is an empirical order statistic, not a validated tail-latency service level.
A warning is emitted whenever fewer than five observations are expected beyond
the requested quantile (`n * (1 - p) < 5`).

`summary.json` also provides conservative 95% Dvoretzky–Kiefer–Wolfowitz
distribution/quantile bounds using
`epsilon = sqrt(log(2 / 0.05) / (2 * n))`. Quantile bounds use the empirical
quantiles at `p - epsilon` and `p + epsilon`. A bound beyond the observed
probability range is `null`, meaning that the finite sample supplies no finite
bound. It is never silently replaced with the observed minimum/maximum.

These bounds assume independent, identically distributed stationary samples.
Serial scans on a shared host may violate that assumption. They quantify finite
sample uncertainty under the stated assumption, not hardware variability or
confidence in syscall compatibility. SVG charts are descriptive percentile bars;
the full uncertainty is in the accompanying machine-readable summary.

## Paired CI delta

Add `ci_pairs` to run an explicitly defined baseline pipeline and an otherwise
equivalent pipeline containing the gate. These commands are argument arrays,
executed without a shell. For pipelines requiring several commands, check a small
script into the repository and invoke it. The harness cannot establish that two
arbitrary commands differ only by the scanner; the experiment author must make
that condition inspectable.

```json
{
  "name": "project-ci-delta",
  "baseline": ["python", "scripts/project_ci.py", "--without-gate"],
  "gate": ["python", "scripts/project_ci.py", "--with-gate"],
  "environment": "local",
  "repetitions": 10,
  "warmups": 1,
  "baseline_exit_codes": [0],
  "gate_exit_codes": [0],
  "runner_price_usd_per_minute": null
}
```

The example script name above illustrates the caller-owned project pipeline; it
is not a claim that such a project experiment has already been run. Pair order
alternates baseline/gate then gate/baseline. Each delta is computed from its own
pair; negative deltas remain negative instead of being clipped. Invalid command
outcomes exclude that pair while retaining its raw observations.

`environment: github-actions` is accepted only when the process is running with
`GITHUB_ACTIONS=true` and a `GITHUB_RUN_ID`. The summary records run ID, repository,
commit, attempt, and runner platform. This metadata is a reproducibility pointer,
not cryptographic authentication of a GitHub run. A local paired measurement
remains labeled `local` and is never relabeled as a GitHub Actions result.

An optional caller-declared USD/minute rate produces a **prorated estimate** in
each raw pair. It excludes billing increments, free minutes, organization
discounts, caching/storage, and concurrent jobs. No price is guessed and no
prorated estimate is described as an actual invoice. Publishing an adoption cost
for an open-source project also requires pinning its source/Dockerfile revision,
documenting baseline and gate scripts, and linking the real Actions run.

## Historical risk incidence

The optional `historical_reports` array supports honest descriptive reuse of
existing reports:

```json
{
  "name": "python-retained",
  "report": "artifacts/live-baselines/python.report.json",
  "clean_label": true,
  "label_source": "docs/VALIDATION.md: profile assertions passed under both tested runtimes",
  "artifacts_root": "."
}
```

Every report is semantically validated; `artifacts_root` requests captured-file
verification as well. A report counts in the clean-label denominator only when
its caller-supplied label is `true`, its status is complete, and its provenance is
locally executed. Duplicate report hashes are rejected. Dates/analyzer versions
remain the original values. Reports with no label remain listed but excluded.

The output is **compatibility-risk incidence among eligible reports**, with a
Wilson interval conditional on independent Bernoulli sampling. It is not a
population false-positive rate: a selected, correlated corpus and caller-attested
labels do not establish that inference. A `compatibility-risk` itself can correctly
identify a failed optional probe in an otherwise functioning workload. The harness
also counts hard-failure-positive clean-labeled reports so such disagreements are
visible. No new multi-tenant load/noise experiment is implied by report-only reuse.

## Frozen KB policy experiment

```json
{
  "snapshot": "kb/snapshot.json",
  "as_of": "2026-09-26",
  "ages_days": [0, 7, 14, 30, 31, 60, 90],
  "max_age_days": 30
}
```

Place this object in the top-level `kb_age` field. It holds the exact snapshot
constant and advances calendar dates. Output shows whether the snapshot satisfies
the configured age limit and how many entries have a `last_verified` date within
that limit. Input dates cannot pretend a snapshot existed before its creation or
use future verification evidence. Snapshot identity and source commit are retained.

This is a **verification-recency and policy-coverage experiment**, not an accuracy
decay curve. Entry dates alone contain no ground truth about workload outcomes at
later runtime releases. A real accuracy-decay study needs historical snapshots,
release-pinned runtimes, independently labeled workloads, and replay/evaluation
at each snapshot/release pair. The harness refuses to manufacture those missing
labels. It uses calendar UTC days; the scanner uses elapsed timestamp days, so
the exact hour at an age-policy boundary can differ.

## Separate measurements still required

Node-probe steady-state CPU/RSS and canary/CRI overhead require a dedicated node
resource experiment with a fixed poll interval, a recorded idle baseline, multiple
sampling windows, and measurements of the probe **and** spawned/runtime services.
A scanner's elapsed time or a one-shot process's peak RSS does not answer that
question. Likewise, a recorded cluster demo, a public GitHub Security screenshot,
Kata VM results, and a historical accuracy-decay curve require their own actual
environments and evidence. The generated benchmark document labels missing
measurements rather than filling them with illustrative numbers.

## Verification

```sh
python -m unittest discover -s tests -p test_benchmark.py -v
```

Tests check known quantiles, bounded/unbounded uncertainty, provenance and exit
contract handling, cache warmup behavior, grouping by input identity, refusal to
overwrite evidence, timeout handling, policy-date boundaries, and actual tiny CLI
measurements. Those fixture measurements validate the benchmark harness; they are
not the published workload performance evaluation.
