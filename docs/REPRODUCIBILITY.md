# Reproducing the evidence

`scripts/demo.py` provides one entry point for two distinct operations. Its default
`verify` mode checks existing evidence and renders an offline report. Explicit
`live` mode executes workloads and, with `--full`, the complete demonstration
pipeline. Neither mode silently substitutes for the other.

## Verify retained observations

From the repository root, with a built scanner and the retained evidence archive:

```sh
python scripts/demo.py --mode verify --out artifacts/demo-verified
```

The default pair is the retained v0.3 minimal baseline and required-io_uring
report in `artifacts/review-v03/final-live/`. The command invokes public semantic
validation and artifact-hash/trace validation, then generates `report.html` and
`summary.json` in a **new** output directory. Source reports are read only. The
summary retains the original scan time, analyzer version, image/report hashes,
evidence tier, and `new_workload_execution: false`.

Override the binary using `--binary PATH`, reports with repeated `--report PATH`,
and the permitted artifact tree with `--artifacts-root PATH`. A checkout without
the retained report/trace archive cannot run this verification; it fails visibly
instead of manufacturing demonstration data. The current parser may reject an
older trace interpretation. That requires investigation or a new live scan, not
silently treating the report as current evidence.

Some retained reports contain absolute paths from the original Linux workspace.
After relocating the archive, request an explicit mapping:

```sh
python scripts/demo.py --mode verify \
  --artifact-prefix /original/workspace=/current/workspace \
  --artifacts-root /current/workspace \
  --out artifacts/demo-relocated
```

The original report bytes are semantically validated first. Only artifact
reference fields are relocated in a **derived copy**, whose hash is separately
recorded and whose artifacts are verified under the requested root. Original
report bytes and signatures are not rewritten or reauthenticated. This also
supports moving `/mnt/c/...` references to a native Windows workspace when the
archive is available there. Signature authentication remains a separate check.

## Run the complete live demonstration

Provision an isolated Linux environment first: Rust/Go outputs, runc, strace,
checksum-verified runsc and its companion binaries, K3s, the Go admission/probe
binaries, gcc, Go, skopeo, and the trusted PostgreSQL fixture. The existing live
scripts require root for their disposable runtime setup. No command here uploads
evidence, opens an upstream issue, or operates on a public cluster.

```sh
sudo python3 scripts/demo.py --mode live --full \
  --postgres-image /path/to/prebuilt-postgres-oci \
  --binary bin/sentrycheck-linux \
  --out /tmp/sentrycheck-demo-evidence \
  --work-dir /tmp/sentrycheck-demo-work
```

`--full` executes the existing scripts in this order:

1. Tiny live baseline, required/optional io_uring, optional BPF, and output-divergence
   comparisons (`live-smoke.sh`).
2. Representative Python, Node.js, and Go comparisons (`live-baselines.sh`).
3. The PostgreSQL 18/liburing comparison (`live-postgres.sh`).
4. Actual disposable Kubernetes runtime mismatch, missing-runtime denial, and
   recovery checks, with a fresh terminal recording (`test-node-runtime-live.sh`).

All selected stages must pass. The final reports undergo public semantic and
artifact validation, and the PostgreSQL finding is selected for `report.html`.
The node check uses the freshly produced clean Go report from this invocation.
The original scripts still assert their expected workload outcomes; an unavailable
sandbox, incomplete trace, unexpected outcome, or failed cluster check makes the
orchestrator fail. A failed stage's stdout/stderr and exit code remain in the
summary. This is a reproduction of particular profiles, not a guarantee for
untested application paths.

Both output and working directories must be new. Temporary builds, generated
images, analyzer caches, copied traces, and reports are directed there through
explicit environment overrides. The default preflight requires at least **4 GiB
free on each relevant filesystem**. This threshold is not a storage upper bound;
large image pulls, PostgreSQL builds, traces, and duplicate retained outputs can
require more. Use a suitable Linux scratch filesystem, not a nearly full desktop
drive. `--min-free-gib` can increase or explicitly change that prerequisite.

Full mode reuses a prebuilt PostgreSQL OCI fixture when supplied. A source rebuild
is allowed only with explicit `--rebuild-postgres`, and preflight requires build
tools and liburing development files to be provisioned. The source script retains
its checksum-verified download and build logic. Registry-backed Python/Node inputs
resolve to recorded digests; network acquisition is part of live reproduction.
This pipeline is not promised to finish in minutes on every CI machine.

Add `--measure-node` to include the idle/active node resource windows before the
recorded mismatch sequence. The resource accounting and recording limitations are
described in [NODE-BENCHMARK.md](NODE-BENCHMARK.md). Override executable paths with
`--k3s`, `--runsc`, `--admission`, and `--probe`. The script's `--help` lists the
supported arguments.

## Run a smaller fresh comparison

```sh
sudo python3 scripts/demo.py --mode live \
  --image /path/to/image-oci --profile profiles/go.toml \
  --out /tmp/sentrycheck-single-evidence --work-dir /tmp/sentrycheck-single-work
```

Alternatively, pass `--manifest PATH` containing explicit `mode: live` cases in
the [benchmark manifest format](BENCHMARK-METHODOLOGY.md). Case paths resolve from
the repository root. The orchestrator rejects historical-only sections, static
cases, or imported evidence in this live pathway. Every selected result must be
complete and locally executed. `--include-node --node-report CLEAN_REPORT`
adds the node scenario to a smaller invocation. `--full` already includes it.

## Real GitHub Actions evidence

[benchmarks.yml](../.github/workflows/benchmarks.yml) is a manual-dispatch workflow.
It builds this repository's actual Dockerfile, records its Git revision and Actions
run identity, and measures alternating-order pairs of:

- A cached Docker build.
- The same cached Docker build plus a static-only `ci-gate` and report validation
  against the prepared OCI image.

The initial build/image export and Rust compilation are preparation outside the
paired intervals. The generated pipeline script, manifest, raw paired samples,
scanner report, SARIF, and summaries are uploaded as artifacts even when a later
gate step fails. Runtime/scanner identities and image digest are retained. It is
an experiment on **this project**, not evidence about an unrelated open-source
project's CI overhead. No price is assumed, so there is no claimed actual dollar
cost until a real runner billing context and completed run are available.

The workflow uploads actual SARIF through GitHub's code-scanning action. A static
capability scan normally has no confirmed findings to display and returns exit
`2`. The workflow preserves that code as an incomplete-evidence outcome; recording
valid measurements does not convert it into a clean compatibility gate. Exit `1`
takes precedence if any paired gate reports a selected failure. Invalid/missing
measurements also fail closed. Consult the artifacts and gate-outcome step rather
than interpreting a red workflow as a benchmark-harness crash.

The workflow has been authored and locally syntax-checked. Until it is dispatched
on a real repository with code-scanning permissions, there is **no measured GitHub
Actions delta, public Security UI screenshot, or completed upstream interaction**
implied by its presence. Publishing those artifacts requires the actual run.
