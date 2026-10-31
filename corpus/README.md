# Corpus and evaluation

`manifest.json` lists a reference workload set. Its ground-truth labels are **null until independently verified for the exact resolved image digest, runtime release, runtime options, and profile**. Generic runtime-suite compatibility documentation is not a label for a particular container image. Set `expected` to `true` for an independently established incompatibility or `false` for a compatible profile; record the labeling evidence alongside the manifest.

The PostgreSQL case uses PostgreSQL 18 built with `--with-liburing` and a profile that explicitly selects `io_method=io_uring`. Stock PostgreSQL 16 is not assumed to provide that backend. Build `corpus/postgres/Dockerfile` and export it as an OCI layout, or use `scripts/live-postgres.sh` on a dedicated Linux runner. The corpus image contains a build-time database seed; each measured run copies it to a fresh data directory, starts the server, and performs database I/O with a checked query result. One-time catalog initialization is outside that profile's measured coverage. Without a seed, the profile can initialize one but may exceed the bounded trace budget.

The synthetic C programs each isolate one mechanism. `io_uring.c` requires setup to succeed; `io_uring_fallback.c` tolerates failure and verifies classic I/O. `bpf_optional.c` deliberately tolerates denied BPF because the native host's security policy may also deny it. `behavior.c` prints a deterministic environment property to exercise output comparison; a different kernel release string is an observable difference, not by itself an isolation defect.

`go/main.go` is a small filesystem/concurrency baseline. Compile with `CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o workload corpus/go/main.go` and package it as `/workload`. The Python and Node profiles exercise filesystem operations and runtime features; the full upstream language regression suites are not bundled.

```sh
python scripts/evaluate.py --suite synthetic
python scripts/evaluate.py --suite live --binary ./target/release/sentrycheck --only python
```

The synthetic suite contains invented traces, clearly labeled as such, to test classifier behavior. Its metrics say nothing about production prediction accuracy. Live mode never substitutes synthetic traces when a runtime is missing. It records every incomplete result and excludes unlabeled cases from precision/recall. A failed labeled positive remains in the recall denominator even when its scan is incomplete.

Evaluation writes per-case reports, wall-clock timings, and per-category/per-evidence-tier metrics. Empty denominators are null, not invented perfect scores. Capture host kernel, runtime versions/flags, image digests, native baseline outcomes, and independent labels before presenting results as a research evaluation.

The PostgreSQL and Python/Node/Go profiles have been exercised against the pinned runtime; see [the validation record](../docs/VALIDATION.md) for actual outcomes and remaining release checks. Component tests and synthetic evidence do not substitute for live workload or cluster results.
