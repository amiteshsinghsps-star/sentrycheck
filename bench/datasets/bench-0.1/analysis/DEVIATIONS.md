# Deviation log

Append-only. `bench/analysis/preregistration.json` is sealed by digest, so a registered value is never
edited in place; a departure from it gets an entry here with the date, the affected hypothesis or
requirement, what changed, why, and how it should be read.

`python -m bench verify --prereg` fails if sealed registration content changes; this file is the only
place allowed to grow.

## D1 — 2026-10-31 — harness package layout (BH-01, PRD section 6.2)

**Registered as:** `bench/py/{cli,schema,store,host,preflight,fetch,predict,label,analyze,publish,faults,adversarial}.py`.
**Actual:** flat modules at `bench/*.py` (`bench/cli.py`, `bench/store.py`, `bench/runner.py`, …) with tests
under `bench/tests/`.
**Why:** a nested `bench/py/` package needs either a `sys.path` hack or its own `setup.py` to be importable as
`python -m bench`; the repository already ships stdlib-only tooling flat under `scripts/`, and the harness is
imported from those tests. Keeping one import root means the same command works on Windows Python 3.14 and WSL
Python 3.12 with no environment setup, which is what NF-03 and BH-01 actually require.
**Effect on interpretation:** none on the measurement. Module names in this plan and in `docs/` map one to one;
`suite`, `baselines`, `fetch`, `label`, `analyze`, `publish`, `faults`, `adversarial` and `sources` are added as
flat modules as their phases land.

## D2 — 2026-10-31 — two runs recorded before the seal

**What:** `bench/runs/20261031-hwin-1/synthetic-baseline/` and `…/synthetic-required-io-uring/` were written by
the Phase 2 store check, roughly 20 minutes before `preregistration.json` was sealed.
**Why:** the content-addressed store, the deterministic index and `bench verify` had to be exercised against real
scanner output before the registration could be trusted to guard anything; a synthetic fixture would not have
tested the digest path.
**Effect on interpretation:** both are `static-only` scans of a development case with no hypothesis attached, and
neither enters any scored table. They are infrastructure proofs. Anyone auditing the ordering can see the recorded
`started_at` of both runs precedes `registered_at`, and the sealed digest covers the registration, not these runs.
No case was selected, excluded or relabelled using their outcome.

## D3 — 2026-10-31 — BM-07 fuzz targets reduced to a seeded mutation driver

**Registered as:** H4, crash and limit-violation accounting over a seeded mutation corpus.
**Actual for this study:** the driver runs, `cargo-fuzz` does not. The workspace builds `--offline --locked`, has
no `fuzz/` directory, and cargo-fuzz needs a nightly toolchain plus a network fetch to create one.
**Why:** attempting it would have spent the session on a toolchain install rather than on measurement, and a
half-provisioned fuzz target produces numbers nobody can re-run.
**Effect on interpretation:** H4's result covers parser-level malformed input handling under the documented limits
only. It is **not** coverage-equivalent to greybox fuzzing, and the acceptance criterion "8 or more fuzz targets,
zero open crashers" from the PRD's BM-07 row is reported as unmet in `bench/specs/NOT-RUN.md` alongside the
runbook at `bench/specs/BM-07-fuzz.md`.

## D4 — 2026-10-31 — B0 and B5 baselines are harness reimplementations

**Registered as:** the naive and just-run baselines in `arms`.
**Actual:** `bench/baselines.py` implements B0 as "flag any binary mentioning a syscall the runtime does not
implement" and B5 as "run once, read the exit code", against the same case set and the same recorded runs.
**Why:** the PRD names these as ablations, not as specific external tools; running anything else would change two
variables at once.
**Effect on interpretation:** the H1 comparison is a controlled ablation of the scanner's own evidence, not a
comparison against published third-party tools. Any claim of the form "SENTRYCHECK beats tool X" is out of scope
for this study.

## D5 — 2026-10-31 — two development cases became available after the seal (BM-01, BM-04, BM-11)

**Registered as:** `corpus.ready_cases` — seven cases; `corpus.blocked_cases` — `registry-python`, `registry-node`,
`cilium-ebpf-optional`.
**Actual:** `bench fetch` resolved and pinned `docker.io/library/python:3.12-slim`
(`sha256:1148dbb01461…`) and `docker.io/library/node:22-alpine` (`sha256:025b8e975a61…`), so both registry cases
are now registrable and `bench/cases/` holds **nine** cases. `cilium-ebpf-optional` stays blocked.
**Why:** the pre-registration could only list what existed on the host at the time; refusing to use two images that
the registration itself told us to go and fetch (`corpus.blocked_reason`) would be worse than recording the change.
**Effect on interpretation:** both cases carry `split: development`, so **the validation and test splits are
unchanged** and no scored hypothesis gains or loses a case. They are used for static-extraction and report-size
checks (BM-02, BM-11) and as additional live-ablation inputs in development only. Any table that cites them is
marked "post-registration development case". `python -m bench verify` re-hashes both pinned layouts, so a replaced
image would fail the run rather than silently change a verdict.

