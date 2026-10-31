# SENTRYCHECK benchmark study plan (bench-0.1)

Owner: Amitesh Singh. Harness: `bench/` at version 0.1.0. This document is the human-readable
companion to `preregistration.json`; the JSON is what the tool enforces, this file is what explains it.

## 1. What is being measured, and what is not

Two claims are kept strictly apart, per PRD principle 4:

* **Compatibility** — did the sandbox change or refuse behaviour that the platform allows. This is
  decidable from exit codes, guest traces and stdout diffs, and it is what the verdict classes describe.
* **Performance** — how much slower or larger the scanner or the sandboxed workload is.

A desktop host with roughly 7 GiB RAM and no cpufreq governor control can support the first claim and
only weakly support the second. Every timing table in this study therefore carries the host record id
and the note that the governor is `null` — recorded, not guessed.

## 2. The verdict mapping (BT-01)

`bench/predict.py` turns a report into one of six classes with six ordered rules, first match wins:

| Rule | Class | Fires when |
|---|---|---|
| R1 | `hard-failure` | any finding of that severity (the schema forces a dynamic runsc/kata tier) |
| R2 | `silent-degradation` | any finding of that severity |
| R3 | `performance-regression` | any finding of that severity |
| R4 | `tolerated` | a recorded dynamic fallback observation with nothing above it |
| R5 | `compatible` | complete status, dynamic diff tier, nothing above compatibility-risk |
| R6 | `indeterminate` | everything else, including every `incomplete` and every static-only report |

The important property is the one that is *not* in the table: a static-only or incomplete report can
never become `compatible`. An absent measurement is reported as absent. `bench/analysis/prediction-map.json`
holds the machine-readable version, and `bench/analysis/predictions-retained.json` is the mapping applied
to the 34 retained reports that already existed before registration, as a fixed reference.

## 3. Corpus and splits

Cases come from `bench/cases`, and a case is registered only when its workload artifact is present on
this host and its digests re-verify. Three planned cases (two registry images, one eBPF workload) stay
unregistered until Phase 5 fetches them; they are not quietly dropped from the plan.

* development: `baseline-go`, `synthetic-baseline`
* validation: the four synthetic divergence and optional-syscall cases
* test: `postgres-18-io-uring`, scored once, after the rest of the analysis is written

The PRD's v1.0 corpus bar is 60 cases with 20 or more positives and documented kappa. This study has
seven registered cases and no human second rater. That bar is **unmet** and is reported as unmet.

## 4. Arms and ordering

`S1_full` (scanner with KB, static plus dynamic), `S2_static` (`--static-only`), `S3_native` (runc
reference run), `S4_sandbox` (digest-pinned runsc), plus the two declared baselines `B0_naive` and
`B5_justrun`. Within a case block the arms run ABBA and each run records `order_index` and
`order_pattern`, so a drift that correlates with position is visible rather than averaged away.

## 5. The knowledge-base age problem, registered before any run

`kb/snapshot.json` is dated 2026-09-26, which is older than the product's 30-day default. Under that
default **every** scan reports `incomplete`, which would make the whole corpus indeterminate for a
reason that has nothing to do with the workload. Two arms are declared:

* the compatibility arms pass `--max-kb-age-days 400`, so staleness cannot masquerade as behaviour;
* the staleness itself is measured as its own subject in a separate arm at the product default of 30,
  because "a stale KB silently degrades every verdict to incomplete" is a real product finding worth
  recording, and `tests/test_cli.py` and `tests/test_reports.py` now lock that path.

The scanner's `--no-cache` flag is always passed by the harness, so a warm cache cannot flatter a timing.

## 6. Statistics

Registered in `preregistration.json` and implemented in `bench/stats.py` with the standard library only:
Wilson and Clopper-Pearson for proportions, exact McNemar on discordant counts for paired binary
outcomes, Mann-Whitney U with tie and continuity correction plus Cliff's delta for distributions,
geometric mean for cross-workload aggregation, BCa bootstrap with 2000 fixed-seed replicates for ratios,
a cluster bootstrap by case so repetitions of one case do not outweigh another case, Holm step-down
across the hypothesis family, Cohen's and Fleiss' kappa for agreement, a two-sided DKW bound for
descriptive distribution comparison, and change-point detection that requires **two consecutive**
confirmations past a 20 percent practical threshold against a warm-up baseline.

Floats are rounded to six digits before they enter any hashed artifact. That is the difference between
"reproducible" and "reproducible on my machine".

## 7. What invalidates a run

Only infrastructure: a driver timeout, a missing report, a schema-invalid report, or digests that no
longer re-verify. An `incomplete` status is a genuine result of the tool's evidence policy and is scored
as such. A verdict that disagrees with its label is kept. A slow measurement is kept. Invalidated runs
stay in `bench/runs` with `valid: false` and an `invalid_reason`; nothing is deleted, and no run is
dropped because of its outcome.

## 8. Labels and the claims ceiling

Ground truth is raw exit codes, runsc debug logs and stdout diffs, adjudicated by a documented rule.
That is a **rule-adjudicator, not a second human rater**, so the study is capped at **L2** on the
`claims ladder` and every table states its ceiling. `bench label` records rater id, kind, class,
confidence, rationale and evidence per case, and computes agreement only between raters of the same kind.

## 9. Suite runbooks

| Suite | Where it runs here | Document |
|---|---|---|
| BM-01 / BM-04 / BM-14 | live native versus sandbox on the WSL host | `bench/specs/BM-01.md` |
| BM-02 | gcc corpus of known-behaviour binaries | `bench/specs/BM-02.md` |
| BM-03 | retained traces plus injected faults | `bench/specs/BM-03.md` |
| BM-07 | seeded mutation driver (cargo-fuzz deferred) | `bench/specs/BM-07.md`, `BM-07-fuzz.md` |
| BM-08 | size ladders to the documented caps | `bench/specs/BM-08.md` |
| BM-13 | two-interpreter byte-identical rebuild | `bench/specs/BM-13.md` |
| BM-09, BM-10, BM-12, arm64, Kata | not run on this machine | `bench/specs/NOT-RUN.md` |

## 10. Reproducing a number

Every published cell resolves to a recorded run:

1. `bench analyze` reads `bench/runs` only and fails on any statistic whose inputs have no `run.json`.
2. `run.json` names its artifacts by repo-relative POSIX path with their digests.
3. `python -m bench verify --root bench/runs` re-hashes every artifact and reports tampering.
4. `python -m bench verify --prereg` refuses an edited registration; the deviation log is append-only.

No table cell in this study was authored by hand.
