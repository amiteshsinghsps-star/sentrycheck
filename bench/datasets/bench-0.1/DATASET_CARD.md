# Dataset card - bench-0.1

## Scope

Compatibility and evidence-tier behaviour of the SENTRYCHECK scanner against a sandboxed Linux runtime (gVisor runsc, systrap), plus how much of a verdict depends on having dynamic evidence. It does not cover Kubernetes admission, arm64, Kata Containers, or bare-metal timing.

## Collection

59 runs recorded by harness 0.1.0 on host ids hwsl2-1. Every run is an actual scanner execution whose report, traces, outputs and logs are digest-pinned in bench/runs/index.json; no measurement in this bundle was typed in.

## Labels and raters

9 adjudicated labels. Both raters are documented deterministic rules over independent evidence (rater A: the knowledge-base citations; rater B: raw exit codes, stdout digests and sandbox refusals). There are no human raters in this dataset, and the agreement statistics must be read with that in mind.

## Splits

unrecorded=9

## Coverage and what is missing

Suites with recorded runs: BM-01, BM-04, BM-14. Everything else is enumerated in bench/analysis/tables/not-run.csv, which the analyzer generates from the store rather than from a hand-maintained list.

## Known biases

Author-selected cases with no sampling frame; one runtime family (gVisor systrap); one architecture (amd64); one host class (WSL2 on an uncontrolled desktop); a rule-based labeler that cannot see a class its rules do not describe; per-case n of 1 to 4, so most confidence intervals are wide.

## Measurement conditions

Native and sandbox repetitions interleaved per case (ABBA for the ablation arms, AB for the stability arms); scan timings exclude staging; the record's environment block carries load, free disk and clock sync, and preflight output is stored per run under logs/preflight.json.

## Claims ceiling

L2. Compatibility claims rest on recorded execution evidence, but with no independent human rater no claim in this dataset supports L3 or above.

## Intended use

Measuring whether a runtime-compatibility scanner's verdict matches observed sandbox behaviour, and how much of that verdict depends on the evidence tier available.

## Unintended use

Not a security guarantee, not a production capacity benchmark, not a certification of any workload, and not a comparison against other tools (none were run here).

## Licenses

See license-manifest.json. Workload layers are pinned by digest and not redistributed; reference documents are cited by URL and digest under their publishers' terms.

## Citation

SENTRYCHECK benchmark harness 0.1.0, dataset bench-0.1, collected 2026-10-31.

## Versioning

Append-only. A bad run keeps its place with valid=false and an invalid_reason; the dataset version changes when the schema or the case registry changes, not when a number is revised.

## Verification

`python -m bench verify --all` re-hashes every stored artifact, `python -m bench verify --prereg` checks the sealed pre-registration, and the checksum file in this directory re-hashes the bundle against the store it points at.

## Suite inventory

| suite | runs | valid | invalid | cases |
| --- | --- | --- | --- | --- |
| BM-01 | 9 | 9 | 0 | 9 |
| BM-04 | 36 | 36 | 0 | 9 |
| BM-14 | 14 | 14 | 0 | 7 |

## Groups in this bundle

| group | files | travels with the bundle |
| --- | --- | --- |
| analysis | 22 | yes |
| baselines | 18 | yes |
| cases | 9 | yes |
| hosts | 2 | yes |
| labels | 9 | yes |
| runs | 1830 | referenced |
| schemas | 4 | yes |
| sources | 1 | referenced |
| workloads | 43 | referenced |

