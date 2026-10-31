# Validation record

Executed locally on 2026-09-26. Results are separated by analyzer version and are bounded observations, not a production compatibility guarantee or a fully labeled research evaluation. The v0.2 review checked 25 primary-source responses; the v0.3 review added 13 targeted source files with saved revisions and hashes. See [DEEP-REVIEW.md](DEEP-REVIEW.md), [AUDIT-V03.md](AUDIT-V03.md), and [AUDIT-ADMISSION-V03.md](AUDIT-ADMISSION-V03.md).

## v0.4 offline frontend and renderer

The [v0.4 validation record](validation-v04.json) includes the final template/binary hashes and browser results. The Astro viewer is documented in [REPORT-VIEWER.md](REPORT-VIEWER.md).

- **34 Windows and 36 Linux Rust unit tests passed**, with formatting and Clippy checks passing on both targets. The existing analyzer was tested alongside the new renderer.
- **32 CLI tests ran on each platform:** 31 passed and one symlink-privilege case was skipped on Windows; all 32 passed on Linux. The 11 new render tests cover embedded-data fidelity, script-boundary escaping, invalid evidence, reduced SARIF consistency, KB matching, output preservation, and refusal to overwrite inputs or traverse output symlinks. Final Windows and Linux binaries both exported the retained io_uring report successfully.
- **10 browser checks passed** in installed Edge 153.0.4234.48. They include 12 malformed/contradictory local imports, unsafe citation schemes, script injection attempts, local import validation labels, KB architecture binding, SARIF unavailable-data states, search/filter/detail navigation, and pagination. A 600-candidate fixture initially rendered 20 rows. Desktop 1440 px and mobile 390 px layouts had no horizontal overflow. The final browser run recorded no JavaScript errors, external HTTP requests, or unexpected dialogs.
- **Astro 7.3.5 with Node 24.11.0 built successfully** and two consecutive builds produced identical embedded templates. The npm audit reported zero known vulnerabilities at the check time. The localhost development page also loaded without console or JavaScript errors; production exports retain the restrictive offline CSP.
- **The retained 50,297,090-byte PostgreSQL JSON opened in the final viewer through local file import.** Overview, findings, KB, and trace views rendered at most 446 DOM elements, with no script errors or external requests. An earlier full HTML export also opened successfully. Regenerating that approximately 40 MB export with the final template exceeded available disk space, so the final large-report check used the file picker. The validated smaller export is `artifacts/viewer-validation/io-uring.html`.

These are renderer and UI checks, not new compatibility measurements. The PostgreSQL and io_uring execution evidence retains its original v0.2/v0.3 dates and analyzer versions. No live workload or Kubernetes test was rerun for the frontend change, and other browser engines were not tested. Screenshots and detailed results are in `artifacts/viewer-validation/`.

## v0.3 component and evidence checks

- **34 Rust unit tests on Windows and 36 on Linux passed.** The Linux-only cases check mode-preserving materialization with symlink-safe cleanup and runtime deletion errors that must not be hidden by guessed state paths. Other new regressions cover quoted trace markers, forged task-name delimiters, missing entry/exit pairs, malformed return values, OCI configuration types, declared CPU requirements, concatenated gzip members, and KB constructor semantics. Formatting and Clippy with warnings denied passed on both targets.
- **21 CLI black-box tests passed on Windows and Linux.** New checks reject contradictory syscall/error totals and complete reports with discarded guest evidence. Six synthetic classifier scenarios also passed; they remain imported, incomplete evidence rather than new runtime observations.
- **54 retained native/gVisor traces replayed successfully, totaling 136,654 events.** Their hashes matched the original reports. The new parser preserved syscall and errno counts with no discarded or unfinished records. These include the previous Python, Node.js, Go, and PostgreSQL captures; replay did not rerun those applications or refresh their attestations.
- The Go suites and `go vet` passed. The actual Kubernetes API tests rejected missing/duplicate runtime snapshot entries and contradictory image completeness under strict policy, with no CEL expression warnings. Warn mode still allowed the dry run with a warning.
- The updated Go controller/probe passed the real node/CRI scenario again: verified gVisor, actual runc mismatch, missing-runtime warning, health-label removal, strict denial, and recovery. `artifacts/node-runtime/summary.json` records completion at `2026-09-26T16:57:52.326144+00:00`. The disposable cluster was stopped.

Offline KB importer checks passed, including four deliberately changed upstream inputs that must be rejected. Schema provenance, stated precisely because the original wording was looser than the evidence: `scripts/write_schemas.py` regenerates `schema/report.schema.json` and `schema/profile.schema.json` byte-identically, with pinned LF line endings so a Windows checkout cannot hash differently from a Linux one, and CI fails on any drift; `schema/runtime-comparison.schema.json` is hand-maintained and is checked against the report schema by `tests/test_matrix.py` rather than regenerated. Report schemas, Python compilation, shell syntax, and local documentation links were checked. Windows and Linux scanner/admission/probe binaries were rebuilt; their hashes are in `artifacts/review-v03/builds.json`.

The original v0.2 observations below remain historical evidence. Their larger workload executions are not counted as fresh v0.3 executions.

## v0.3 fresh runtime checks

After the cleanup correction and final rebuild, the five small profiles passed again: **30 fresh executions**, three native and three sandboxed runs per profile. Required io_uring returned native `0/0/0` and gVisor `42/42/42`; baseline, fallback, optional BPF, and deterministic-output fixtures returned `0/0/0` in both runtimes. The output fixture retained its expected divergence finding. Only required io_uring produced a hard-failure finding; timing observations remain uncontrolled and separate.

Every final comparison was complete, locally executed, and had zero discarded guest records. Reports, traces, and outputs are in `artifacts/review-v03/final-live/`. The [v0.3 validation record](validation-v03.json) identifies report hashes, tested binary hashes, runtime/profile identities, the distinct retained-trace replay, and the real node test. All five reports passed the public JSON schema and semantic validation with artifact hashes and reparsed traces. The Go CLI signed and verified both baseline and hard-failure reports, rejected a whitespace-modified report, and rejected signing a complete report with a discarded trace record. Results are in `artifacts/review-v03/final-contract-checks.json`. This rerun used gVisor 20260921.0 and runc 1.3.4 on the WSL kernel listed in the historical environment description below.

To retain a new small-workload run separately from older corpus evidence:

```sh
SENTRYCHECK_BIN="$PWD/bin/sentrycheck-linux" \
  SENTRYCHECK_LIVE_OUTPUT="$PWD/artifacts/review-v03/final-live" \
  bash scripts/live-smoke.sh
python scripts/record_validation.py --directory review-v03/final-live \
  --trace-replay artifacts/review-v03/trace-replay.json \
  --builds artifacts/review-v03/builds.json --output docs/validation-v03.json
```

## v0.2 component and contract checks

- The **26 Rust unit tests** passed on Windows and Ubuntu WSL. They cover malformed/overflowing ELF, bounded metadata parsing, instruction boundaries, conservative constant invalidation, x86/ARM64 extraction, OCI hardlink identity and overlays, path traversal, Linux filenames containing colons, profile validation, aligned/interleaved guest traces, causal attribution, and exact KB release applicability. Formatting and Clippy with warnings denied passed on both targets.
- The **19 CLI black-box tests** passed on Windows and Linux, including digest tampering, static/native-only incompleteness, cache reuse, failure versus tolerated fallback, output/timing comparisons, doctor modes, report validation, artifact containment, inconsistent outcome claims, regression comparison, SARIF mapping, and aggregate reports larger than one trace budget. Six explicitly synthetic trace scenarios also passed. Their metrics in `artifacts/evaluation/metrics.json` are classifier regressions, not real-world accuracy.
- The Go suites and `go vet ./...` passed, including signature/expiry/scan-age checks, invalid key sizes, digest/version/architecture binding, RuntimeClass handler/version drift, conflicting probes, earliest-evidence expiry, init/ephemeral image coverage, canary ID/readiness, subprocess limits, and cleanup retries. Exact-byte CLI verification accepted a real Python report and rejected a whitespace-modified copy. The actual **50,297,090-byte PostgreSQL report** also passed semantic validation, signing, and exact-byte verification.
- Generated reports passed the public JSON schema. Mapped and unmapped SARIF passed the official SARIF 2.1.0 schema and format checker. The output-overflow and native-trace-overflow live regressions retained incomplete observations with bounded artifacts and matching hashes; the latter retained a 33,554,432-byte prefix with 31,024 parsed events. Evidence is under `artifacts/review/` and `artifacts/trace-limit/`.

## v0.2 real workload comparisons

Ubuntu WSL used kernel `6.6.87.2-microsoft-standard-WSL2`, runc `1.3.4`, and checksum-verified gVisor **20260921.0** with its companion binaries. The scanner used fresh root filesystems, native guest strace, and runsc guest tracing with the systrap platform and no external networking. Each case ran three times per runtime.

| Workload/profile | Native exits | gVisor exits | Observed result |
| --- | --- | --- | --- |
| Minimal ELF baseline | 0 / 0 / 0 | 0 / 0 / 0 | No functional failure |
| Required io_uring | 0 / 0 / 0 | 42 / 42 / 42 | Hard failure, with a documented io_uring correlation |
| io_uring with classic-I/O fallback | 0 / 0 / 0 | 0 / 0 / 0 | Tolerated failure; no hard-failure finding |
| Optional BPF | 0 / 0 / 0 | 0 / 0 / 0 | No hard-failure finding |
| Deterministic environment-output fixture | 0 / 0 / 0 | 0 / 0 / 0 | Output difference detected; not independently an isolation defect |
| Python filesystem/SQLite/threads | 0 / 0 / 0 | 0 / 0 / 0 | No hard failure or silent output divergence |
| Node.js filesystem/crypto/timers | 0 / 0 / 0 | 0 / 0 / 0 | No hard failure or silent output divergence |
| Go filesystem/goroutines | 0 / 0 / 0 | 0 / 0 / 0 | No hard failure or silent output divergence |
| PostgreSQL 18.0, explicit io_uring backend | 0 / 0 / 0 | 42 / 42 / 42 | Native query assertions passed; sandbox startup failed |

Full digests, profiles, reports, syscall records, and referenced output are in `artifacts/live-validation/`, `artifacts/live-baselines/`, and `artifacts/live-postgres/`. All nine comparisons were rerun with v0.2, totaling **54 workload executions**, with complete, locally executed evidence. One observed workload failure is F1; syscall correlations, including unrelated failed probes such as rseq, are separate unconfirmed compatibility risks. The recorded report hashes and analyzer versions are in [validation-summary.json](validation-summary.json).

The PostgreSQL image was built from the official 18.0 source tarball with SHA-256 `0d5b903b1e5fe361bca7aa9507519933773eb34266b1357c4e7780fdee6d6078` and `--with-liburing`. Its manifest digest is `sha256:85f15ac1e4ab8f4fb0beaf9e3413505e68331a6d72ba5cf0d6bb1fe3fd4d7efb`. Each measured run copied a fresh build-time database seed, started the server, and attempted table I/O with a checked query result. One-time catalog initialization is outside this profile's measured coverage; tracing it exceeded the default capture budget and was correctly recorded as incomplete during development.

Timing findings were retained separately. These local debug-build runs included runtime/tracer startup, registry acquisition where applicable, and uncontrolled host load. They are not controlled performance benchmarks or evidence of a netstack-specific regression. The Python/Node/Go profiles are representative exercises, not the complete upstream runtime regression suites.

## v0.2 Kubernetes checks

The CEL policies passed against a real Kubernetes **v1.35.0+k3s1** API server: immutable digest/report requirements, runtime selection, init-container coverage, confirmed-failure denial, and warn-only behavior. API-server type checking returned no expression warnings. Artifacts are in `artifacts/admission-api/`.

`scripts/test-node-runtime-live.sh` **passed** on a real disposable Kubernetes node with containerd 2.1.5. It verified a gVisor canary, detected a real runc canary as `isolation-mismatch`, published a Warning when the configured binary was missing, removed the protected node health label, denied workload admission, and admitted it again after successful runtime recovery. The completion record and supporting objects are in `artifacts/node-runtime/summary.json` and its directory. The controller and probe ran with dedicated Kubernetes service-account credentials; workload admission checks used server dry-run. The cluster was stopped after the test.

The first v0.2 node attempt exposed concurrent cleanup by kubelet and the probe: containerd logged duplicate StopPodSandbox requests and a closed shim connection. The probe correctly remained unverified. After adding bounded idempotent cleanup with exact-ID absence verification, the full rerun passed. The test now replaces stale success summaries with explicit running/failed/passed status. First-attempt evidence remains in `artifacts/review/canary-cleanup-first-attempt.json` and its associated log.

The optional Kubernetes 1.36 mutation policy, Kata VM execution, controller-outage operational recovery, and a larger independently labeled corpus remain separate validation work. No public deployment, upstream issue, paper upload, or conference submission has been performed.
