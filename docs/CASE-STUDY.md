# Case study: required io_uring versus tolerated probing

This case study describes **retained local evidence**, not a production incident or a new v0.5 benchmark. SENTRYCHECK 0.2.0 compared nine workload profiles under runc and gVisor on 2026-09-26. Version 0.3.0 reran the five small profiles and replayed the larger workload traces; version 0.4.0 added and validated the offline report viewer. The exact scopes are in [VALIDATION.md](VALIDATION.md).

## Question and experimental identity

Can a scanner distinguish a workload that requires a currently unavailable interface from a workload that probes that same interface and completes using another path?

The environment was Ubuntu WSL with kernel `6.6.87.2-microsoft-standard-WSL2`, runc **1.3.4**, and gVisor **20260921.0**, using systrap. Native execution used guest strace; sandbox execution used runsc guest tracing. Each comparison used three repetitions per runtime with fresh root filesystems, a pinned profile and no external workload networking. These are bounded developer-machine observations, not a controlled performance study.

| Profile | Native exit codes | gVisor exit codes | Functional interpretation |
| --- | --- | --- | --- |
| Required io_uring fixture | 0 / 0 / 0 | 42 / 42 / 42 | Observed workload failure; documented syscall correlation is separate from causality. |
| io_uring with classic-I/O fallback | 0 / 0 / 0 | 0 / 0 / 0 | The exercised profile tolerates the interface failure; no hard-failure finding. |
| PostgreSQL 18.0, explicit io_uring | 0 / 0 / 0 | 42 / 42 / 42 | Native database assertions pass; sandbox startup fails. |
| Python filesystem/SQLite/threads | 0 / 0 / 0 | 0 / 0 / 0 | No hard failure or silent output divergence in this profile. |
| Node.js filesystem/crypto/timers | 0 / 0 / 0 | 0 / 0 / 0 | Same bounded functional result. |
| Go filesystem/goroutines | 0 / 0 / 0 | 0 / 0 / 0 | Same bounded functional result. |

The baseline, optional-BPF and deterministic-output fixtures complete the nine-profile corpus. The output fixture reports its intended output difference; that observation does not independently establish an isolation defect. Timing findings are retained separately and must not be presented as a netstack benchmark.

## PostgreSQL trigger and reproduced result

The database image was built from the official **PostgreSQL 18.0** source tarball using `--with-liburing`. PostgreSQL documents that this option enables io_uring support, and that `io_method=io_uring` explicitly selects it; the ordinary default is `worker`. This case therefore does not establish that an unmodified PostgreSQL image defaults to the failing path.

- Source tarball SHA-256: `0d5b903b1e5fe361bca7aa9507519933773eb34266b1357c4e7780fdee6d6078`.
- OCI manifest digest: `sha256:85f15ac1e4ab8f4fb0beaf9e3413505e68331a6d72ba5cf0d6bb1fe3fd4d7efb`.
- Profile: [postgres-io-uring.toml](../profiles/postgres-io-uring.toml), SHA-256 `9f4d17fd687ef0ed6ba0a0e89d6b80eb9eec63d0ca5b722269a06a87688696da`.
- Original report SHA-256: `403568c3fa7abcff98dd565639fe331d034eb5a8fff2876726b4de06f7cda7f2`, recorded in [validation-summary.json](validation-summary.json).

For each observation the profile copied a fresh build-time database seed, started PostgreSQL with `-c io_method=io_uring`, created a 10,000-row table, issued `CHECKPOINT`, and asserted that `SELECT sum(i)` returned `50005000`. A start failure produces profile exit code **42**. This is the profile wrapper’s code, not an assertion that the PostgreSQL executable intrinsically exits with 42 or crashes.

Native runs passed the database assertion. The runsc runs failed server startup. The scanner reports the changed workload outcome and supplies syscall/KB context without claiming that every failed probe in the trace caused the failure. The pinned gVisor compatibility guide states that io_uring is disabled by default and that its opt-in implementation is limited; results depend on that runtime configuration.

One-time catalog initialization is outside the measured profile. An earlier attempt to trace initialization exceeded the capture budget and was correctly retained as incomplete. The final profile uses seed copies so database startup and I/O can be evaluated within the capture budget. Report and artifact validation must be retained alongside this coverage qualification.

## What the fallback comparison adds

Both the required and fallback-enabled fixtures can expose an io_uring capability candidate during static inspection. Their runtime behavior differs: the fallback fixture passes its profile, whereas the required fixture does not. This directly demonstrates why symbol or syscall presence alone cannot justify a hard-failure verdict. It does not prove a general fallback guarantee for glibc, liburing or an arbitrary application version.

Version 0.3’s fresh run repeated all five small profiles, totaling **30 executions**. Separately, its parser replayed **54 saved traces** from the previous corpus and preserved syscall/errno totals across **136,654 events** without discarded or unfinished records. Replay validates parsing of retained evidence; it does not refresh the original workload execution or attestation.

## Runtime identity demonstration

The Kubernetes test used a real disposable **v1.35.0+k3s1** API server and containerd **2.1.5**. Real CRI canaries exercised gVisor and runc. The probe detected a mismatched runtime type; a missing configured binary produced a Warning, removal of the protected health label and strict admission denial. Restoring healthy runtime observations allowed admission again. Admission requests were server dry-runs, while canaries actually executed. The v0.3 record reports completion at `2026-09-26T16:57:52.326144+00:00`.

This demonstrates detection of runtime mismatch and missing-runtime drift. It does **not** demonstrate an automatic Kubernetes fallback from Kata to runc: the official RuntimeClass contract normally fails an unsupported handler with an event. A CRI canary also does not constitute hardware attestation or proof that all later Pods execute under the same runtime.

## Limits and next measurements

The profiles were selected and labeled by the implementer, not an independent evaluator. Nine selected workloads cannot establish production precision, per-category recall or absence of false positives. Java/PHP suites, Kata VM execution, arbitrary service traffic and controller-outage recovery are outside these results. Startup, tracing and uncontrolled host load affect the recorded durations.

The next benchmark must publish experimental units, workload digests, profile/runsc configuration, host conditions, warm/cold cache treatment, repeated measurements, exclusions and confidence intervals. Any new results belong in a separately versioned record before being added to this case study or the paper. The current evidence supports the narrow conclusion that the tool reproduced the required-I/O failure while preserving successful fallback and baseline observations under the tested profiles.

Primary documentation: [PostgreSQL 18 resource settings](https://www.postgresql.org/docs/18/runtime-config-resource.html#GUC-IO-METHOD), [PostgreSQL build options](https://www.postgresql.org/docs/18/install-make.html), [pinned gVisor compatibility guide](https://github.com/google/gvisor/blob/26f3455a4cb9a377354c33aeac049080a077c79c/g3doc/user_guide/compatibility.md), and [Kubernetes RuntimeClass](https://kubernetes.io/docs/concepts/containers/runtime-class/). Retrieval records and corrections are in [the v2 audit](../research/v2-PRD-AUDIT.md).
