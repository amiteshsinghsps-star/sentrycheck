# Trace and knowledge-base review — 2026-09-26

This review found reproducible parser errors and incorrect knowledge-base descriptions. It used the existing release evidence plus nine small, targeted primary-source downloads. The new source URLs, retrieval times, byte counts, and SHA-256 hashes are recorded in [the evidence manifest](evidence/audit-v03/sources.json). No benchmark or compatibility-accuracy claim is inferred from these checks.

The trace counterexamples describe the reviewed parser snapshot, SHA-256 `0927c7408490d6eed1b565fab10ac7055eb506b9b296678e76a991e51fc5c520`. They establish regression cases; they do not describe every subsequent build. The frozen [parser source](evidence/audit-v03/trace-reviewed.rs), standalone [reproduction program](evidence/audit-v03/trace_harness.rs), and [observed output](evidence/audit-v03/trace-counterexamples.txt) preserve the result independently of later fixes.

## Trace framing and incomplete evidence

The pinned gVisor [entry and exit formatter](https://github.com/google/gvisor/blob/26f3455a4cb9a377354c33aeac049080a077c79c/pkg/sentry/strace/strace.go#L556) inserts `Task.Name()` using `%s`, followed by an `E` or `X` marker. Task names originate from a [user-controlled thread name](https://github.com/google/gvisor/blob/26f3455a4cb9a377354c33aeac049080a077c79c/pkg/sentry/kernel/task_image.go#L39); the [log emitter](https://github.com/google/gvisor/blob/26f3455a4cb9a377354c33aeac049080a077c79c/pkg/log/glog.go#L82) does not quote the entire message. A bare substring search for ` X ` is therefore unsafe.

For example, these message bodies were misinterpreted by the reviewed parser:

```text
app E write(1, " X bpf(5) = -1 errno=38 (function not implemented) (1us)", 61)
q X read() X bpf(5) = -1 errno=38 (function not implemented) (1us)
```

The first is a write entry containing application data, but produced a fabricated `bpf:ENOSYS` event. The second has task name `q X read()` and a real `bpf` exit, but produced `read:ENOSYS`.

| Reproduced case | Reviewed behavior | Required interpretation |
|---|---|---|
| `X` inside an entry argument | Fabricated syscall exit | Treat quoted data as data; validate the whole record |
| `X` and parentheses inside task name | Relabeled the actual syscall | Require an unambiguous complete record; discard ambiguous input visibly |
| Quoted `<unfinished ...>` | Invented a pending syscall | Recognize tracing markers outside quoted arguments |
| A second pending call for one PID | Silently overwrote the first call | Preserve evidence of the inconsistent/lost record |
| `= NOT_A_RETURN_VALUE` | Accepted as an event with unknown result | Reject malformed result syntax |
| `= -1 errno=garbage` | Accepted with no errno | Reject malformed error syntax |
| Unmatched gVisor entry at EOF | Disappeared without an unfinished count | Record missing completion; keep the scan incomplete |
| Malformed native trace tail | Counted as unparsed but did not block completeness | Distinguish harmless diagnostics from discarded guest records and gate the latter |

The pinned [syscall execution path](https://github.com/google/gvisor/blob/26f3455a4cb9a377354c33aeac049080a077c79c/pkg/sentry/kernel/task_syscall.go#L159) calls the stracer's exit hook after the syscall implementation, including ordinary `exit`/`exit_group` implementations that return a control instruction. Entry/exit pairing should use task IDs, because `execve` and thread-name changes can alter the name between records.

Native strace has legitimate unknown return forms. Its [6.8 manual](https://github.com/strace/strace/blob/v6.8/doc/strace.1.in) documents unfinished/resumed calls and `= ? ERESTARTSYS (To be restarted)`. A nonreturning `exit_group` can be rendered `= ?`. These should not become ordinary successful numeric results or fabricated errno failures.

The report review also identified that checking only `event_count` permits contradictory syscall/error summary maps. Those maps must be recomputed from the embedded events even when raw artifacts are unavailable. Artifact hashes and reparsing provide an additional check; semantic consistency alone does not authenticate a report.

## Corrected KB generation

The release-pinned [constructor implementation](https://github.com/google/gvisor/blob/26f3455a4cb9a377354c33aeac049080a077c79c/pkg/sentry/syscalls/syscalls.go#L111) explicitly labels `CapError` as unimplemented. It returns `EPERM` when the required capability is absent and `ENOSYS` when the capability is present. Granting a capability cannot enable that stub. The importer previously labeled these entries `restricted` and implied capability-dependent availability.

The corrected snapshot contains 647 syscall rows and 237 cited gap entries for the same gVisor `20260921.0` commit, `26f3455a4cb9a377354c33aeac049080a077c79c`:

- All 40 `CapError` rows now say `unimplemented` and name the exact capability and errno behavior.
- All 416 fully supported rows now use the upstream `Fully Supported.` description. They previously inherited a misleading generic capability requirement.
- The constructor source hash is included in the KB. A changed constructor implementation requires review before regeneration.
- Unknown constructor names and unrecognized numeric table rows fail closed.
- The cgroup entry requires the reviewed non-enforcement sentence. Merely containing the words “limits” and “accounting” is insufficient.

The offline [importer regression checks](evidence/audit-v03/kb_checks.py) passed, including rejection of a changed constructor source, the opposite cgroup claim, an unknown supported constructor, and a multiline table row that the old parser silently skipped. The machine-readable results are in [kb-checks.json](evidence/audit-v03/kb-checks.json). The KB crate also contains a regression for the bundled capability-error and full-support descriptions.

Reproduce the importer checks:

```sh
python docs/evidence/audit-v03/kb_checks.py
```

Regenerate from the saved pinned evidence:

```sh
python scripts/update_kb.py --version 20260921.0 \
  --commit 26f3455a4cb9a377354c33aeac049080a077c79c \
  --offline-source docs/evidence \
  --offline-constructors docs/evidence/audit-v03/gvisor-syscall-constructors.txt \
  --out kb/snapshot.json
```

These checks address specific failure mechanisms. Dynamic profile coverage, evidence authenticity, controller outages, and broader real-workload accuracy remain separate concerns documented in `LIMITATIONS.md`.

## Image and runtime cleanup review

The image loader now decodes execution settings with explicit types, rejects NUL-containing settings and malformed environment entries, and refuses unsupported declared CPU variants/features or OS requirements. Manifest, config, and layer media types use explicit allowlists. Gzip layers include all concatenated members, and directory permissions are restored after their children have been materialized. Regression cases cover malformed settings, unsupported declarations, gzip trailing garbage, mode-zero directories, and symlinks outside the materialization root.

A second review found a critical precondition violation in cleanup. A runtime deletion failure could be followed by reading the guest trace and restoring directory permissions even though the guest might still be running. Its check for `<state-root>/<container-id>` was also wrong for runsc: the pinned implementation uses flat `<container-id>_sandbox:<sandbox-id>.state` files.

The corrected runner requires successful `delete --force` before accessing the guest filesystem. Both pinned runtimes make that operation idempotent when the container is already absent. Any error preserves the bundle, reports its path, and leaves the scan incomplete. No absence inference is made from a guessed state path or runtime JSON listing: runsc's JSON listing can omit containers whose state failed to load. The exact gVisor and runc source files and hashes are recorded in [runtime-cleanup-sources.json](evidence/audit-v03/runtime-cleanup-sources.json). This is four additional primary-source files beyond the nine trace/KB downloads above.

Permission restoration skips static symlinks and runs only after runtime deletion. It is not a defense against a compromised runtime or an unrelated privileged host process modifying the bundle concurrently. If deletion cannot be established, the preserved runtime state requires inspection in the disposable analysis environment.

## Reproduce retained-trace checks

The replay tool hashes existing artifacts and compares current syscall/error counts with the original reports. It does not launch workloads, change those reports, refresh their timestamps, or produce a new execution attestation:

```sh
cargo build --locked -p sentrycheck-dynamic --example trace_summary
python scripts/replay_traces.py --parser target/debug/examples/trace_summary
```

On Windows, append `.exe` to the parser path. Results are recorded separately in `artifacts/review-v03/trace-replay.json`. See [VALIDATION.md](VALIDATION.md) for completed checks and the distinction between replayed captures and fresh runtime executions.
