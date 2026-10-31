# Workload profiles and captured evidence

A profile is JSON or a deliberately small TOML subset: top-level keys, quoted strings, booleans, numbers, and one-line JSON-compatible arrays. Unsupported keys/syntax are rejected. Multiline scripts can be represented as JSON strings containing `\n`, or placed in an image and invoked by path.

```toml
name = "service-regression"
description = "Exercise the public operation and assert deterministic output."
command = ["/usr/local/bin/integration-check", "--small-data"]
env = ["LC_ALL=C", "TZ=UTC"]
timeout_seconds = 30
repetitions = 3
expected_exit_code = 0
compare_stdout = true
compare_stderr = false
timing_ratio = 2.0
timing_min_native_ms = 100
coverage = "representative"
```

Commands are argument arrays. No shell is inserted automatically; use `['/bin/sh','-ec',...]` (with double quotes in TOML arrays) when the profile explicitly requires a shell. The image ENTRYPOINT/CMD is used when `command` is empty. The image's environment and working directory are preserved; profile environment entries override matching image keys. The image user is resolved from numeric IDs or its passwd/group files.

Each repetition gets a fresh rootfs, so database/service profiles must initialize their own data and shut down their subprocesses. Server startup alone is not representative coverage. Use a shell trap or in-image test harness to cleanly stop services. External networking and host bind mounts are not exposed. A profile can print normalized filesystem/resource measurements and enable stdout comparison to detect silent differences.

Only compare stdout/stderr when it is deterministic. When every repetition within a runtime satisfies the profile, changes in its compared output make the scan incomplete. Varying diagnostics from failed repetitions do not invalidate the observed failure. Timestamps, random IDs, and environment-specific addresses should be normalized by the workload's test harness, not silently ignored by the scanner. Timing findings require at least three separated samples and include runtime/tracer startup overhead.

For offline analysis, `--evidence evidence.json` imports this format:

```json
{
  "schema_version": "1.0",
  "image_digest": "sha256:<64 lowercase hex characters>",
  "target_runtime": {"name": "gvisor", "version": "20260921.0", "architecture": "amd64"},
  "profile": {"name": "example", "command": ["/workload"], "coverage": "representative"},
  "profile_sha256": "sha256:<canonical full profile hash>",
  "native": [{
    "runtime": "runc", "runtime_version": "runc version 1.3.4",
    "exit_code": 0, "timed_out": false, "duration_ms": 100,
    "stdout": "native.stdout", "stdout_sha256": "sha256:<hash>",
    "stderr": "native.stderr", "stderr_sha256": "sha256:<hash>",
    "trace": "native.trace", "trace_sha256": "sha256:<hash>", "trace_kind": "strace-guest"
  }],
  "sandbox": []
}
```

The example abbreviates digests and profile defaults; use `scripts/make_fixtures.py` to see a complete valid bundle. The profile hash is SHA-256 over the compact JSON serialization of **all** WorkloadProfile fields in the order defined in `sentrycheck-core/src/model.rs`. Whitespace in the manifest itself is irrelevant. Artifact hashes cover raw bytes. Paths are relative to the manifest and must not escape or traverse symlinks.

Sandbox records use runtime `gvisor`, the exact target version, and `runsc-guest`; externally collected Kata records use runtime `kata` and `strace-guest`. Only gVisor's `X` guest syscall records are accepted as runsc events. Where task IDs are present, `E`/`X` records are paired to detect missing completions. Native unfinished/resumed calls are paired by thread ID. Balanced argument parsing keeps quoted tracing markers from becoming events. Malformed or ambiguous guest records increment `discarded_guest_records` and keep the scan incomplete; recognized log chatter is counted separately as `diagnostic_lines`. The supported runsc framing is tested against the pinned runtime release. Host syscall traces of runsc are never accepted as guest evidence.

Imported evidence is labeled `imported-user-supplied`. Hash consistency does not prove execution origin. A reproduced failure can still exit 1; otherwise the imported scan exits 2 and is not eligible for signing as a trusted clean report.

These trace formats identify syscall names, not originating ELF file offsets. Consequently `capability_set_only` retains every un-attributed static site even when that syscall name appears in `dynamic.exercised_syscalls`. Associated static evidence in a finding is a correlated candidate, not a claim that the exact site was exercised.
