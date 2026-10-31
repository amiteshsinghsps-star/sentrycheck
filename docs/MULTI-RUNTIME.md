# Comparing gVisor and Kata observations

SENTRYCHECK can combine separately collected native-versus-gVisor and native-versus-Kata reports for the **same OCI image digest, architecture and workload profile**. The schema 1.1 comparison envelope preserves the existing schema 1.0 reports, their individual evidence tiers, citations and incomplete reasons.

This is two experiments with separate native baselines. It does not claim a shared native execution or invent a `dynamic-three-way-diff` evidence tier. Host configuration and runtime settings are not fingerprinted, so the result provides observations without recommending a runtime or attributing differences to a particular subsystem.

## Scan both targets

```sh
sentrycheck scan ./image-oci --runtime gvisor,kata \
  --gvisor-version 20260921.0 --kata-version 3.3.0 \
  --profile profiles/python.toml --format json --output matrix.json
```

Versions must be provided separately; `--version` cannot name both projects' releases. The CLI runs its existing single-runtime scanner twice, sequentially, with runtime-specific artifact directories. Native execution is repeated, so the total cost includes two baseline runs. A shared ELF cache can reduce the second static pass.

Registry references are resolved independently by those scans. Prefer a digest-pinned image or local OCI layout. If the digest changes between executions, composition fails rather than presenting two different images as a runtime comparison.

**The existing live runner supports runc/runsc. Live Kata execution is not implemented by this envelope.** A Kata target without usable guest observations remains explicitly incomplete. Installing a binary named `kata-runtime` does not establish that a VM was used or that guest syscalls were traced. Actual Kata commonly requires a configured CRI shim, guest tracing and hardware virtualization/KVM support; it cannot be promised on every CI runner. Use verified externally collected Kata guest evidence through the supported import path below until a live adapter is validated.

```sh
sentrycheck scan ./image-oci --runtime gvisor,kata \
  --gvisor-version 20260921.0 --kata-version 3.3.0 \
  --gvisor-evidence captures/gvisor/evidence.json \
  --kata-evidence captures/kata/evidence.json \
  --format json --output matrix.json
```

Both imported evidence paths are required together. Existing bundle checks bind image digest, profile, target release, architecture and capture hashes. Kata evidence must contain **guest** `strace-guest` records, not host shim/VM-launcher traces. Imported provenance remains visible and produces exit 2 unless a selected observed failure takes precedence. Fabricated fixtures used by the tests are not Kata validation results.

`--static-only` works for both targets but never produces a confirmed compatibility result. A missing native or sandbox run is a limitation, not a successful workload result.

## Compose existing reports

```sh
sentrycheck report compare gvisor.json kata.json --format json --output matrix.json
```

Input order is accepted either way; output is ordered gVisor then Kata. Composition requires one report for each runtime, explicit version identifiers, the same non-null image digest and architecture. If both reports have dynamic evidence, their exact profile digests must match. Mismatched identities/profiles are errors; a missing dynamic report can still appear as an explicitly incomplete comparison.

The cross-runtime outcome comparison additionally requires complete run counts, intact guest traces, successful native baselines and matching native runc versions. Declared deterministic stdout/stderr must be stable and equal across the two native baselines. Otherwise `cross_runtime.comparable` is false and the difference fields are null.

When comparable, `outcome_difference` compares the distributions of recorded exit statuses/timeouts. Stdout/stderr differences are computed only for profile-declared deterministic streams stable within each sandbox. A null value means unavailable or unasserted, not equal. Failed workloads can have different diagnostics; a hash difference does not establish a silent correctness defect or its cause. Timing samples are included for inspection; unequal tracing/startup costs and separate execution environments prevent a causal performance ranking.

The envelope retains per-report findings. It does not promote syscall correlations into new causal findings, and it does not replace node runtime-identity checks.

## Extract for existing tools and admission

```sh
sentrycheck report extract matrix.json --runtime gvisor --output gvisor-extracted.json
sentrycheck report validate gvisor-extracted.json --format json
sentrycheck report render gvisor-extracted.json --output gvisor.html
```

Extraction revalidates both embedded reports and recomputes the entire envelope, including summaries, ordering and per-report digests. Contradictions or altered summary fields fail closed. It writes the selected schema 1.0 JSON object, compatible with existing validation, SARIF, viewer and admission tooling.

**Sign the extracted bytes again before admission.** JSON reserialization does not preserve a signature over the original report-file bytes. Matrix `report_digests` identify compact `serde_json` serialization of the embedded objects, not original files; they provide consistency checking, not authentication. Both original and extracted reports remain unauthenticated until verified through the Go signing/verification chain.

Compare and multi-runtime scan use the usual gate priority: **1** for a selected finding, otherwise **2** for an incomplete comparison, otherwise **0**. `--fail-on` defaults to `hard-failure`. Extract returns **0** when export succeeds regardless of the selected report's compatibility status; **2** indicates an error. Matrix output is bounded by the same aggregate 128 MiB report limit as other report tools.

## Schema and testing

`schema/runtime-comparison.schema.json` documents the envelope. Its `urn:sentrycheck:report:1.0` reference is resolved offline to `schema/report.schema.json`; no network lookup is necessary. The CLI additionally checks semantic consistency beyond JSON Schema.

```sh
cargo build -p sentrycheck-cli --locked
python -m unittest discover -s tests -p test_matrix.py -v
```

These tests exercise synthetic native/gVisor/Kata evidence, identity/profile mismatches, missing baselines, failure precedence, extraction and tampered summaries. They establish tool mechanics; they are not real-world Kata compatibility or performance measurements.
