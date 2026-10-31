# External Kata guest-trace collector

`scripts/capture_kata.py` is an **experimental collector**, not a Kata installer or a live-validated compatibility claim. It uses a preconfigured local CRI endpoint, runs guest strace inside Kata, and writes the existing `--evidence` import format. The resulting scanner report remains **`imported-user-supplied`** and incomplete for a clean gate. Kata KB coverage is still experimental/uncovered.

The initial implementation has offline identity, containment, cleanup and metadata regressions. A real Kata VM/CRI run must be recorded separately before claiming live support. A working `/dev/kvm` is one prerequisite; it does not establish that the guest kernel, rootfs, VMM, shim and CRI handler are configured correctly.

## Runtime feasibility and source pinning

The [Kata 4.2.0 release API](https://api.github.com/repos/kata-containers/kata-containers/releases/tags/4.2.0), checked on 2026-09-26, reports:

| amd64 asset | Compressed bytes | GitHub asset digest |
| --- | --- | --- |
| `kata-static-4.2.0-amd64.tar.zst` | 996,647,537 | `sha256:b828904fa3f1e49ddd7dc799c72cb1503cd1e772d354c3987c8d4189b2a623a8` |
| `kata-go-static-4.2.0-amd64.tar.zst` | 1,260,982,791 | `sha256:7dda31ca54b397cbf8165f620d6041872d3c45b7a77383ce0e86f76a06e103d0` |
| `kata-tools-static-4.2.0-amd64.tar.zst` | 22,645,350 | `sha256:a4f8e1b6ee500b6e94d3925249e741c75bb4a89bf275b5d5066d6275c68e29ef` |

These are checked release metadata, not a claim that an archive was downloaded or verified locally. Verify the downloaded bytes against the selected asset digest before extracting. The small tools archive alone is not a working Kata runtime.

The [retained installation source](https://github.com/kata-containers/kata-containers/blob/8a2c6acfa662dc579b69a296275337d803b4f5ab/docs/installation.md) describes the runtime-rs archive as containing the shim, configurations, composable guest images and shared host/VMM components. The deprecated Go runtime uses a separate archive. No smaller complete subset or extracted size is asserted without inspecting the actual release archive. Do not extract either complete archive onto a nearly full host filesystem. A bounded RAM workspace can be used only if it has space for both compressed and extracted data and remains alive for the whole experiment.

Kata normally needs hardware virtualization and accessible `/dev/kvm`; supported Microsoft-hypervisor configurations use `/dev/mshv` instead. A nested VM needs the corresponding virtualization facilities exposed. `runsc` is gVisor's runtime and cannot provide a Kata comparison.

## Inputs and execution contract

Prepare a dedicated, isolated, rootful Linux CRI runner. Configure the Kata handler outside this collector. The prototype requires its CRI `runtime_type` to be the **absolute, resolved path** to the actual `containerd-shim-kata-v2` binary. This binds the observed runtime type to the version-checked binary; arbitrary PATH resolution of `io.containerd.kata.v2` is not guessed.

The image must already exist in CRI under `repository@sha256:manifest`. `inspecti` must expose that exact repo digest, a config digest, Linux architecture and the image configuration. Tag-only input or ambiguous image metadata is rejected. If an OCI archive needs importing, use the administrator's explicit containerd import workflow first and verify `inspecti`; the collector does not automatically fetch or retag images.

Supply trusted **static ELF** strace and BusyBox binaries for the image architecture. The collector records their hashes, copies them into a private read-only tools mount, and uses BusyBox only for a fixed launcher and output redirection. Workload strings are positional arguments, never interpolated into shell source. Dynamic host tools with `PT_INTERP` are rejected; no host library tree is exposed to the guest.

A saved SENTRYCHECK JSON report supplies the native observations and canonical profile. The trusted `sentrycheck report validate --artifacts-root ...` command verifies that source report, including reparsed trace and artifact consistency. Native observations must have passed the declared expected exit, match the repetition count, and have no infrastructure error, timeout, truncation, discarded records or unfinished calls. Their raw artifacts are copied with matching hashes. **They are reused captures, not concurrently rerun native measurements.** Their original scan date and source report hash remain in the collector ledger.

The profile command overrides image ENTRYPOINT/CMD; an empty profile command uses the inspected image command. Image environment and working directory are preserved, with profile environment values taking precedence. CRI retains image USER resolution. The guest is unprivileged, drops capabilities and has no-new-privileges enabled; seccomp is explicitly unconfined to permit tracing one's own child. The CRI environment is still different from the native OCI runner: networking, mounts, PID layout, VM resources and capture file limits can differ. The caller must provide an isolated test cluster, and timings from reused native captures are not a controlled benchmark.

## Example

The paths and handler below are placeholders for an already configured disposable runner:

```sh
python3 scripts/capture_kata.py \
  --native-report artifacts/review-v03/final-live/baseline.report.json \
  --native-artifacts-root "$PWD" \
  --image 'registry.example/fixture@sha256:<same-manifest-digest-as-native-report>' \
  --kata-version 4.2.0 \
  --runtime-binary /opt/kata/runtime-rs/bin/containerd-shim-kata-v2 \
  --handler sentrycheck-kata \
  --endpoint unix:///run/containerd/containerd.sock \
  --crictl /trusted/bin/crictl \
  --sentrycheck "$PWD/bin/sentrycheck-linux" \
  --strace /trusted/static/strace \
  --busybox /trusted/static/busybox \
  --output /tmp/dedicated-ram-workspace/kata-baseline

sentrycheck scan ./same-image-oci --runtime kata --version 4.2.0 \
  --evidence /tmp/dedicated-ram-workspace/kata-baseline/evidence.json \
  --format json --output kata-report.json
```

`--output` must be a new directory with a canonical, symlink-free parent. The collector creates no cluster and changes no CRI configuration. It returns `0` only after capturing a manifest; this is **not** a compatibility pass. Input/infrastructure/cleanup failure returns `2`. Importing an observed failure can exit `1`; imported evidence otherwise remains exit `2` under the scanner's evidence policy.

## Identity, bounds and cleanup

Each repetition gets a fresh sandbox and container. The collector checks the exact returned 64-hex sandbox ID, private UID, ready state and expected `runtimeType`, then the exact container ID, private label, requested image ref and resolved digest. Boolean or missing enum fields cannot stand in for a ready/running state. Initial and final inspections are retained outside the guest mount.

Each guest output directory is its own **96 MiB tmpfs**, independent of the output workspace filesystem. Captured stdout, stderr and trace must each remain **below 16 MiB**. A shell file-size limit, host polling, filesystem-space checks and final bounded reads prevent an output overflow from being silently promoted to a workload finding. A file-limit signal is treated as incomplete instrumentation. The profile timeout bounds workload execution; CRI startup and cleanup have separate bounded timeouts.

Cleanup uses only IDs returned for this collector's requests. Failed stop/removal calls can be accepted as idempotent only when successful exact removal or an explicit filtered exact-ID absence check establishes that the resource is gone. If cleanup cannot establish removal, the collector stops **before reading guest output or unmounting its output filesystem**. It retains the IDs and a failed ledger for operator recovery; it never enumerates and deletes unrelated containers.

If a CRI creation RPC times out without returning an ID, the collector cannot prove whether the daemon created a resource. The private sandbox UID and saved configuration identify the request for manual inspection. It does not guess an ID or delete resources by an ambiguous name. Do not treat a failed collector invocation as proof that no canary remains.

Only after all repetitions and cleanup succeed is `evidence.json` written. `collector-start.json` records intent; `collector-result.json` records captured or failed status, native origin, tool/runtime hashes, configuration and limits. A partial directory is not a completed experiment.

## Evidence limits and tests

The guest can write its own output/trace mount, so this collection is **not tamper-proof attestation** against an actively malicious workload. Read-only tools and post-cleanup reads reduce accidental contamination; artifact hashes identify bytes without proving their origin. Exact runtime type and binary version are useful consistency checks, not hardware attestation. Missing or incompatible Kata KB coverage remains visible.

Run the offline regressions with:

```sh
python scripts/test_capture_kata.py
```

These tests check digest/profile binding, image and CRI identity, ambiguous state rejection, static tool requirements, path bounds, environment precedence and exact-ID cleanup. They do not boot a Kata VM. Record a successful live run, failed-handler case, timeout, output overflow and cleanup failure separately before claiming the collector is validated for a particular CRI/Kata combination.
