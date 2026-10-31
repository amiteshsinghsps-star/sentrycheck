# Primary-source review, 26 September 2026

This review checked upstream source and specifications against SENTRYCHECK's implementation and proposed CLI additions. It is a source-backed engineering review, not proof of error-free behavior, a broad compatibility benchmark, or an exhaustive novelty search.

Original response bytes, retrieval times, final URLs, byte counts, and SHA-256 hashes are retained in [the source manifest](evidence/deep-review/sources.json). `docs/evidence/deep-review/fetch.py` refreshes the principal sources with an 8 MiB limit per response. GitHub branch/tag references were resolved before fetching documents:

| Project | Revision checked | Scope of the evidence |
| --- | --- | --- |
| gVisor | `26f3455a4cb9a377354c33aeac049080a077c79c` | The selected `release-20260921.0`, not inferred support for newer releases. |
| OCI image specification | `147f9c13cedb47a0c4d9a11a222961073d585877` | Published `v1.1.1` descriptor, index, config, and layer semantics. |
| Kubernetes documentation | `a746bbd76e9504ecdedafbda7f7abfdbdee5642e` | Documentation checked on the review date; deployed API behavior still needs version-specific tests. |
| Kata Containers | `8a2c6acfa662dc579b69a296275337d803b4f5ab` | Current project documentation, not a versioned compatibility KB or a tested Kata installation. |
| OASIS SARIF specification | `adbb670c018335b0f384e6dd8819f4ea055d7ee1` | The SARIF 2.1.0 JSON schema at that revision. |

The manifest also retains an unsuccessful request for Kata's old `docs/install.md` path. The verified replacement is `docs/installation.md`; an HTTP 404 is not treated as evidence about product behavior. GitHub's live documentation responses are timestamped and hashed, but do not have a pinned source revision.

## Findings that affect behavior

### gVisor installation and readiness

The selected release's [installation guide](https://github.com/google/gvisor/blob/26f3455a4cb9a377354c33aeac049080a077c79c/g3doc/user_guide/install.md) explicitly requires Linux 5.6 or newer and supports x86-64 and ARM64. A present `runsc` executable is insufficient: the release tarball contains a sibling `gvisor-bin/` directory that must move with the binary. Its migration section says binary-only installation auto-download is being removed at the end of September 2026.

The release's [configuration source](https://github.com/google/gvisor/blob/26f3455a4cb9a377354c33aeac049080a077c79c/runsc/config/config.go) makes this operationally significant: `SidecarUsagePolicy.AllowEmbeddedFallback()` returns false for both `DEFAULT` and `STRICT`. Only the explicitly deprecated legacy policy permits the embedded fallback. A readiness check must not conceal missing sidecars by silently changing this policy.

**Implementation consequence:** environment diagnostics should check the resolved binary location, exact release, Linux/architecture prerequisites, required companion files, and native tracing dependencies. File presence and `--version` are preflight evidence; they do not prove a successful sandbox launch, installed CRI handler, or workload compatibility. The existing direct execution and CRI canary tests remain necessary.

The [platform guide](https://github.com/google/gvisor/blob/26f3455a4cb9a377354c33aeac049080a077c79c/g3doc/user_guide/platforms.md) confirms `systrap` is the default. It does not require `/dev/kvm`. The KVM platform does, and using it inside a VM requires nested virtualization. The old gVisor `ptrace` platform is unsupported; this is distinct from using the native `strace` utility for SENTRYCHECK's baseline tracing.

The [debugging guide](https://github.com/google/gvisor/blob/26f3455a4cb9a377354c33aeac049080a077c79c/g3doc/user_guide/debugging.md) places application syscall logs in the Sentry's boot logs. Tracing the host runtime launcher is not equivalent to recording guest syscalls. The current native-inside-runc versus runsc guest-strace design follows this distinction.

### OCI identity and platform scope

The [descriptor specification](https://github.com/opencontainers/image-spec/blob/147f9c13cedb47a0c4d9a11a222961073d585877/descriptor.md) ties a digest to exact bytes and identifies descriptor size as an integrity boundary. The [configuration specification](https://github.com/opencontainers/image-spec/blob/147f9c13cedb47a0c4d9a11a222961073d585877/config.md) separately defines a layer DiffID over the **uncompressed** tar archive. SENTRYCHECK's descriptor and DiffID verification checks different objects and should retain both.

An [image index](https://github.com/opencontainers/image-spec/blob/147f9c13cedb47a0c4d9a11a222961073d585877/image-index.md) points to platform manifests; its digest and the selected image manifest digest are not interchangeable. The report's image identity is the selected platform manifest. Multi-platform attestations must not reuse it as a claim about every child of an index.

The same specification includes CPU variants such as `amd64/v1`, `amd64/v2`, `amd64/v3`, and `arm64/v8`. At review start, SENTRYCHECK represented OS and architecture but did not preserve or verify these CPU feature requirements. Architecture equality alone cannot establish CPU portability. Likewise, the reader intentionally rejects ambiguous matching manifests instead of guessing a tag; arbitrary mixed nested indexes and additional formats need explicit support, not a silent compatibility pass.

**Implementation consequence:** report validation and comparison should bind target runtime, exact version, architecture, profile identity, evidence tier, and image identity. A profile change or target change must be visible as a different experiment. Structural validation and matching hashes detect inconsistency; they do not establish the identity or honesty of whoever produced an unsigned report.

### Kubernetes and Kata boundaries

The [RuntimeClass guide](https://github.com/kubernetes/website/blob/a746bbd76e9504ecdedafbda7f7abfdbdee5642e/content/en/docs/concepts/containers/runtime-class.md) says an absent RuntimeClass or an unrunnable handler leads to Pod failure and an event. It does not specify a normal silent fallback to runc. A handler configured to the wrong runtime is a separate measurable condition; it should be reported as an observed mismatch, not explained using the unsupported fallback anecdote.

The [ValidatingAdmissionPolicy guide](https://github.com/kubernetes/website/blob/a746bbd76e9504ecdedafbda7f7abfdbdee5642e/content/en/docs/reference/access-authn-authz/validating-admission-policy.md) documents Warn/Deny/Audit behavior and states that `parameterNotFoundAction: Allow` treats missing parameters as successful validation. A warn-only binding with that setting can therefore give no warning when its controller snapshot is absent. The strict path must explicitly handle missing parameters. No CEL expression in this architecture performs registry access, binary inspection, or live node execution.

Kata's [installation requirements](https://github.com/kata-containers/kata-containers/blob/8a2c6acfa662dc579b69a296275337d803b4f5ab/docs/installation.md) require hardware virtualization, including nested virtualization when the host is a VM. The usual backend requires `/dev/kvm`; the guide also documents the Microsoft Hypervisor `/dev/mshv` exception with a suitable Cloud Hypervisor backend. An unconditional claim that every Kata backend requires exactly `/dev/kvm` would be too broad. VM artifacts, backend configuration, and VSOCK support add prerequisites absent from gVisor systrap.

**Implementation consequence:** gVisor readiness and experimental Kata support must remain distinct. A green gVisor preflight cannot certify Kata. Kubernetes policy checks and actual node canaries complement image findings but cannot prove every already-running Pod's identity or replace controller freshness handling.

### SARIF is useful, with an integration constraint

The [OASIS SARIF 2.1.0 schema](https://github.com/oasis-tcs/sarif-spec/blob/adbb670c018335b0f384e6dd8819f4ea055d7ee1/sarif-2.1/schema/sarif-schema-2.1.0.json) permits results without a source location. It defines stable rule IDs, result levels, partial fingerprints, binary byte offsets, and `invocations[].executionSuccessful`. These fields can preserve SENTRYCHECK's evidence rather than reducing a scan to an unexplained severity.

[GitHub's SARIF support documentation](https://docs.github.com/en/code-security/reference/code-scanning/sarif-files/sarif-support), however, says at least one location is required for a displayed code scanning result and recommends a repository-relative source path. Container paths like `/usr/lib/liburing.so` are not files in the user's repository. Fabricating a source line would misrepresent the analysis. A standards-valid export alone is therefore insufficient to promise visible GitHub code scanning alerts.

An explicit user-supplied Dockerfile or deployment-file association can provide a real repository location. It must be described as an association supplied for review, not a proven source-code call site. Without such a mapping, the export remains useful as a generic SARIF artifact and must disclose the GitHub display limitation. URI escaping must preserve spaces and reserved characters without changing the intended file.

GitHub further documents stable rule/path requirements for deduplication, uses `partialFingerprints.primaryLocationLineHash`, and imposes a 10 MB compressed-file limit, 20 runs per file, and 25,000 results per run, with only the top 5,000 included. Custom SARIF fingerprints are valid but should not be advertised as sufficient for GitHub deduplication. Incomplete scans should carry unsuccessful invocation/diagnostic metadata, while unconfirmed static capability candidates must not turn into confirmed error alerts.

## Feature priorities from this review

1. **Environment diagnostics:** identify missing tools, unsupported hosts, runtime release mismatch, and incomplete runsc installation before a costly scan. Return explicit readiness/degradation with remediation and no claim of a live compatibility test.
2. **Report validation:** catch schema/enum/digest inconsistencies, absent required evidence, and tampered optional local artifacts before downstream display or gating. Keep unsigned authenticity separate from structural integrity and signed admission verification.
3. **Report comparison:** show newly observed failures and resolved findings while flagging profile, target, evidence, and completeness changes. Stable semantic keys should replace per-run finding numbers. An incomplete replacement scan cannot establish that an old failure disappeared.
4. **SARIF export:** preserve citations, evidence tiers, scan limitations, and stable rule identity. Use explicit repository associations when GitHub code scanning display is intended; do not invent source positions.

These priorities are recommendations derived from verified sources and inspection. The CLI documentation and tests describe which features are actually implemented; this review does not claim that a recommendation alone is delivered.

## Claims still not established

The original PRD's unnamed July 2026 post-mortem and GitHub issue still lack exact checkable URLs. This review does not verify their quotations, a universal silent-fallback claim, or the assertion that no competing tool exists. It also does not establish full Kata parity, arbitrary-workload coverage, universal Linux CI readiness, zero defects, or a measured real-world precision/recall rate. See [the earlier PRD corrections](PRD-REVIEW.md), [recorded validation](VALIDATION.md), and [limitations](../LIMITATIONS.md) for the distinct evidence already available.
