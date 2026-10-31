# Admission audit, v0.3.0

This review exercised the Go attestation/controller/policy code and the generated
CEL policy on 26 September 2026. It checks concrete failure paths; it is not a
proof that every deployment or Kubernetes configuration is correct.

## Corrections and reproduced cases

| Issue | Previous behavior | Corrected behavior |
| --- | --- | --- |
| A managed RuntimeClass disappeared from an otherwise present snapshot | CEL `all`/`exists` expressions over an empty managed-runtime list could allow a Pod without the optional isolation label. | Every Pod selected by the policy must resolve to exactly one snapshot runtime entry. Omitted and duplicate entries fail the gate. |
| Contradictory image completeness rows | CEL accepted one complete row while the offline Go evaluator rejected an incomplete row for the same image and target. | Every matching image row must be complete; any hard failure still blocks strict admission. |
| A runtime handler or shim configuration changed | Health selector identities included release/architecture but omitted handler and expected CRI runtime type. | Selector identities bind both fields. Reconciliation revokes obsolete SENTRYCHECK-owned Node labels, including prior release labels. |
| An operator added a RuntimeClass scheduling constraint | A verified Node outside that workload pool still appeared in `healthyNodes`. | Nodes must satisfy all RuntimeClass selectors other than the health label being reconciled. This does not establish that Pod-specific affinity, taints, or resource availability permit scheduling. |
| A probe report contradicted its own healthy flag | The controller consumed healthy/verified flags without requiring the recorded ready canary state and ID. | A healthy record must identify a `canary-verified`, `SANDBOX_READY` canary. Equal-time conflicting records are rejected independently of list order. |
| A configuration called a known runc shim the expected sandbox | A correct comparison with that configuration could mark a runc canary verified. | Controller configuration and the probe reject known runc runtime types for gVisor/Kata claims. Custom shim identities still require operator review. |
| A correctly signed claim contained invalid metadata | Unknown statuses/severities, mismatched runtime/evidence tiers, or invalid profile digests could reach controller policy generation. | Sign and verify reject unsupported or contradictory claim fields. |
| A report declared completeness despite missing execution evidence | Signing relied primarily on status and summary metadata. | Complete reports require the requested native and sandbox observations, a successful native profile baseline, exact sandbox runtime/version, and nonempty finished guest traces. Discarded guest records, truncation, infrastructure errors, and incomplete reasons prevent signing as complete. |

`sentrycheck-admission evaluate --config <controller-config.json>` now uses the
same configured runtime names as CEL. Without `--config`, the command can infer
managed names only from the supplied snapshot and cannot identify a configured
runtime that the snapshot entirely omits.

Trace `diagnostic_lines` are not treated as guest-record loss. Older reports that
omit the new `discarded_guest_records` field remain readable; their recorded
scanner version still identifies the parser that produced them.

## Validation

- `go test ./...` and `go vet ./...` passed after the changes. Regression cases
  cover omitted/duplicate runtimes, handler/type selector identity, retired label
  revocation, scheduling eligibility, contradictory canaries, inconsistent signed
  claims, missing native baselines, discarded/unfinished records, and harmless
  diagnostic chatter.
- Both Go commands were rebuilt for Windows and Linux amd64.
- `scripts/test-k3s-local.sh` passed against Kubernetes v1.35.0+k3s1. It exercised
  a managed Pod without an isolation label and confirmed strict rejection for
  omitted/duplicate runtime entries and conflicting image completeness, alongside
  existing digest/init/hard-failure cases. The API server reported no CEL type
  checking warnings. Warn mode emitted its warning and allowed the dry run.
- The actual Go workload report from the existing live baseline corpus was signed
  and verified against its exact bytes using the new admission binary.

The API test uses synthetic policy parameters and server dry runs. Its results
are stored in `artifacts/admission-api`; it does not launch or attest a container.
The separate live node/CRI test remains the evidence source for canary execution.

## Boundaries that remain

Signatures authenticate the trusted CI signer's claims and exact report bytes.
These structural checks do not independently rerun the workload or verify every
trace artifact. The signer and its execution environment remain trusted.

The node probe compares a configured binary's version and a fresh canary's
reported CRI runtime type. These are separate observations: they do not
cryptographically bind the canary to that binary or prove the identity of every
already running Pod. Operators must configure the expected runtime type and
binary path correctly; even a matching separately checked binary version does
not establish which executable the CRI shim launched for that canary.

CEL admission cannot fetch registry metadata or read a live clock. Controller
reconciliation computes evidence expiry and readiness, but a controller outage
can leave the last snapshot and labels resident. The changes above do not claim
to make strict admission enforce elapsed-time expiry during that outage.

Relevant Kubernetes contracts: [ValidatingAdmissionPolicy parameters and CEL](https://kubernetes.io/docs/reference/access-authn-authz/validating-admission-policy/),
[RuntimeClass scheduling](https://kubernetes.io/docs/concepts/containers/runtime-class/#scheduling),
and [Node isolation and NodeRestriction labels](https://kubernetes.io/docs/concepts/scheduling-eviction/assign-pod-node/#node-isolation-restriction).
