# Kubernetes installation and operation

Use Kubernetes 1.30+ for the stable ValidatingAdmissionPolicy API. The optional mutation manifest uses the Kubernetes 1.36 stable MutatingAdmissionPolicy API; omit it on older clusters. The integration uses in-cluster TLS credentials and Kubernetes REST, with no admission webhook.

## Prepare a trusted configuration

1. Build the two Go binaries or the v0.2.0 integration container image. Install the expected runtime handler and `crictl` on test nodes. The default DaemonSet mounts `/usr/local/bin` and `/run/containerd`; change these paths and the `--binary`, `--crictl`, and `--endpoint` arguments for your cluster. The probe does not install or register runtimes. For gVisor 20260921.0, keep `runsc` and its required `gvisor-bin` companions together on the node.
2. Generate an Ed25519 key with `sentrycheck-admission keygen`. Keep the private key in CI secrets. Add the public PEM to the controller JSON's `trustedKeys` map under the selected key ID. Empty trust keys mean no report is accepted.
3. Set the exact RuntimeClass name, CRI handler, runtime version, architecture, and expected CRI runtimeType. For containerd, common runtimeType values are `io.containerd.runsc.v1` and `io.containerd.kata.v2`; verify the actual deployment. A handler name alone is not runtime identity.
4. Run `python scripts/render_deploy.py --config controller-config.json --image your-built-image`. Review the rendered resources. They are JSON Kubernetes manifests accepted by kubectl.

The controller may manage scheduling selectors only for the RuntimeClasses explicitly named in its config. It preserves unrelated selectors. The rendered policy matches those configured names and Pods declaring required isolation; re-render it when changing the managed RuntimeClass list. Enable Kubernetes NodeRestriction and the Node authorizer so kubelets cannot set the protected health labels themselves. The controller remains a trusted cluster-level component.

## Install in warning mode

```sh
kubectl apply -f deploy/namespace.json
kubectl apply -f deploy/snapshot-crd.json
kubectl apply -f deploy/rbac.json
kubectl apply -f deploy/controller-config.json
kubectl apply -f deploy/runtimeclasses.json
kubectl apply -f deploy/controller.json
kubectl apply -f deploy/node-probes.json
kubectl rollout status -n sentrycheck-system deployment/sentrycheck-controller
kubectl get sandboxpolicysnapshots cluster -o json
kubectl apply -f deploy/policy.json
kubectl apply -f deploy/binding-warn.json
```

These commands are operator actions; the repository's build and renderer do not execute them automatically. The integration image name must resolve on the cluster. Do not apply an entire directory indiscriminately: both warning and strict bindings are provided, and the mutation resources are optional.

Warning mode reports validation failures to clients and audit logs. Missing parameters are allowed during rollout, so a missing controller snapshot can produce no warning. Once the controller and probes are healthy, strict mode switches `parameterNotFoundAction` to Deny and uses `[Deny, Audit]`. Warn and Deny are never combined in one binding.

```sh
kubectl apply -f deploy/binding-strict.json
# Return to non-blocking rollout behavior:
kubectl apply -f deploy/binding-warn.json
```

The snapshot reader ClusterRole lets authenticated API users read the policy parameters, as required by parameter authorization. Snapshots contain image digests and verdict metadata, not private keys or full traces. Restrict this role to appropriate deployer groups if needed. The node-probe service account's ConfigMap writes and CRI socket are privileged infrastructure access; keep that namespace isolated from workloads.

Compatibility policy does not replace Pod Security controls. Apply the workload namespace's required restrictions on privileged containers, host namespaces, and host mounts independently. Restrict scheduler credentials, direct Pod binding, and `pods/binding` permission to trusted infrastructure. A controller-owned node selector is not a complete authorization boundary against an administrator or a caller allowed to bypass intended scheduling paths.

## Publish CI evidence

Scan the selected platform manifest with a representative profile and a matching locally installed runsc. Preserve the full report and traces in CI artifacts. Sign a compact claim for the report:

```sh
sentrycheck scan image-oci --version 20260921.0 --profile profiles/python.toml --output report.json
sentrycheck-admission attest --report report.json --key ci-private.pem --key-id ci \
  --configmap-namespace sentrycheck-system --output signed-report.configmap.json
kubectl apply -f signed-report.configmap.json
```

The signer rejects imported execution provenance. Claims bind the full report's hash, image digest, runtime name/version/architecture, original scan time, coverage, and findings. An attestation's fresh signature cannot refresh an old scan. The controller accepts only signatures from configured keys and only unexpired, sufficiently recent scans. Conflicting current reports are combined conservatively; a current failure is not hidden by another passing report.

For a separately archived bare attestation envelope, verify its signature and exact report bytes:

```sh
sentrycheck-admission attest --report report.json --key ci-private.pem --key-id ci \
  --output report.attestation.json
sentrycheck-admission verify --file report.attestation.json --public-key ci-public.pem \
  --key-id ci --report report.json
```

`verify --file` accepts the bare envelope, not the surrounding ConfigMap; an envelope published in a ConfigMap is its `data["attestation.json"]` value. Without `--report`, verification checks the claim's signature and freshness only. Preserve original report bytes because even whitespace changes alter the signed digest. `sentrycheck report validate` is a useful separate consistency/artifact check, but it does not authenticate the report. See [CI-TOOLS.md](CI-TOOLS.md).

The trusted CI producer is part of this boundary. Native traces reside in a guest-writable location; hashing and signing do not make them adversarially trustworthy. Use the reports for compatibility evidence with that limitation, rather than treating a signed clean report as proof against a malicious workload.

Deploy images as `registry/name@sha256:<platform-manifest-digest>` and select the configured RuntimeClass. The policy covers application, init, and ephemeral containers. Tags, missing reports, wrong versions/architectures, incomplete evidence, and confirmed hard failures warn or block according to the binding. User-controlled annotations are ignored as evidence.

## Node health and drift

Each probe checks the configured binary's version, asks CRI to launch a canary with the requested handler, verifies the returned canary ID and `SANDBOX_READY` state, inspects `info.runtimeType`, and stops/removes the canary. It publishes a report and a Warning event on transitions to unhealthy/unverified states. Missing binaries, version mismatches, failed/not-ready canaries, conflicting IDs, absent runtimeType, unexpected runc, and cleanup failures cannot become verified health.

Warning events reference the namespaced probe-report ConfigMap and relate it to the affected Node. This keeps the object reference valid for a namespaced Kubernetes Event.

The controller selects the latest report per node/handler/version/architecture, expires old results, removes unhealthy labels, and publishes eligible node names. Conflicting latest probe reports do not establish health. Observed RuntimeClass handler/configuration drift invalidates the affected eligibility so an old healthy result cannot remain authoritative merely because reconciliation encountered that drift. RuntimeClass scheduling requires a version-specific protected label and architecture. Direct Pod node assignment is checked against verified nodes. Extra selectors or taints can still leave a Pod unschedulable; the tool does not replace the scheduler.

The probe is not a hardware attestation and does not prove the runtime of every existing Pod. Normal Kubernetes reports missing handlers as failures; the explicit runtime mismatch alarm is useful for misconfigured wrappers and unexpected CRI behavior.

**Monitor `/readyz` and snapshot age.** CEL has no wall clock or external data fetch. The controller evaluates TTLs, but a controller outage can leave stale labels and parameters. Strict CEL alone cannot close this failure window. Operationally suspend new sandbox scheduling until reconciliation is healthy; this remains a v0.2 limitation.

## Offline checks and a disposable-cluster demo

`sentrycheck-admission reconcile --config ... --state ... --output snapshot.json` builds a snapshot from captured report, probe, node, and RuntimeClass JSON. `evaluate --pod admitted-pod.json --snapshot snapshot.json --strict` checks the same policy rules, with an additional real-time snapshot expiry check that CEL cannot perform.

For a live drift demo, use a dedicated test RuntimeClass/node, establish a verified canary, then change **only the test probe's** `--binary` to a nonexistent path. Observe `runtime-unavailable`, a Warning event, removal of its health label, and warning/denial for a test Pod. Restore the probe configuration and observe recovery. To demonstrate an actual wrong runtime, configure a disposable CRI test handler to report runc and confirm `isolation-mismatch`. Do not remove or rename production runtime binaries. Unit tests exercise both mechanisms, but are not a substitute for recording this live demo.

`scripts/test-node-runtime-live.sh` automates that test on a dedicated Linux host using the local k3s binary, a configured runsc containerd handler, and previously generated corpus evidence. It uses real CRI canaries and server-side dry-run admission. The completed local run is recorded in [VALIDATION.md](VALIDATION.md). For a host process, `SENTRYCHECK_SERVICE_ACCOUNT_DIR` can point to its dedicated `ca.crt` and `token` files alongside `KUBERNETES_SERVICE_HOST` and `KUBERNETES_SERVICE_PORT_HTTPS`; TLS verification remains enabled. Pods use the standard service-account mount by default.
