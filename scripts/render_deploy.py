"""Render reviewable Kubernetes manifests. This script does not contact a cluster."""
import argparse
import hashlib
import json
from pathlib import Path

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, default=Path("integration/config.example.json"))
    parser.add_argument("--image", default="sentrycheck-integration:0.3.0")
    parser.add_argument("--out", type=Path, default=Path("deploy"))
    args = parser.parse_args()
    cfg = json.loads(args.config.read_text(encoding="utf-8"))
    namespace = cfg["namespace"]
    args.out.mkdir(parents=True, exist_ok=True)
    def save(name, value):
        (args.out / name).write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8", newline="\n")
    def resource(api, kind, name, **fields):
        return {"apiVersion": api, "kind": kind, "metadata": {"name": name}, **fields}
    def string(): return {"type": "string"}
    def boolean(): return {"type": "boolean"}
    def obj(properties, required=None):
        return {"type": "object", "properties": properties, "required": required or list(properties)}
    def array(items, maximum=10000):
        return {"type": "array", "items": items, "maxItems": maximum}
    save("namespace.json", resource("v1", "Namespace", namespace))
    runtime_fields = {key: string() for key in ["name", "handler", "runtime", "version", "architecture", "selectorKey", "selectorValue"]}
    runtime_fields.update(configured=boolean(), healthyNodes=array(string(), 5000))
    image_fields = {key: string() for key in ["digest", "runtime", "version", "architecture", "reportDigest"]}
    image_fields.update(complete=boolean(), hardFailure=boolean(), silentDegradation=boolean())
    schema = obj({"apiVersion": string(), "kind": string(), "metadata": {"type": "object"}, "spec": obj({
        "generatedAt": {"type": "string", "format": "date-time"}, "expiresAt": {"type": "string", "format": "date-time"},
        "runtimes": array(obj(runtime_fields), 128), "images": array(obj(image_fields), 10000), "warnings": array(string(), 10000)})}, ["spec"])
    crd = resource("apiextensions.k8s.io/v1", "CustomResourceDefinition", "sandboxpolicysnapshots.sentrycheck.io", spec={
        "group": "sentrycheck.io", "scope": "Cluster", "names": {"plural": "sandboxpolicysnapshots", "singular": "sandboxpolicysnapshot", "kind": "SandboxPolicySnapshot", "shortNames": ["scsnap"]},
        "versions": [{"name": "v1alpha1", "served": True, "storage": True, "schema": {"openAPIV3Schema": schema}}]})
    save("snapshot-crd.json", crd)
    variables = [
        {"name": "runtimeName", "expression": "has(object.spec.runtimeClassName) ? object.spec.runtimeClassName : ''"},
        {"name": "managed", "expression": "params.spec.runtimes.filter(r, r.name == variables.runtimeName)"},
        {"name": "images", "expression": "object.spec.containers.map(c, c.image) + (has(object.spec.initContainers) ? object.spec.initContainers.map(c, c.image) : []) + (has(object.spec.ephemeralContainers) ? object.spec.ephemeralContainers.map(c, c.image) : [])"},
        {"name": "requiredIsolation", "expression": "has(object.metadata.labels) && 'sentrycheck.io/require-isolation' in object.metadata.labels && object.metadata.labels['sentrycheck.io/require-isolation'] == 'true'"},
    ]
    matches = "i.runtime == r.runtime && i.version == r.version && i.architecture == r.architecture && c.endsWith('@' + i.digest)"
    validations = [
        ("size(variables.managed) == 1", "SENTRYCHECK: the configured or required RuntimeClass must have exactly one current controller snapshot entry."),
        ("variables.managed.all(r, r.configured && size(r.healthyNodes) > 0)", "SENTRYCHECK: runtime has no verified healthy scheduling target or its handler configuration differs."),
        ("variables.managed.all(r, has(object.spec.nodeSelector) && r.selectorKey in object.spec.nodeSelector && object.spec.nodeSelector[r.selectorKey] == r.selectorValue && 'kubernetes.io/arch' in object.spec.nodeSelector && object.spec.nodeSelector['kubernetes.io/arch'] == r.architecture && (!has(object.spec.nodeName) || object.spec.nodeName == '' || object.spec.nodeName in r.healthyNodes))", "SENTRYCHECK: Pod must retain the RuntimeClass health and architecture selectors; a direct node assignment must be verified."),
        ("size(variables.managed) == 0 || variables.images.all(c, c.matches('^[^@]+@sha256:[a-f0-9]{64}$') && variables.managed.all(r, params.spec.images.exists(i, " + matches + ") && !params.spec.images.exists(i, " + matches + " && !i.complete)))", "SENTRYCHECK: every app, init, and ephemeral image needs complete trusted reports for its immutable digest and exact runtime version/architecture."),
        ("variables.images.all(c, variables.managed.all(r, !params.spec.images.exists(i, " + matches + " && i.hardFailure)))", "SENTRYCHECK: image has a confirmed hard-failure finding for the selected runtime."),
    ]
    policy = resource("admissionregistration.k8s.io/v1", "ValidatingAdmissionPolicy", "sentrycheck-compatibility", spec={
        "failurePolicy": "Fail", "paramKind": {"apiVersion": "sentrycheck.io/v1alpha1", "kind": "SandboxPolicySnapshot"},
        "matchConstraints": {"resourceRules": [{"apiGroups": [""], "apiVersions": ["v1"], "operations": ["CREATE", "UPDATE"], "resources": ["pods", "pods/ephemeralcontainers"]}]},
        "matchConditions": [{"name": "managed-or-required-isolation", "expression": "(has(object.spec.runtimeClassName) && object.spec.runtimeClassName in " + json.dumps([r["name"] for r in cfg["runtimes"]]) + ") || (has(object.metadata.labels) && 'sentrycheck.io/require-isolation' in object.metadata.labels && object.metadata.labels['sentrycheck.io/require-isolation'] == 'true')"}],
        "variables": variables, "validations": [{"expression": expression, "message": message, "reason": "Invalid"} for expression, message in validations]})
    save("policy.json", policy)
    binding = resource("admissionregistration.k8s.io/v1", "ValidatingAdmissionPolicyBinding", "sentrycheck-compatibility", spec={
        "policyName": "sentrycheck-compatibility", "validationActions": ["Warn", "Audit"],
        "paramRef": {"name": cfg["snapshotName"], "parameterNotFoundAction": "Allow"}})
    save("binding-warn.json", binding)
    binding["spec"]["validationActions"] = ["Deny", "Audit"]
    binding["spec"]["paramRef"]["parameterNotFoundAction"] = "Deny"
    save("binding-strict.json", binding)
    # Mutations can add convenience metadata only. These labels are never trust inputs.
    mutation = resource("admissionregistration.k8s.io/v1", "MutatingAdmissionPolicy", "sentrycheck-observability", spec={
        "failurePolicy": "Ignore", "reinvocationPolicy": "IfNeeded", "matchConstraints": {"resourceRules": [{"apiGroups": [""], "apiVersions": ["v1"], "operations": ["CREATE"], "resources": ["pods"]}]},
        "matchConditions": [{"name": "declared-isolation", "expression": "has(object.metadata.labels) && 'sentrycheck.io/require-isolation' in object.metadata.labels && object.metadata.labels['sentrycheck.io/require-isolation'] == 'true'"}],
        "mutations": [{"patchType": "ApplyConfiguration", "applyConfiguration": {"expression": "Object{metadata: Object.metadata{annotations: {'sentrycheck.io/admission-observer': 'enabled'}}}"}}]})
    save("mutation-optional.json", {"apiVersion": "v1", "kind": "List", "items": [mutation, resource("admissionregistration.k8s.io/v1", "MutatingAdmissionPolicyBinding", "sentrycheck-observability", spec={"policyName": "sentrycheck-observability"})]})
    def sa(name):
        value = resource("v1", "ServiceAccount", name); value["metadata"]["namespace"] = namespace; return value
    cluster_role = resource("rbac.authorization.k8s.io/v1", "ClusterRole", "sentrycheck-controller", rules=[
        {"apiGroups": [""], "resources": ["nodes"], "verbs": ["get", "list", "patch"]},
        {"apiGroups": ["node.k8s.io"], "resources": ["runtimeclasses"], "verbs": ["get", "list", "patch"]},
        {"apiGroups": ["sentrycheck.io"], "resources": ["sandboxpolicysnapshots"], "verbs": ["get", "create", "update"]}])
    cluster_binding = resource("rbac.authorization.k8s.io/v1", "ClusterRoleBinding", "sentrycheck-controller", roleRef={"apiGroup": "rbac.authorization.k8s.io", "kind": "ClusterRole", "name": "sentrycheck-controller"}, subjects=[{"kind": "ServiceAccount", "name": "sentrycheck-controller", "namespace": namespace}])
    reader = resource("rbac.authorization.k8s.io/v1", "ClusterRole", "sentrycheck-snapshot-reader", rules=[{"apiGroups": ["sentrycheck.io"], "resources": ["sandboxpolicysnapshots"], "verbs": ["get", "list"]}])
    reader_binding = resource("rbac.authorization.k8s.io/v1", "ClusterRoleBinding", "sentrycheck-snapshot-reader", roleRef={"apiGroup": "rbac.authorization.k8s.io", "kind": "ClusterRole", "name": "sentrycheck-snapshot-reader"}, subjects=[{"kind": "Group", "name": "system:authenticated", "apiGroup": "rbac.authorization.k8s.io"}])
    items = [sa("sentrycheck-controller"), sa("sentrycheck-node-probe"), cluster_role, cluster_binding, reader, reader_binding]
    for name, rules in [("sentrycheck-controller", [{"apiGroups": [""], "resources": ["configmaps"], "verbs": ["get", "list"]}]), ("sentrycheck-node-probe", [{"apiGroups": [""], "resources": ["configmaps"], "verbs": ["get", "create", "update"]}, {"apiGroups": [""], "resources": ["events"], "verbs": ["create"]}])]:
        role = resource("rbac.authorization.k8s.io/v1", "Role", name, rules=rules); role["metadata"]["namespace"] = namespace
        rb = resource("rbac.authorization.k8s.io/v1", "RoleBinding", name, roleRef={"apiGroup": "rbac.authorization.k8s.io", "kind": "Role", "name": name}, subjects=[{"kind": "ServiceAccount", "name": name, "namespace": namespace}]); rb["metadata"]["namespace"] = namespace
        items.extend([role, rb])
    save("rbac.json", {"apiVersion": "v1", "kind": "List", "items": items})
    config_map = resource("v1", "ConfigMap", "sentrycheck-controller-config", data={"config.json": json.dumps(cfg, indent=2)})
    config_map["metadata"]["namespace"] = namespace
    save("controller-config.json", config_map)
    deployment = resource("apps/v1", "Deployment", "sentrycheck-controller", spec={"replicas": 1, "selector": {"matchLabels": {"app": "sentrycheck-controller"}}, "template": {"metadata": {"labels": {"app": "sentrycheck-controller"}}, "spec": {
        "serviceAccountName": "sentrycheck-controller", "securityContext": {"runAsNonRoot": True, "runAsUser": 65532, "seccompProfile": {"type": "RuntimeDefault"}},
        "containers": [{"name": "controller", "image": args.image, "imagePullPolicy": "IfNotPresent", "command": ["/sentrycheck-admission", "controller"], "ports": [{"containerPort": 8080}],
                        "readinessProbe": {"httpGet": {"path": "/readyz", "port": 8080}, "periodSeconds": 10}, "livenessProbe": {"httpGet": {"path": "/healthz", "port": 8080}},
                        "resources": {"requests": {"cpu": "50m", "memory": "64Mi"}, "limits": {"cpu": "500m", "memory": "256Mi"}},
                        "securityContext": {"allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True, "capabilities": {"drop": ["ALL"]}}, "volumeMounts": [{"name": "config", "mountPath": "/etc/sentrycheck", "readOnly": True}]}],
        "volumes": [{"name": "config", "configMap": {"name": "sentrycheck-controller-config"}}]}}})
    deployment["metadata"]["namespace"] = namespace
    save("controller.json", deployment)
    runtime_items = []
    probe_items = []
    for runtime in cfg["runtimes"]:
        key_data = "/".join(runtime[k] for k in ["name", "runtime", "version", "architecture", "handler", "expectedRuntimeType"])
        selector = "sentrycheck.io.node-restriction.kubernetes.io/runtime-" + hashlib.sha256(key_data.encode()).hexdigest()[:16]
        runtime_items.append(resource("node.k8s.io/v1", "RuntimeClass", runtime["name"], handler=runtime["handler"], scheduling={"nodeSelector": {selector: "verified", "kubernetes.io/arch": runtime["architecture"]}}))
        name = "sentrycheck-probe-" + runtime["name"]
        binary = "runsc" if runtime["runtime"] == "gvisor" else "kata-runtime"
        daemon = resource("apps/v1", "DaemonSet", name, spec={"selector": {"matchLabels": {"app": name}}, "template": {"metadata": {"labels": {"app": name}}, "spec": {
            "serviceAccountName": "sentrycheck-node-probe", "nodeSelector": {"kubernetes.io/arch": runtime["architecture"]}, "tolerations": [{"operator": "Exists"}],
            "containers": [{"name": "probe", "image": args.image, "imagePullPolicy": "IfNotPresent", "command": ["/sentrycheck-node-probe"],
                            "args": ["--publish", "--runtime", runtime["runtime"], "--version", runtime["version"], "--architecture", runtime["architecture"], "--handler", runtime["handler"], "--expected-runtime-type", runtime["expectedRuntimeType"], "--binary", "/host/usr/local/bin/" + binary, "--crictl", "/host/usr/local/bin/crictl"],
                            "env": [{"name": "NODE_NAME", "valueFrom": {"fieldRef": {"fieldPath": "spec.nodeName"}}}],
                            "securityContext": {"runAsUser": 0, "allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True, "capabilities": {"drop": ["ALL"]}},
                            "resources": {"requests": {"cpu": "20m", "memory": "32Mi"}, "limits": {"cpu": "250m", "memory": "128Mi"}},
                            "volumeMounts": [{"name": "host-bin", "mountPath": "/host/usr/local/bin", "readOnly": True}, {"name": "cri", "mountPath": "/run/containerd", "readOnly": True}, {"name": "tmp", "mountPath": "/tmp"}]}],
            "volumes": [{"name": "host-bin", "hostPath": {"path": "/usr/local/bin", "type": "Directory"}}, {"name": "cri", "hostPath": {"path": "/run/containerd", "type": "Directory"}}, {"name": "tmp", "emptyDir": {"sizeLimit": "32Mi"}}]}}})
        daemon["metadata"]["namespace"] = namespace; probe_items.append(daemon)
    save("runtimeclasses.json", {"apiVersion": "v1", "kind": "List", "items": runtime_items})
    save("node-probes.json", {"apiVersion": "v1", "kind": "List", "items": probe_items})
    print("Rendered", args.out, "(warn-only binding is the default; strict is a separate opt-in file)")

if __name__ == "__main__":
    main()
