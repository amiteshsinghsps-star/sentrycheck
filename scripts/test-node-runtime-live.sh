#!/usr/bin/env bash
# Disposable single-node Kubernetes/CRI test. Installs no service. Uses real
# containerd canaries and the built Go components with scoped service accounts.
set -euo pipefail
project_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$project_root"
runtime="${SENTRYCHECK_NODE_K3S:-$project_root/.cache/linux/bin/k3s}"
runsc="${SENTRYCHECK_NODE_RUNSC:-$project_root/.cache/linux/bin/runsc}"
admission="${SENTRYCHECK_NODE_ADMISSION:-$project_root/bin/sentrycheck-admission-linux}"
probe="${SENTRYCHECK_NODE_PROBE:-$project_root/bin/sentrycheck-node-probe-linux}"
baseline_report="${SENTRYCHECK_NODE_REPORT:-$project_root/artifacts/live-baselines/go.report.json}"
output="${SENTRYCHECK_NODE_OUTPUT:-$project_root/artifacts/node-runtime}"
temp_base="${SENTRYCHECK_NODE_TEMP_BASE:-/tmp}"
mkdir -p "$output" "$temp_base"
output="$(cd -- "$output" && pwd)"
temp_base="$(cd -- "$temp_base" && pwd)"
if [[ "${SENTRYCHECK_NODE_RECORD:-0}" == 1 && "${SENTRYCHECK_NODE_RECORD_ACTIVE:-0}" != 1 ]]; then
  export SENTRYCHECK_NODE_RECORD_ACTIVE=1
  exec python3 "$project_root/scripts/record_demo.py" --output "$output/demo.cast" --events "$output/demo.events.jsonl" \
    --start-marker SENTRYCHECK_DEMO_BEGIN --stop-marker SENTRYCHECK_DEMO_END \
    --title 'SENTRYCHECK: actual gVisor, runc mismatch, missing runtime, recovery' -- bash "$project_root/scripts/test-node-runtime-live.sh" "$@"
fi
test_root="$(mktemp -d "$temp_base/sentrycheck-node.XXXXXX")"
mkdir -p "$output" "$test_root/bin" "$test_root/controller-credentials" "$test_root/probe-credentials"
python3 - "$output/summary.json" <<'PY'
import json, sys
from datetime import datetime, timezone
from pathlib import Path
Path(sys.argv[1]).write_text(json.dumps({'status':'running','started_at':datetime.now(timezone.utc).isoformat(),'scope':'Real node runtime test; completion has not been established.'},indent=2)+'\n')
PY
if [[ -S /run/k3s/containerd/containerd.sock ]] || ip link show sc-test0 >/dev/null 2>&1; then
  printf '%s\n' 'Existing K3s socket or test bridge found; refusing to disturb another cluster.'
  exit 2
fi
export K3S_DATA_DIR="$test_root/data" KUBECONFIG="$test_root/kubeconfig.yaml"
export SENTRYCHECK_TEST_K3S="$runtime"
export PATH="$test_root/bin:$project_root/.cache/linux/bin:$PATH"
mkdir -p "$K3S_DATA_DIR/agent/etc/containerd"
cat > "$K3S_DATA_DIR/agent/etc/containerd/config-v3.toml.tmpl" <<'TOML'
{{ template "base" . }}
[plugins.'io.containerd.cri.v1.runtime'.containerd.runtimes.runsc]
  runtime_type = "io.containerd.runsc.v1"
TOML
ln -s "$runtime" "$test_root/bin/kubectl"
cat > "$test_root/bin/crictl" <<'SH'
#!/bin/sh
exec "$SENTRYCHECK_TEST_K3S" crictl "$@"
SH
chmod 755 "$test_root/bin/crictl"
cat > "$test_root/cni.conflist" <<'JSON'
{"name":"sentrycheck-live","cniVersion":"1.0.0","plugins":[{"type":"flannel","delegate":{"bridge":"sc-test0","isDefaultGateway":true,"hairpinMode":true}},{"type":"portmap","capabilities":{"portMappings":true}}]}
JSON
setsid "$runtime" server --data-dir "$K3S_DATA_DIR" --write-kubeconfig "$KUBECONFIG" --write-kubeconfig-mode 600 \
  --https-listen-port 16443 --bind-address 127.0.0.1 --node-name sentrycheck-test \
  --flannel-backend=host-gw --flannel-cni-conf "$test_root/cni.conflist" \
  --cluster-cidr 10.99.0.0/16 --service-cidr 10.100.0.0/16 \
  --disable=traefik,servicelb,local-storage,coredns,metrics-server --disable-cloud-controller \
  --kubelet-arg=fail-swap-on=false --kubelet-arg=cgroup-driver=cgroupfs \
  '--kubelet-arg=eviction-hard=nodefs.available<100Mi,imagefs.available<100Mi' \
  --kubelet-arg=image-gc-high-threshold=100 --kubelet-arg=image-gc-low-threshold=99 \
  > "$output/server.log" 2>&1 &
server_pid=$!
cleanup() {
  test_exit=$?
  if (( test_exit != 0 )); then
    python3 - "$output/summary.json" "$test_exit" <<'PY'
import json, sys
from datetime import datetime, timezone
from pathlib import Path
Path(sys.argv[1]).write_text(json.dumps({'status':'failed','finished_at':datetime.now(timezone.utc).isoformat(),'exit_code':int(sys.argv[2]),'scope':'Real node runtime test failed; inspect the retained probe and runtime logs.'},indent=2)+'\n')
PY
  fi
  if [[ -f "$K3S_DATA_DIR/agent/containerd/containerd.log" ]]; then cp "$K3S_DATA_DIR/agent/containerd/containerd.log" "$output/containerd.log"; fi
  kill -TERM -- "-$server_pid" 2>/dev/null || true
  wait "$server_pid" 2>/dev/null || true
  if ! "$test_root/bin/crictl" --runtime-endpoint unix:///run/k3s/containerd/containerd.sock --timeout 1s info >/dev/null 2>&1; then
    rm -f -- /run/k3s/containerd/containerd.sock
  fi
  # sc-test0 was checked absent before this test; no other bridge is touched.
  ip link delete sc-test0 2>/dev/null || true
}
trap cleanup EXIT
ready=false
for attempt in {1..120}; do
  if ! kill -0 "$server_pid" 2>/dev/null; then tail -n 35 "$output/server.log"; exit 2; fi
  if [[ -f "$KUBECONFIG" ]] && kubectl get --raw=/readyz >/dev/null 2>&1; then ready=true; break; fi
  sleep 1
done
if [[ "$ready" != true ]]; then tail -n 35 "$output/server.log"; exit 2; fi
for attempt in {1..90}; do
  if kubectl get node sentrycheck-test >/dev/null 2>&1; then break; fi
  sleep 1
done
kubectl wait --for=condition=Ready node/sentrycheck-test --timeout=90s
cp "$K3S_DATA_DIR/agent/etc/containerd/config.toml" "$output/containerd-config.toml"
pause_image="$(python3 - "$output/containerd-config.toml" <<'PY'
import sys,tomllib
with open(sys.argv[1], 'rb') as source: config=tomllib.load(source)
print(config['plugins']['io.containerd.cri.v1.images']['pinned_images']['sandbox'])
PY
)"
"$test_root/bin/crictl" --runtime-endpoint unix:///run/k3s/containerd/containerd.sock --image-endpoint unix:///run/k3s/containerd/containerd.sock --timeout 120s pull "$pause_image"
kubectl version -o json > "$output/version.json"
kubectl apply -f deploy/namespace.json
kubectl apply -f deploy/snapshot-crd.json
kubectl wait --for=condition=Established crd/sandboxpolicysnapshots.sentrycheck.io --timeout=60s
kubectl apply -f deploy/rbac.json
kubectl apply -f deploy/runtimeclasses.json
"$admission" keygen --private "$test_root/private.pem" --public "$test_root/public.pem"
python3 - "$test_root" "$baseline_report" <<'PY'
import json, sys
from datetime import datetime, timezone
from pathlib import Path
root = Path(sys.argv[1])
config = json.loads(Path('integration/config.example.json').read_text())
config['trustedKeys'] = {'ci': (root / 'public.pem').read_text()}
(root / 'config.json').write_text(json.dumps(config))
report = json.loads(Path(sys.argv[2]).read_text())
pod = {'apiVersion':'v1','kind':'Pod','metadata':{'name':'sentrycheck-runtime-dry-run','labels':{'sentrycheck.io/require-isolation':'true'}},'spec':{'runtimeClassName':'sentrycheck-gvisor','containers':[{'name':'workload','image':'registry.invalid/corpus-go@'+report['image_digest']}]}}
(root / 'pod.json').write_text(json.dumps(pod))
PY
"$admission" attest --report "$baseline_report" --key "$test_root/private.pem" \
  --configmap-namespace sentrycheck-system --output "$test_root/report.json"
kubectl apply -f "$test_root/report.json"
for account in controller node-probe; do
  directory="$test_root/controller-credentials"
  if [[ "$account" == node-probe ]]; then directory="$test_root/probe-credentials"; fi
  kubectl -n sentrycheck-system create token "sentrycheck-$account" --duration=20m > "$directory/token"
  kubectl config view --raw -o jsonpath='{.clusters[0].cluster.certificate-authority-data}' | base64 -d > "$directory/ca.crt"
done
export KUBERNETES_SERVICE_HOST=127.0.0.1 KUBERNETES_SERVICE_PORT_HTTPS=16443
run_probe() {
  local name="$1" binary="$2" handler="$3" expected_code="$4"
  set +e
  SENTRYCHECK_SERVICE_ACCOUNT_DIR="$test_root/probe-credentials" "$probe" --once --publish \
    --node sentrycheck-test --binary "$binary" --handler "$handler" --crictl "$test_root/bin/crictl" \
    --endpoint unix:///run/k3s/containerd/containerd.sock --output "$output/$name.json" > "$output/$name.stdout.json" 2> "$output/$name.stderr.txt"
  local code=$?
  set -e
  if [[ "$code" != "$expected_code" ]]; then cat "$output/$name.stdout.json" "$output/$name.stderr.txt"; exit 2; fi
  if [[ "${SENTRYCHECK_NODE_RECORD_ACTIVE:-0}" == 1 ]]; then
    printf '\n%s\n' "Actual probe result: $name (exit $code)"
    cat "$output/$name.stdout.json"
  fi
}
reconcile() {
  SENTRYCHECK_SERVICE_ACCOUNT_DIR="$test_root/controller-credentials" "$admission" controller --once --config "$test_root/config.json"
}
run_probe healthy "$runsc" runsc 0
reconcile
kubectl get node sentrycheck-test -o json > "$output/healthy-node.json"
kubectl get sandboxpolicysnapshots cluster -o json > "$output/healthy-snapshot.json"
kubectl apply -f deploy/policy.json
kubectl apply -f deploy/binding-strict.json
sleep 3
kubectl create --dry-run=server -f "$test_root/pod.json" > "$output/healthy-admission.txt" 2>&1
if [[ "${SENTRYCHECK_NODE_MEASURE:-0}" == 1 ]]; then
  SENTRYCHECK_SERVICE_ACCOUNT_DIR="$test_root/probe-credentials" python3 scripts/measure_node_probe.py \
    --server-pid "$server_pid" --seconds "${SENTRYCHECK_NODE_MEASURE_SECONDS:-60}" \
    --sample-interval "${SENTRYCHECK_NODE_SAMPLE_SECONDS:-0.2}" --out "$output/overhead" \
    --probe-report "$output/overhead/latest-probe.json" -- \
    "$probe" --publish --interval "${SENTRYCHECK_NODE_PROBE_INTERVAL:-5s}" \
    --node sentrycheck-test --binary "$runsc" --handler runsc --crictl "$test_root/bin/crictl" \
    --endpoint unix:///run/k3s/containerd/containerd.sock --output "$output/overhead/latest-probe.json"
fi
printf '\n%s\n' 'SENTRYCHECK_DEMO_BEGIN'
if [[ "${SENTRYCHECK_NODE_RECORD_ACTIVE:-0}" == 1 ]]; then
  # A fresh invocation makes the recorded healthy state a live observation,
  # even when the optional resource experiment took several minutes first.
  printf '%s\n' 'PHASE 1: verify the actual gVisor runtime and admission'
  run_probe healthy "$runsc" runsc 0
  reconcile
  kubectl get node sentrycheck-test -o json > "$output/healthy-node.json"
  kubectl get sandboxpolicysnapshots cluster -o json > "$output/healthy-snapshot.json"
  kubectl create --dry-run=server -f "$test_root/pod.json" > "$output/healthy-admission.txt" 2>&1
  cat "$output/healthy-admission.txt"
  sleep "${SENTRYCHECK_NODE_DEMO_PAUSE_SECONDS:-0}"
fi
# A real runc canary, despite an expected gVisor type, must raise a mismatch.
printf '\n%s\n' 'PHASE 2: deliberately request a real runc canary while requiring gVisor identity'
run_probe mismatch "$runsc" runc 1
if [[ "${SENTRYCHECK_NODE_RECORD_ACTIVE:-0}" == 1 ]]; then sleep "${SENTRYCHECK_NODE_DEMO_PAUSE_SECONDS:-0}"; fi
printf '\n%s\n' 'PHASE 3: unavailable runtime; revoke health and deny the workload'
run_probe missing "$test_root/nonexistent-runsc" runsc 1
reconcile
kubectl get node sentrycheck-test -o json > "$output/missing-node.json"
kubectl get sandboxpolicysnapshots cluster -o json > "$output/missing-snapshot.json"
sleep 2
if kubectl create --dry-run=server -f "$test_root/pod.json" > "$output/missing-admission.txt" 2>&1; then
  printf '%s\n' 'Unverified runtime was incorrectly admitted'; exit 1
fi
if [[ "${SENTRYCHECK_NODE_RECORD_ACTIVE:-0}" == 1 ]]; then
  cat "$output/missing-admission.txt"
  sleep "${SENTRYCHECK_NODE_DEMO_PAUSE_SECONDS:-0}"
fi
printf '\n%s\n' 'PHASE 4: recover the verified runtime and restore admission'
run_probe recovered "$runsc" runsc 0
reconcile
sleep 2
kubectl create --dry-run=server -f "$test_root/pod.json" > "$output/recovered-admission.txt" 2>&1
if [[ "${SENTRYCHECK_NODE_RECORD_ACTIVE:-0}" == 1 ]]; then cat "$output/recovered-admission.txt"; fi
kubectl -n sentrycheck-system get events -o json > "$output/events.json"
python3 - "$output" <<'PY'
import json, sys
from datetime import datetime, timezone
from pathlib import Path
root = Path(sys.argv[1])
states = {name: json.loads((root / (name+'.json')).read_text())['state'] for name in ['healthy','mismatch','missing','recovered']}
assert states == {'healthy':'canary-verified','mismatch':'isolation-mismatch','missing':'runtime-unavailable','recovered':'canary-verified'}, states
healthy = json.loads((root / 'healthy-snapshot.json').read_text())['spec']['runtimes'][0]
missing = json.loads((root / 'missing-snapshot.json').read_text())['spec']['runtimes'][0]
assert healthy['healthyNodes'] == ['sentrycheck-test'] and not missing['healthyNodes']
labels = json.loads((root / 'missing-node.json').read_text())['metadata'].get('labels',{})
assert healthy['selectorKey'] not in labels
assert 'SENTRYCHECK' in (root / 'missing-admission.txt').read_text()
events = json.loads((root / 'events.json').read_text())['items']
assert any(event.get('reason') == 'RuntimeIsolationUnverified' and event.get('type') == 'Warning' for event in events)
(root / 'summary.json').write_text(json.dumps({'status':'passed','finished_at':datetime.now(timezone.utc).isoformat(),'scope':'Real CRI canaries and Go controller/probe against a disposable Kubernetes node; workload admissions use server dry-run.', 'states':states,'health_label_removed':True,'strict_denial':True,'warning_event':True,'recovery_admitted':True}, indent=2)+'\n')
print('Live node-runtime checks passed: real gVisor, real runc mismatch, missing binary, warning, label removal, strict denial, and recovery.')
PY
printf '\n%s\n' 'SENTRYCHECK_DEMO_END'
