#!/usr/bin/env bash
# Run CEL checks against a disposable, loopback-only API server. No service install.
set -euo pipefail
project_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$project_root"
runtime="${SENTRYCHECK_K3S:-$project_root/.cache/linux/bin/k3s}"
test_root="$(mktemp -d /tmp/sentrycheck-k3s.XXXXXX)"
output="$project_root/artifacts/admission-api"
mkdir -p "$output" "$test_root/bin"
export K3S_DATA_DIR="$test_root/data"
export KUBECONFIG="$test_root/kubeconfig.yaml"
export PATH="$test_root/bin:$PATH"
ln -s "$runtime" "$test_root/bin/kubectl"
"$runtime" server --disable-agent --data-dir "$K3S_DATA_DIR" \
  --write-kubeconfig "$KUBECONFIG" --write-kubeconfig-mode 600 \
  --https-listen-port 16443 --bind-address 127.0.0.1 --advertise-address 127.0.0.1 \
  --disable=traefik,servicelb,local-storage,coredns,metrics-server \
  --disable-cloud-controller --disable-network-policy > "$output/server.log" 2>&1 &
server_pid=$!
cleanup() {
  kill "$server_pid" 2>/dev/null || true
  wait "$server_pid" 2>/dev/null || true
}
trap cleanup EXIT
ready=false
for attempt in {1..90}; do
  if ! kill -0 "$server_pid" 2>/dev/null; then
    tail -n 35 "$output/server.log"
    exit 2
  fi
  if [[ -f "$KUBECONFIG" ]] && kubectl get --raw=/readyz >/dev/null 2>&1; then ready=true; break; fi
  sleep 1
done
if [[ "$ready" != true ]]; then tail -n 35 "$output/server.log"; exit 2; fi
kubectl version -o json > "$output/version.json"
bash scripts/test-admission-cel.sh 2>&1 | tee "$output/results.txt"
kubectl get validatingadmissionpolicy sentrycheck-compatibility -o json > "$output/policy-status.json"
printf '%s\n' 'Disposable Kubernetes API-server validation completed.'
