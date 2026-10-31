#!/usr/bin/env bash
# API-server tests of CEL using synthetic policy parameters in a disposable cluster.
# These are not node runtime-attestation tests and launch no runnable workload.
set -euo pipefail
project_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$project_root"
test_dir="$(mktemp -d /tmp/sentrycheck-cel.XXXXXX)"
kubectl apply -f deploy/snapshot-crd.json
kubectl wait --for=condition=Established crd/sandboxpolicysnapshots.sentrycheck.io --timeout=60s
kubectl apply -f deploy/policy.json
python3 - "$test_dir" <<'PY'
import json, sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
root = Path(sys.argv[1])
now = datetime.now(timezone.utc)
managed_name = json.loads(Path('integration/config.example.json').read_text())['runtimes'][0]['name']
runtime = {'name':managed_name,'handler':'runc','runtime':'gvisor','version':'20260921.0','architecture':'amd64','configured':True,'selectorKey':'sentrycheck.io/cel-test','selectorValue':'verified','healthyNodes':['synthetic-node']}
image = {'digest':'sha256:'+'a'*64,'runtime':'gvisor','version':'20260921.0','architecture':'amd64','complete':True,'hardFailure':False,'silentDegradation':False,'reportDigest':'sha256:'+'b'*64}
snapshot = {'apiVersion':'sentrycheck.io/v1alpha1','kind':'SandboxPolicySnapshot','metadata':{'name':'cluster'},'spec':{'generatedAt':now.isoformat(),'expiresAt':(now+timedelta(minutes=5)).isoformat(),'runtimes':[runtime],'images':[image],'warnings':[]}}
pod = {'apiVersion':'v1','kind':'Pod','metadata':{'name':'sentrycheck-cel-dry-run'},'spec':{'runtimeClassName':runtime['name'],'containers':[{'name':'app','image':'registry.invalid/app@'+image['digest']}]}}
rc = {'apiVersion':'node.k8s.io/v1','kind':'RuntimeClass','metadata':{'name':runtime['name']},'handler':'runc','scheduling':{'nodeSelector':{runtime['selectorKey']:runtime['selectorValue'],'kubernetes.io/arch':'amd64'}}}
for name, data in [('snapshot',snapshot),('good',pod),('runtimeclass',rc)]:
    (root/(name+'.json')).write_text(json.dumps(data))
for name in ['tag','unscanned','init','no-runtime']:
    case = json.loads(json.dumps(pod))
    if name == 'tag': case['spec']['containers'][0]['image'] = 'registry.invalid/app:latest'
    if name == 'unscanned': case['spec']['containers'][0]['image'] = 'registry.invalid/app@sha256:'+'c'*64
    if name == 'init': case['spec']['initContainers'] = [{'name':'init','image':'registry.invalid/init:latest'}]
    if name == 'no-runtime':
        del case['spec']['runtimeClassName']
        case['metadata']['labels'] = {'sentrycheck.io/require-isolation':'true'}
    (root/(name+'.json')).write_text(json.dumps(case))
for name in ['missing-runtime','duplicate-runtime','conflicting-images']:
    case = json.loads(json.dumps(snapshot))
    if name == 'missing-runtime': case['spec']['runtimes'] = []
    if name == 'duplicate-runtime': case['spec']['runtimes'].append(runtime)
    if name == 'conflicting-images': case['spec']['images'].append(dict(image, complete=False))
    (root/(name+'.json')).write_text(json.dumps(case))
snapshot['spec']['images'][0]['hardFailure'] = True
(root/'failure.json').write_text(json.dumps(snapshot))
PY
kubectl apply -f "$test_dir/runtimeclass.json"
kubectl apply -f "$test_dir/snapshot.json"
kubectl apply -f deploy/binding-strict.json
for attempt in {1..20}; do
  if response="$(kubectl create --dry-run=server -f "$test_dir/tag.json" 2>&1)"; then :
  elif [[ "$response" == *SENTRYCHECK* ]]; then break; fi
  sleep 1
done
kubectl create --dry-run=server -f "$test_dir/good.json"
for name in tag unscanned init no-runtime; do
  if response="$(kubectl create --dry-run=server -f "$test_dir/$name.json" 2>&1)"; then printf 'Unexpected admission: %s\n' "$name"; exit 1; fi
  if [[ "$response" != *SENTRYCHECK* ]]; then printf 'Wrong rejection reason for %s: %s\n' "$name" "$response"; exit 1; fi
done
for name in missing-runtime duplicate-runtime conflicting-images; do
  kubectl apply -f "$test_dir/snapshot.json"
  admitted=false
  for attempt in {1..20}; do
    if kubectl create --dry-run=server -f "$test_dir/good.json" >/dev/null 2>&1; then admitted=true; break; fi
    sleep 1
  done
  if [[ "$admitted" != true ]]; then printf 'Healthy snapshot did not recover before %s\n' "$name"; exit 1; fi
  kubectl apply -f "$test_dir/$name.json"
  rejected=false
  for attempt in {1..20}; do
    if response="$(kubectl create --dry-run=server -f "$test_dir/good.json" 2>&1)"; then :
    elif [[ "$response" == *SENTRYCHECK* ]]; then rejected=true; break; fi
    sleep 1
  done
  if [[ "$rejected" != true ]]; then printf 'Invalid snapshot unexpectedly admitted: %s\n' "$name"; exit 1; fi
done
kubectl apply -f "$test_dir/failure.json"
sleep 2
if response="$(kubectl create --dry-run=server -f "$test_dir/good.json" 2>&1)"; then printf '%s\n' 'Hard failure admitted'; exit 1; fi
if [[ "$response" != *SENTRYCHECK* ]]; then printf '%s\n' "$response"; exit 1; fi
kubectl apply -f deploy/binding-warn.json
sleep 2
kubectl create --dry-run=server -f "$test_dir/good.json"
kubectl get validatingadmissionpolicy sentrycheck-compatibility -o json > "$test_dir/policy-status.json"
python3 - "$test_dir/policy-status.json" <<'PY'
import json,sys
policy=json.load(open(sys.argv[1]))
warnings=policy.get('status',{}).get('typeChecking',{}).get('expressionWarnings',[])
if warnings: raise SystemExit(json.dumps(warnings,indent=2))
print('API-server CEL checks passed: digest/report/runtime/init gates, omitted/duplicate runtime entries, conflicting image reports, hard failure, and warn-only behavior.')
PY
