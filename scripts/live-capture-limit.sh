#!/usr/bin/env bash
# Regression: excess output must retain incomplete evidence instead of losing the run.
set -euo pipefail
project_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$project_root"
test_root="$(mktemp -d /tmp/sentrycheck-capture.XXXXXX)"
output="$project_root/artifacts/capture-limit"
mkdir -p "$output"
gcc -O2 -static corpus/synthetic/output_flood.c -o "$test_root/workload"
python3 - "$test_root" <<'PY'
import json, sys
from pathlib import Path
sys.path.insert(0, 'scripts')
from make_fixtures import oci
root = Path(sys.argv[1])
oci(root / 'image', {'workload': (root / 'workload').read_bytes()})
(root / 'profile.json').write_text(json.dumps({'name':'capture-limit-regression','command':['/workload'],'timeout_seconds':15,'repetitions':1,'coverage':'representative'}))
PY
scanner="${SENTRYCHECK_BIN:-$project_root/bin/sentrycheck-linux}"
set +e
"$scanner" scan "$test_root/image" --native-only --profile "$test_root/profile.json" \
  --artifacts "$test_root/runs" --cache "$test_root/cache" --format json --output "$output/capture.report.json" > /dev/null
code=$?
set -e
python3 - "$output/capture.report.json" "$code" <<'PY'
import hashlib, json, sys
from pathlib import Path
report = json.loads(Path(sys.argv[1]).read_text())
assert sys.argv[2] == '2' and report['status'] == 'incomplete'
assert not any(f['severity'] == 'hard-failure' for f in report['findings'])
assert len(report['dynamic']['native']) == 1
run = report['dynamic']['native'][0]
assert run['infrastructure_error'] and run['trace_summary']['truncated']
data = Path(run['stdout_ref']).read_bytes()
assert len(data) <= 32 * 1024 * 1024
assert 'sha256:' + hashlib.sha256(data).hexdigest() == run['stdout_sha256']
print('Capture overflow retained one incomplete observation, bounded output, and matching artifact hash.')
PY
