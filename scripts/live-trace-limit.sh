#!/usr/bin/env bash
# Real runc/strace regression of the native trace-file boundary. The workload is
# explicitly synthetic; this measures capture handling, not runtime compatibility.
set -euo pipefail
project_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$project_root"
if [[ "$(uname -s)" != Linux ]]; then printf '%s\n' 'Linux is required'; exit 2; fi
test_root="$(mktemp -d /tmp/sentrycheck-trace-limit.XXXXXX)"
output="$project_root/artifacts/trace-limit"
mkdir -p "$output"
cleanup() {
  # Only delete this script's checked, freshly allocated temporary directory.
  # A surviving rootfs may belong to an incompletely stopped runtime: retain it.
  local resolved
  resolved="$(realpath -e -- "$test_root")" || return
  case "$resolved" in /tmp/sentrycheck-trace-limit.*) ;; *) return ;; esac
  if [[ "$resolved" != "$test_root" || -L "$test_root" ]]; then return; fi
  if [[ -n "$(find "$test_root" -type d -name rootfs -print -quit)" ]]; then
    printf 'Retained temporary runtime files for inspection: %s\n' "$test_root" >&2
    return
  fi
  rm -rf -- "$test_root"
}
trap cleanup EXIT
gcc -O2 -static -Wall -Wextra -Werror corpus/synthetic/trace_flood.c -o "$test_root/workload"
python3 - "$test_root" <<'PY'
import json, sys
from pathlib import Path
sys.path.insert(0, 'scripts')
from make_fixtures import oci
root = Path(sys.argv[1])
oci(root / 'image', {'workload': (root / 'workload').read_bytes()})
(root / 'profile.json').write_text(json.dumps({
    'name': 'native-trace-limit-regression',
    'description': 'Synthetic bounded loop generating guest trace records; tests capture handling only.',
    'command': ['/workload'], 'timeout_seconds': 60, 'repetitions': 1,
    'coverage': 'representative',
}), encoding='utf-8')
PY
scanner="${SENTRYCHECK_BIN:-$project_root/bin/sentrycheck-linux}"
set +e
"$scanner" scan "$test_root/image" --native-only --profile "$test_root/profile.json" \
  --artifacts "$test_root/runs" --cache "$test_root/cache" --format json \
  --output "$output/trace.report.json" > /dev/null 2> "$output/scanner.stderr.txt"
code=$?
set -e
python3 - "$test_root" "$output" "$code" <<'PY'
import hashlib, json, shutil, sys
from pathlib import Path

source, output = map(Path, sys.argv[1:3])
report_path = output / 'trace.report.json'
report = json.loads(report_path.read_text(encoding='utf-8'))
# Keep the evidence usable after the script removes its temporary directory.
for name in ['runs', 'image']:
    shutil.copytree(source / name, output / name, dirs_exist_ok=True,
                    ignore=shutil.ignore_patterns('rootfs', 'state'))
shutil.copy2(source / 'profile.json', output / 'profile.json')
serialized = json.dumps(report, indent=2).replace(str(source), str(output)) + '\n'
report_path.write_text(serialized, encoding='utf-8')
report = json.loads(serialized)

assert sys.argv[3] == '2', f'expected incomplete exit 2, got {sys.argv[3]}'
assert report['status'] == 'incomplete'
assert not any(f['severity'] == 'hard-failure' for f in report['findings'])
assert report['dynamic']['provenance'] == 'locally-executed'
assert len(report['dynamic']['native']) == 1 and not report['dynamic']['sandbox']
run = report['dynamic']['native'][0]
assert run['infrastructure_error'] and 'budget' in run['infrastructure_error'].lower()
assert not run['timed_out'], 'timeout would not establish the capture boundary'
assert run['trace_summary']['truncated'] and run['trace_summary']['event_count'] > 0
assert run['events'], 'bounded trace evidence must be retained'
for stream in ['stdout', 'stderr', 'trace']:
    data = Path(run[stream + '_ref']).read_bytes()
    assert len(data) <= 32 * 1024 * 1024
    assert 'sha256:' + hashlib.sha256(data).hexdigest() == run[stream + '_sha256']
trace_size = Path(run['trace_ref']).stat().st_size
assert trace_size == 32 * 1024 * 1024, trace_size
assert Path(run['stdout_ref']).stat().st_size == 0
assert Path(run['stderr_ref']).stat().st_size == 0
summary = {
    'scenario': 'synthetic-native-guest-trace-overflow',
    'exit_code': int(sys.argv[3]), 'status': report['status'],
    'retained_observations': 1, 'trace_bytes': trace_size,
    'parsed_events': run['trace_summary']['event_count'],
    'truncated': True, 'artifact_hashes_verified': True,
    'infrastructure_error': run['infrastructure_error'],
}
(output / 'summary.json').write_text(json.dumps(summary, indent=2) + '\n', encoding='utf-8')
print('Native trace overflow retained one incomplete observation, a 32 MiB trace prefix, parsed events, and verified artifact hashes.')
PY
