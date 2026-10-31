#!/usr/bin/env bash
# Representative Python, Node, and Go profiles; registry references resolve to digests.
set -euo pipefail
project_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$project_root"
scanner="${SENTRYCHECK_BIN:-$project_root/bin/sentrycheck-linux}"
runtime="${SENTRYCHECK_RUNSC:-$project_root/.cache/linux/bin/runsc}"
output="${SENTRYCHECK_BASELINES_OUTPUT:-$project_root/artifacts/live-baselines}"
temp_base="${SENTRYCHECK_TEMP_BASE:-/tmp}"
image_root="${SENTRYCHECK_LIVE_IMAGES:-$project_root/artifacts/live-images}"
go_workload="${SENTRYCHECK_GO_WORKLOAD:-$project_root/bin/go-workload}"
mkdir -p "$temp_base" "$output" "$image_root" "$(dirname -- "$go_workload")"
run_root="$(mktemp -d "$temp_base/sentrycheck-baselines.XXXXXX")"
if [[ ! -f "$go_workload" ]]; then
  CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o "$go_workload" corpus/go/main.go
fi
python3 - "$project_root" "$image_root" "$go_workload" <<'PY'
import sys
from pathlib import Path
root = Path(sys.argv[1])
sys.path.insert(0, str(root / 'scripts'))
from make_fixtures import oci
oci(Path(sys.argv[2]) / 'go', {'workload': Path(sys.argv[3]).read_bytes()})
PY
for name in python node go; do
  case "$name" in
    python) image="${SENTRYCHECK_PYTHON_IMAGE:-docker.io/library/python:3.12-slim}" ;;
    node) image="${SENTRYCHECK_NODE_IMAGE:-docker.io/library/node:22-alpine}" ;;
    go) image="$image_root/go" ;;
  esac
  printf 'Scanning %s\n' "$name"
  set +e
  "$scanner" scan "$image" --version 20260921.0 --profile "profiles/$name.toml" \
    --runsc-bin "$runtime" --artifacts "$run_root" --cache "${SENTRYCHECK_BASELINES_CACHE:-$project_root/.cache/live-baselines}" \
    --format json --output "$output/$name.report.json" > "$output/$name.stdout.json" 2> "$output/$name.stderr.txt"
  scan_code=$?
  set -e
  if (( scan_code > 2 )); then printf 'Scanner crashed on %s\n' "$name"; exit "$scan_code"; fi
done
python3 - "$run_root" "$output" <<'PY'
import json, shutil, sys
from pathlib import Path
source, output = map(Path, sys.argv[1:])
destination = output / 'runs'
destination.mkdir(exist_ok=True)
for child in source.glob('scan-*'):
    shutil.copytree(child, destination / child.name, dirs_exist_ok=True, ignore=shutil.ignore_patterns('state', 'rootfs'))
rows = []
for name in ['python', 'node', 'go']:
    path = output / (name + '.report.json')
    if not path.exists():
        rows.append({'case': name, 'status': 'scan-error', 'error': (output / (name + '.stderr.txt')).read_text()[-4000:]})
        continue
    text = path.read_text().replace(str(source), str(destination))
    path.write_text(text)
    data = json.loads(text)
    dynamic = data.get('dynamic') or {}
    rows.append({'case': name, 'image_digest': data['image_digest'], 'status': data['status'], 'evidence_tier': dynamic.get('evidence_tier'),
                 'native_exit_codes': [r['exit_code'] for r in dynamic.get('native', [])], 'sandbox_exit_codes': [r['exit_code'] for r in dynamic.get('sandbox', [])],
                 'findings': [{'gap_id': f['gap_id'], 'severity': f['severity']} for f in data['findings']], 'incomplete_reasons': data['incomplete_reasons'], 'duration_ms': data['duration_ms']})
(output / 'summary.json').write_text(json.dumps({'scope': 'Profile-bounded live Python, Node, and Go observations; not full language regression suites.', 'cases': rows}, indent=2) + '\n')
for row in rows:
    print(json.dumps(row))
if not all(row['status'] == 'complete' and row.get('native_exit_codes') == [0, 0, 0] and row.get('sandbox_exit_codes') == [0, 0, 0] and not any(f['severity'] in ['hard-failure', 'silent-degradation'] for f in row.get('findings', [])) for row in rows):
    raise SystemExit(2)
PY
