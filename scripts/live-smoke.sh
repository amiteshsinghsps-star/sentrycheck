#!/usr/bin/env bash
# Real runtime tests of tiny workloads. Requires a disposable Linux environment.
set -euo pipefail
project_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$project_root"
if [[ "$(uname -s)" != Linux ]]; then printf '%s\n' 'Linux is required'; exit 2; fi
scanner="${SENTRYCHECK_BIN:-$project_root/target/debug/sentrycheck}"
if [[ ! -x "$scanner" && -x "$project_root/bin/sentrycheck-linux" ]]; then scanner="$project_root/bin/sentrycheck-linux"; fi
if [[ ! -x "$scanner" && -x "$project_root/target/x86_64-unknown-linux-gnu/debug/sentrycheck" ]]; then scanner="$project_root/target/x86_64-unknown-linux-gnu/debug/sentrycheck"; fi
runtime="${SENTRYCHECK_RUNSC:-$project_root/.cache/linux/bin/runsc}"
output="${SENTRYCHECK_LIVE_OUTPUT:-$project_root/artifacts/live-validation}"
image_root="${SENTRYCHECK_LIVE_IMAGES:-$project_root/artifacts/live-images}"
temp_base="${SENTRYCHECK_TEMP_BASE:-/tmp}"
mkdir -p "$output" "$image_root" "$temp_base"
output="$(cd -- "$output" && pwd)"
run_root="$(mktemp -d "$temp_base/sentrycheck-live.XXXXXX")"
printf '%s\n' "$run_root" > "$output/artifact-root.txt"
python3 scripts/make_fixtures.py --out "$image_root/fixtures"
for name in io_uring io_uring_fallback bpf_optional behavior; do
  gcc -O2 -static "corpus/synthetic/$name.c" -o "$output/$name"
done
python3 - "$project_root" "$output" "$image_root" <<'PY'
import sys
from pathlib import Path
root = Path(sys.argv[1])
output = Path(sys.argv[2])
sys.path.insert(0, str(root / 'scripts'))
from make_fixtures import oci
for name in ['io_uring', 'io_uring_fallback', 'bpf_optional', 'behavior']:
    oci(Path(sys.argv[3]) / name, {'workload': (output / name).read_bytes()})
PY
mode=()
if [[ ! -x "$runtime" ]]; then mode=(--native-only); fi
for name in baseline io_uring io_uring_fallback bpf_optional behavior; do
  image="$image_root/$name"
  if [[ "$name" == baseline ]]; then image="$image_root/fixtures/baseline"; fi
  set +e
  "$scanner" scan "$image" --version 20260921.0 --profile profiles/synthetic.toml \
    --runsc-bin "$runtime" "${mode[@]}" --artifacts "$run_root" \
    --cache "$run_root/cache" --format json --output "$output/$name.report.json" > "$output/$name.stdout.json" 2> "$output/$name.stderr.txt"
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
for report in output.glob('*.report.json'):
    text = report.read_text().replace(str(source), str(destination))
    report.write_text(text)
    data = json.loads(text)
    for run in (data.get('dynamic') or {}).get('sandbox', []):
        if run.get('infrastructure_error'):
            diagnostic = Path(run['stderr_ref']).read_text(errors='replace')
            print(report.stem, 'runtime diagnostic:', diagnostic[:2000])
            break
PY
python3 scripts/summarize_live.py --directory "$output"
