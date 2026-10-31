#!/usr/bin/env bash
# Local v0.2 review checks. Workloads require a disposable Linux host with installed runtimes.
set -euo pipefail
project_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$project_root"
mkdir -p artifacts/review
export SENTRYCHECK_BIN="$project_root/bin/sentrycheck-linux"
"$SENTRYCHECK_BIN" doctor --runsc-bin "$project_root/.cache/linux/bin/runsc" \
  --profile profiles/python.toml --format json > artifacts/review/doctor-linux.json
python3 -m unittest discover -s tests -v
bash scripts/live-smoke.sh
bash scripts/live-capture-limit.sh
bash scripts/live-trace-limit.sh
bash scripts/live-baselines.sh
bash scripts/live-postgres.sh
"$SENTRYCHECK_BIN" report validate artifacts/live-validation/io_uring.report.json \
  --artifacts-root "$project_root" --format json > artifacts/review/validated-live.json
"$SENTRYCHECK_BIN" report diff artifacts/live-baselines/python.report.json \
  artifacts/live-baselines/python.report.json --format json > artifacts/review/unchanged-live.json
python3 scripts/record_validation.py
