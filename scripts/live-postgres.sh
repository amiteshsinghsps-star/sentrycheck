#!/usr/bin/env bash
# Build an official PostgreSQL 18 source release with liburing, then compare runtimes.
# Uses a disposable Linux build directory, no Docker daemon or host database service.
set -euo pipefail
project_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$project_root"
output="${SENTRYCHECK_POSTGRES_OUTPUT:-$project_root/artifacts/live-postgres}"
temp_base="${SENTRYCHECK_TEMP_BASE:-/tmp}"
mkdir -p "$temp_base"
build_root="$(mktemp -d "$temp_base/sentrycheck-postgres.XXXXXX")"
mkdir -p "$output" "$build_root/rootfs"
image="${SENTRYCHECK_POSTGRES_IMAGE:-$project_root/artifacts/live-images/postgres}"
packaged_image="${SENTRYCHECK_POSTGRES_PACKAGED_IMAGE:-$image}"
if [[ -f "$image/index.json" && "${SENTRYCHECK_REBUILD_POSTGRES:-0}" != 1 ]]; then
  python3 scripts/unpack_postgres_fixture.py --image "$image" --rootfs "$build_root/rootfs"
else
if ! pkg-config --exists liburing; then
  apt-get update
  DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends liburing-dev bison flex
fi
version=18.0
source_url="https://ftp.postgresql.org/pub/source/v$version/postgresql-$version.tar.bz2"
curl --fail --silent --show-error --location "$source_url" -o "$build_root/source.tar.bz2"
curl --fail --silent --show-error --location "$source_url.sha256" -o "$build_root/source.sha256"
python3 - "$build_root" "$output" "$source_url" <<'PY'
import hashlib, json, sys, tarfile
from pathlib import Path
root, output = map(Path, sys.argv[1:3])
expected = (root / 'source.sha256').read_text().split()[0]
with (root / 'source.tar.bz2').open('rb') as source:
    actual = hashlib.file_digest(source, 'sha256').hexdigest()
if actual != expected: raise SystemExit('PostgreSQL source checksum mismatch')
(output / 'source.json').write_text(json.dumps({'url': sys.argv[3], 'sha256': actual, 'configure': ['--prefix=/opt/pgsql', '--with-liburing', '--without-icu', '--without-readline', '--without-zlib']}, indent=2)+'\n')
with tarfile.open(root / 'source.tar.bz2') as archive:
    archive.extractall(root, filter='data')
PY
(
  cd "$build_root/postgresql-$version"
  ./configure --prefix=/opt/pgsql --with-liburing --without-icu --without-readline --without-zlib > "$output/configure.log" 2>&1
  make -j4 > "$output/build.log" 2>&1
  make DESTDIR="$build_root/rootfs" install > "$output/install.log" 2>&1
)
fi
# Build-time seed data avoids spending the profile's bounded trace budget on
# one-time system-catalog bootstrap. Every measured run copies a fresh data set.
if [[ ! -d "$build_root/rootfs/seed/pg_notify" ]]; then
  if [[ -d "$build_root/rootfs/seed" ]]; then mv -- "$build_root/rootfs/seed" "$build_root/old-seed"; fi
  chmod 755 "$build_root" "$build_root/rootfs"
  install -d -o nobody -g nogroup -m 700 "$build_root/rootfs/seed"
  runuser -u nobody -- env "LD_LIBRARY_PATH=$build_root/rootfs/opt/pgsql/lib" "$build_root/rootfs/opt/pgsql/bin/initdb" -D "$build_root/rootfs/seed" \
    -U sentrycheck -A trust --locale=C --no-sync > "$output/seed.log" 2>&1
  chmod -R go+rX "$build_root/rootfs/seed"
fi
python3 scripts/package_postgres.py --rootfs "$build_root/rootfs" --out "$packaged_image"
scanner="${SENTRYCHECK_BIN:-$project_root/bin/sentrycheck-linux}"
runtime="${SENTRYCHECK_RUNSC:-$project_root/.cache/linux/bin/runsc}"
set +e
"$scanner" scan "$packaged_image" --version 20260921.0 \
  --profile profiles/postgres-io-uring.toml --runsc-bin "$runtime" --artifacts "$build_root/runs" \
  --cache "${SENTRYCHECK_POSTGRES_CACHE:-$project_root/.cache/postgres-analysis}" --format json --output "$output/postgres.report.json" > "$output/stdout.json" 2> "$output/stderr.txt"
scan_code=$?
set -e
python3 - "$build_root/runs" "$output" "$scan_code" <<'PY'
import json, shutil, sys
from pathlib import Path
source, output = map(Path, sys.argv[1:3])
destination = output / 'runs'
destination.mkdir(exist_ok=True)
for child in source.glob('scan-*'):
    shutil.copytree(child, destination / child.name, dirs_exist_ok=True, ignore=shutil.ignore_patterns('state', 'rootfs'))
path = output / 'postgres.report.json'
if not path.exists(): raise SystemExit((output / 'stderr.txt').read_text()[-4000:])
text = path.read_text().replace(str(source), str(destination))
path.write_text(text)
data = json.loads(text)
dynamic = data.get('dynamic') or {}
summary = {'scope': 'Actual PostgreSQL 18.0 liburing profile; exact source and OCI manifest recorded.', 'image_digest': data['image_digest'], 'status': data['status'],
           'evidence_tier': dynamic.get('evidence_tier'), 'native_exit_codes': [r['exit_code'] for r in dynamic.get('native', [])],
           'sandbox_exit_codes': [r['exit_code'] for r in dynamic.get('sandbox', [])], 'incomplete_reasons': data['incomplete_reasons'],
           'findings': [{'gap_id': f['gap_id'], 'severity': f['severity']} for f in data['findings']], 'duration_ms': data['duration_ms']}
(output / 'summary.json').write_text(json.dumps(summary, indent=2)+'\n')
print(json.dumps(summary, indent=2))
if not (data['status'] == 'complete' and summary['native_exit_codes'] == [0, 0, 0] and any(f['severity'] == 'hard-failure' for f in data['findings'])):
    raise SystemExit(2)
PY
