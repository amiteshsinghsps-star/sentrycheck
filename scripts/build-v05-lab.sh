#!/usr/bin/env bash
# Optional local fixture build. Downloads a hash-pinned Go compiler into scratch.
set -euo pipefail
root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
lab="$(tr -d '\r\n' < "$root/artifacts/v05-lab-path.txt")"
[[ "$lab" == /tmp/sentrycheck-v05.* && -d "$lab/bin" ]] || exit 2
python3 - "$lab" <<'PY'
import hashlib, pathlib, sys, tarfile, urllib.request
lab = pathlib.Path(sys.argv[1])
archive = lab / 'go1.25.0.linux-amd64.tar.gz'
if not archive.exists():
    with urllib.request.urlopen('https://go.dev/dl/go1.25.0.linux-amd64.tar.gz', timeout=120) as src, archive.open('wb') as dest:
        while chunk := src.read(1024 * 1024):
            dest.write(chunk)
if archive.stat().st_size != 59659213 or hashlib.file_digest(archive.open('rb'), 'sha256').hexdigest() != '2852af0cb20a13139b3448992e69b868e50ed0f8a1e5940ee1de9e19a123b613':
    raise SystemExit('Go distribution size/hash verification failed')
if not (lab / 'go/bin/go').exists():
    with tarfile.open(archive) as source:
        source.extractall(lab, filter='data')
print('Verified official Go 1.25.0 Linux compiler', flush=True)
PY
export GOCACHE="$lab/go-cache-linux" GOMODCACHE="$lab/go-modcache-linux" GOTMPDIR="$lab/tmp" GOTOOLCHAIN=local CGO_ENABLED=0
"$lab/go/bin/go" -C "$root/corpus/cilium-ebpf" mod tidy
"$lab/go/bin/go" -C "$root/corpus/cilium-ebpf" build -trimpath -o "$lab/bin/cilium-ebpf" .
gcc -O2 -static "$root/corpus/node-uring/uring-helper.c" -luring -o "$lab/bin/uring-helper"
sha256sum "$lab/bin/cilium-ebpf" "$lab/bin/uring-helper"
