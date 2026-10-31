#!/usr/bin/env bash
# Local measurement/build scratch space. No existing data is removed.
set -euo pipefail
project_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
if [[ "$EUID" != 0 ]]; then printf '%s\n' 'Run this local scratch setup as root.' >&2; exit 2; fi
work="$(mktemp -d /tmp/sentrycheck-v05.XXXXXX)"
[[ "$work" == /tmp/sentrycheck-v05.* && -d "$work" ]] || exit 2
chmod 1777 "$work"
mount -t tmpfs -o size=5G,mode=1777 tmpfs "$work"
mkdir -p "$work/target" "$work/measurements" "$work/tmp" "$work/bin"
chmod 1777 "$work/tmp"
printf '%s\n' "$work" > "$project_root/artifacts/v05-lab-path.txt"
cp -a "$project_root/target/." "$work/target/"
chmod -R a+rwX "$work/target"
printf 'Memory-backed scratch: %s\n' "$work"
df -h "$work"
if [[ "${1:-}" == --shell ]]; then
  export PS1='sentrycheck-lab# '
  exec bash --noprofile --norc
fi
