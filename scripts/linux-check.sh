#!/bin/sh
set -eu
uname -a
id
for tool in cargo rustc go gcc cc strace runc runsc skopeo docker kubectl curl sudo; do
  command -v "$tool" || true
done
if command -v cargo >/dev/null 2>&1; then cargo --version; fi
if command -v go >/dev/null 2>&1; then go version; fi
if command -v runc >/dev/null 2>&1; then runc --version; fi
if command -v runsc >/dev/null 2>&1; then runsc --version; fi
project_root="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
for script in "$project_root"/scripts/*.sh; do bash -n "$script"; done
printf '%s\n' 'All checked-in shell scripts passed syntax validation.'
if pgrep -f '/tmp/sentrycheck-node\.[^ /]+/data' >/dev/null 2>&1; then
  printf '%s\n' 'A SENTRYCHECK test-node process is still active.'
else
  printf '%s\n' 'No SENTRYCHECK test-node processes remain.'
fi
