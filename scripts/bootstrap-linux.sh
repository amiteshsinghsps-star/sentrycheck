#!/usr/bin/env bash
# Optional developer/CI setup. Requires root for distro packages. Runtimes are not
# registered with Docker/containerd; runsc and Rust are installed under this repo.
set -euo pipefail
project_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
if [[ "$(id -u)" != 0 ]]; then
  printf '%s\n' 'Run this setup script as root (e.g. sudo bash scripts/bootstrap-linux.sh).'
  exit 2
fi
apt-get update
DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends ca-certificates curl build-essential pkg-config runc strace skopeo python3 xz-utils
mkdir -p "$project_root/.cache/linux/bin"
tools_root="${SENTRYCHECK_TOOLS_DIR:-/tmp/sentrycheck-tools}"
mkdir -p "$tools_root"
export CARGO_HOME="$tools_root/cargo"
export RUSTUP_HOME="$tools_root/rustup"
if [[ ! -x "$CARGO_HOME/bin/cargo" ]]; then
  curl --fail --show-error --silent --location https://sh.rustup.rs --output "$project_root/.cache/linux/rustup-init.sh"
  bash "$project_root/.cache/linux/rustup-init.sh" -y --no-modify-path --profile minimal --default-toolchain 1.94.1
fi
runtime_version="${SENTRYCHECK_RUNSC_VERSION:-20260921.0}"
if [[ ! "$runtime_version" =~ ^[0-9]{8}\.[0-9]+$ ]]; then printf '%s\n' 'Invalid runsc version'; exit 2; fi
runtime_arch="$(uname -m)"
python3 "$project_root/scripts/install_runsc.py" --version "$runtime_version" --arch "$runtime_arch" --out "$project_root/.cache/linux/bin"
"$project_root/.cache/linux/bin/runsc" --version
printf '%s\n' "Linux setup ready. Run: bash scripts/test-linux.sh"
