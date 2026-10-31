#!/usr/bin/env bash
set -euo pipefail
project_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$project_root"
tools_root="${SENTRYCHECK_TOOLS_DIR:-/tmp/sentrycheck-tools}"
export CARGO_HOME="$tools_root/cargo"
export RUSTUP_HOME="$tools_root/rustup"
export CARGO_TARGET_DIR="$tools_root/target"
export PATH="$CARGO_HOME/bin:$project_root/.cache/linux/bin:$PATH"
cargo test --workspace --locked
cargo build --locked
mkdir -p "$project_root/bin"
cp "$CARGO_TARGET_DIR/debug/sentrycheck" "$project_root/bin/sentrycheck-linux"
