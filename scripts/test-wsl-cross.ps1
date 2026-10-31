$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
Set-Location -LiteralPath $projectRoot
$env:CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER = Join-Path $PSScriptRoot 'wsl-linker.cmd'
$env:CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUNNER = Join-Path $PSScriptRoot 'wsl-runner.cmd'
cargo clippy --locked --offline --workspace --all-targets --target x86_64-unknown-linux-gnu -- -D warnings
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
cargo test --locked --offline --workspace --target x86_64-unknown-linux-gnu
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
cargo build --locked --offline --target x86_64-unknown-linux-gnu
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
Copy-Item -LiteralPath 'target/x86_64-unknown-linux-gnu/debug/sentrycheck' -Destination 'bin/sentrycheck-linux' -Force
exit $LASTEXITCODE
