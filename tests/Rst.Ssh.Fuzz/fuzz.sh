#!/usr/bin/env bash
# Instrument the parser assembly and run one SharpFuzz target under libFuzzer.
# Usage:  ./fuzz.sh [target]      target ∈ ssh-reader | sftp-attrs | sftp-path | pubkey-verify
#
# One-time setup (see README.md): a Linux host, `dotnet tool install --global SharpFuzz.CommandLine`,
# and a built `libfuzzer-dotnet` binary on PATH.
set -euo pipefail
cd "$(dirname "$0")"

TARGET="${1:-ssh-reader}"
CONFIG=Release
OUT="bin/${CONFIG}/net8.0"

command -v sharpfuzz >/dev/null        || { echo "sharpfuzz not found: dotnet tool install --global SharpFuzz.CommandLine"; exit 1; }
command -v libfuzzer-dotnet >/dev/null || { echo "libfuzzer-dotnet not found on PATH (see README.md)"; exit 1; }

dotnet build -c "$CONFIG"

# Instrument only our own parser assembly (not the BCL).
sharpfuzz "${OUT}/Rst.Ssh.dll"

mkdir -p "corpus/${TARGET}" "findings/${TARGET}"
export FUZZ_TARGET="$TARGET"
exec libfuzzer-dotnet \
  --target_path="${OUT}/Rst.Ssh.Fuzz" \
  -artifact_prefix="findings/${TARGET}/" \
  -timeout=10 -rss_limit_mb=4096 \
  "corpus/${TARGET}"
