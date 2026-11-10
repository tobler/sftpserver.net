#!/bin/sh
# Run one SharpFuzz/libFuzzer target. Usage: <target> [seconds]
set -eu

TARGET="${1:-ssh-reader}"
RUN_SECONDS="${2:-30}"
CORPUS="/src/tests/Rst.Ssh.Fuzz/corpus/${TARGET}"

if [ ! -d "$CORPUS" ]; then
    echo "Unknown target '$TARGET'. Expected one of: ssh-reader sftp-attrs sftp-path pubkey-verify" >&2
    exit 2
fi

export FUZZ_TARGET="$TARGET"
mkdir -p /fuzz/findings
echo "== Fuzzing '${TARGET}' for ${RUN_SECONDS}s =="

exec libfuzzer-dotnet \
    -timeout=10 -rss_limit_mb=4096 -max_total_time="${RUN_SECONDS}" \
    -print_final_stats=1 -artifact_prefix=/fuzz/findings/ \
    --target_path=dotnet --target_arg=/fuzz/bin/Rst.Ssh.Fuzz.dll \
    "$CORPUS"
