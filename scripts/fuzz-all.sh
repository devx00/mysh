#!/usr/bin/env bash
# Build every fuzz target and run each for SECONDS (default 5), then summarise.
# Requires a nightly toolchain and cargo-fuzz (`cargo install cargo-fuzz`).
# The root workspace pins a stable toolchain, so nightly is selected explicitly.
set -u
cd "$(dirname "$0")/.."
seconds="${1:-5}"

cargo +nightly fuzz build || exit 1

pass=() fail=()
for target in $(cargo +nightly fuzz list); do
    echo "=== $target (${seconds}s)"
    if cargo +nightly fuzz run "$target" -- -max_total_time="$seconds"; then
        pass+=("$target")
    else
        fail+=("$target")
    fi
done

echo
echo "passed (${#pass[@]}): ${pass[*]:-}"
echo "failed (${#fail[@]}): ${fail[*]:-}"
[ "${#fail[@]}" -eq 0 ]
