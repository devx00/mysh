#!/usr/bin/env bash
# Type-check the tier-3 stretch targets (no prebuilt `std`): nightly builds
# the standard library from source with `-Z build-std`.
#
#   scripts/check-tier3.sh [TARGET...]
#
# With no TARGET every tier-3 row of the scripts/release.sh table is
# checked. A cargo alias cannot select a toolchain, so this lives in a
# script; `.cargo/config.toml` points here from `check-matrix-stretch`.
# Needs `rustup toolchain install nightly --component rust-src`.
set -euo pipefail
cd "$(dirname "$0")/.."

# Mirrors the tier-3 rows of scripts/release.sh.
TIER3=(
  s390x-unknown-linux-musl
  x86_64-unknown-openbsd
  aarch64-unknown-openbsd
  aarch64-unknown-netbsd
  mipsel-unknown-linux-musl
  mips-unknown-linux-musl
)

targets=("$@")
[ ${#targets[@]} -gt 0 ] || targets=("${TIER3[@]}")

if ! rustup run nightly rustc --print sysroot >/dev/null 2>&1 \
    || [ ! -d "$(rustup run nightly rustc --print sysroot)/lib/rustlib/src/rust/library" ]; then
  echo "check-tier3: needs nightly with rust-src:" >&2
  echo "  rustup toolchain install nightly --component rust-src" >&2
  exit 2
fi

for target in "${targets[@]}"; do
  echo "==> $target"
  cargo +nightly check -Z build-std=std,panic_abort --workspace --target "$target"
done
