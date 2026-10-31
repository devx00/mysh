#!/usr/bin/env bash
# Build release binaries for every supported target and write SHA256SUMS.
#
#   scripts/release.sh [TARGET...]        default: all five targets
#
# Output: dist/mysh-<version>-<target> plus dist/SHA256SUMS.
#
# Linkers (no C dependencies exist, so only a linker is needed per target):
#   *-apple-darwin        the host toolchain (Apple clang links both archs)
#   *-unknown-linux-musl  musl cross gcc: `brew install filosottile/musl-cross/musl-cross`
#                         (or any `<arch>-linux-musl-gcc` on PATH; override with
#                         MUSL_LINKER_<ARCH>)
#   aarch64-linux-android NDK clang via scripts/android-build.sh conventions
#                         (ANDROID_NDK_HOME or the Homebrew cask path)
set -euo pipefail
cd "$(dirname "$0")/.."

version=$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -n 1)
targets=("$@")
if [ ${#targets[@]} -eq 0 ]; then
  targets=(
    aarch64-apple-darwin
    x86_64-apple-darwin
    aarch64-unknown-linux-musl
    x86_64-unknown-linux-musl
    aarch64-linux-android
  )
fi

ndk="${ANDROID_NDK_HOME:-/opt/homebrew/share/android-ndk}"
api="${ANDROID_API:-24}"

linker_for() {
  case "$1" in
    aarch64-unknown-linux-musl) echo "${MUSL_LINKER_AARCH64:-aarch64-linux-musl-gcc}" ;;
    x86_64-unknown-linux-musl) echo "${MUSL_LINKER_X86_64:-x86_64-linux-musl-gcc}" ;;
    aarch64-linux-android)
      local prebuilt
      prebuilt=$(ls -d "$ndk"/toolchains/llvm/prebuilt/* 2>/dev/null | head -n 1)
      echo "$prebuilt/bin/aarch64-linux-android${api}-clang"
      ;;
    *) echo "" ;;
  esac
}

mkdir -p dist
for target in "${targets[@]}"; do
  linker=$(linker_for "$target")
  if [ -n "$linker" ] && ! command -v "$linker" >/dev/null 2>&1 && [ ! -x "$linker" ]; then
    echo "release: no linker for $target ($linker); skipping" >&2
    exit 2
  fi
  var="CARGO_TARGET_$(echo "$target" | tr 'a-z-' 'A-Z_')_LINKER"
  echo "==> $target"
  if [ -n "$linker" ]; then
    env "$var=$linker" cargo build --release --target "$target" -p mysh
  else
    cargo build --release --target "$target" -p mysh
  fi
  cp "target/$target/release/mysh" "dist/mysh-$version-$target"
done

(cd dist && shasum -a 256 mysh-"$version"-* > SHA256SUMS)
echo
cat dist/SHA256SUMS
