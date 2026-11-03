#!/usr/bin/env bash
# Link a release `mysh` for Android with the NDK's clang as the linker.
# No C dependencies exist, so only the linker is needed.
#
#   ANDROID_NDK_HOME=/path/to/ndk scripts/android-build.sh [TARGET] [API]
#
# TARGET is one of aarch64-linux-android, armv7-linux-androideabi,
# x86_64-linux-android or i686-linux-android (default aarch64), API 24.
# Falls back to the Homebrew cask location when ANDROID_NDK_HOME is unset.
# scripts/release.sh calls this for every android row of its target table.
set -euo pipefail

target="${1:-aarch64-linux-android}"
api="${2:-24}"
ndk="${ANDROID_NDK_HOME:-/opt/homebrew/share/android-ndk}"

if [ ! -d "$ndk/toolchains/llvm/prebuilt" ]; then
  echo "android-build: NDK not found at $ndk (set ANDROID_NDK_HOME)" >&2
  exit 2
fi

prebuilt=$(ls -d "$ndk"/toolchains/llvm/prebuilt/* | head -n 1)
case "$target" in
  armv7-linux-androideabi) clang_target="armv7a-linux-androideabi" ;;
  *) clang_target="$target" ;;
esac
linker="$prebuilt/bin/${clang_target}${api}-clang"
if [ ! -x "$linker" ]; then
  echo "android-build: linker not found: $linker" >&2
  exit 2
fi

var="CARGO_TARGET_$(echo "$target" | tr 'a-z-' 'A-Z_')_LINKER"
export "$var=$linker"
cd "$(dirname "$0")/.."
cargo build --release --target "$target" -p mysh "${@:3}"
echo "built: target/$target/release/mysh"
