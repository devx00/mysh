#!/usr/bin/env bash
# Build release binaries for the support matrix and write SHA256SUMS.
#
#   scripts/release.sh [--stretch] [TARGET...]
#
# With no TARGET the *required* set is built (every row of the table below
# whose last column is `required`); `--stretch` or MYSH_STRETCH=1 adds the
# stretch rows. Output: dist/mysh-<version>-<target>, a `lipo` universal
# macOS binary when both darwin targets were built, and dist/SHA256SUMS.
#
# Linkers (no C dependencies exist, so only a linker is needed per target):
#   darwin      the host toolchain (Apple clang links both archs; `lipo`
#               merges them into mysh-<version>-universal-apple-darwin)
#   linux-musl  `cargo zigbuild` (brew install zig && cargo install
#   linux-gnu   cargo-zigbuild). MUSL_LINKER_AARCH64 / MUSL_LINKER_X86_64 may
#   freebsd     name a musl cross gcc instead for those two targets, in which
#               case plain `cargo build` is used. Zig prints
#               `argument unused during compilation: '-nostartfiles'` on
#               32-bit ARM musl; it is a warning and the link succeeds.
#   android     NDK clang (API 24) through scripts/android-build.sh
#               (ANDROID_NDK_HOME or the Homebrew cask path)
set -euo pipefail
cd "$(dirname "$0")/.."

# target  family  tier  set
# `family` selects the linker; `tier` is the rustc tier (2 = std ships);
# `set` is `required` (built by default) or `stretch` (`--stretch`).
TARGETS=(
  "x86_64-unknown-linux-musl         linux-musl 2 required"
  "aarch64-unknown-linux-musl        linux-musl 2 required"
  "i686-unknown-linux-musl           linux-musl 2 required"
  "armv7-unknown-linux-musleabihf    linux-musl 2 required"
  "arm-unknown-linux-musleabihf      linux-musl 2 required"
  "riscv64gc-unknown-linux-musl      linux-musl 2 required"
  "x86_64-unknown-freebsd            freebsd    2 required"
  "aarch64-unknown-freebsd           freebsd    2 required"
  "aarch64-linux-android             android    2 required"
  "armv7-linux-androideabi           android    2 required"
  "x86_64-linux-android              android    2 required"
  "aarch64-apple-darwin              darwin     1 required"
  "x86_64-apple-darwin               darwin     1 required"
  "powerpc64le-unknown-linux-musl    linux-musl 2 stretch"
  "loongarch64-unknown-linux-musl    linux-musl 2 stretch"
  "s390x-unknown-linux-gnu           linux-gnu  2 stretch"
  "i686-linux-android                android    2 stretch"
)

stretch="${MYSH_STRETCH:-0}"
targets=()
for arg in "$@"; do
  case "$arg" in
    --stretch) stretch=1 ;;
    -h | --help) sed -n '2,22p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) targets+=("$arg") ;;
  esac
done

row_for() {
  local row
  for row in "${TARGETS[@]}"; do
    case "$row" in "$1 "*) echo "$row"; return 0 ;; esac
  done
  return 1
}

if [ ${#targets[@]} -eq 0 ]; then
  for row in "${TARGETS[@]}"; do
    set -- $row
    if [ "$4" = required ] || [ "$stretch" = 1 ]; then
      targets+=("$1")
    fi
  done
fi

version=$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -n 1)

need_zig() {
  if ! command -v zig >/dev/null 2>&1 || ! cargo zigbuild --help >/dev/null 2>&1; then
    echo "release: $1 needs zig and cargo-zigbuild:" >&2
    echo "  brew install zig && cargo install cargo-zigbuild" >&2
    exit 2
  fi
}

# Linker env override for the two original musl targets (musl cross gcc).
musl_override() {
  case "$1" in
    aarch64-unknown-linux-musl) echo "${MUSL_LINKER_AARCH64:-}" ;;
    x86_64-unknown-linux-musl) echo "${MUSL_LINKER_X86_64:-}" ;;
    *) echo "" ;;
  esac
}

build_one() {
  local target="$1" family="$2" override
  case "$family" in
    darwin)
      cargo build --release --target "$target" -p mysh
      ;;
    linux-musl | linux-gnu | freebsd)
      override=$(musl_override "$target")
      if [ -n "$override" ]; then
        if ! command -v "$override" >/dev/null 2>&1 && [ ! -x "$override" ]; then
          echo "release: linker for $target not found: $override" >&2
          exit 2
        fi
        env "CARGO_TARGET_$(echo "$target" | tr 'a-z-' 'A-Z_')_LINKER=$override" \
          cargo build --release --target "$target" -p mysh
      else
        need_zig "$target"
        cargo zigbuild --release --target "$target" -p mysh
      fi
      ;;
    android)
      scripts/android-build.sh "$target" "${ANDROID_API:-24}"
      ;;
    *)
      echo "release: unknown family $family for $target" >&2
      exit 2
      ;;
  esac
}

mkdir -p dist
built=()
for target in "${targets[@]}"; do
  if ! row=$(row_for "$target"); then
    echo "release: $target is not in the target table" >&2
    exit 2
  fi
  set -- $row
  echo "==> $target ($2, tier $3, $4)"
  build_one "$target" "$2"
  cp "target/$target/release/mysh" "dist/mysh-$version-$target"
  built+=("mysh-$version-$target")
done

universal="dist/mysh-$version-universal-apple-darwin"
if [ -f "dist/mysh-$version-aarch64-apple-darwin" ] && [ -f "dist/mysh-$version-x86_64-apple-darwin" ]; then
  if command -v lipo >/dev/null 2>&1; then
    echo "==> universal-apple-darwin (lipo)"
    lipo -create -output "$universal" \
      "dist/mysh-$version-aarch64-apple-darwin" "dist/mysh-$version-x86_64-apple-darwin"
    built+=("mysh-$version-universal-apple-darwin")
  else
    echo "release: lipo not found; skipping the universal macOS binary" >&2
  fi
fi

if command -v sha256sum >/dev/null 2>&1; then
  sha=(sha256sum)
else
  sha=(shasum -a 256)
fi
(cd dist && "${sha[@]}" mysh-"$version"-* > SHA256SUMS && "${sha[@]}" -c SHA256SUMS >/dev/null)

echo
printf '%-40s %10s  %s\n' TARGET SIZE FILE
for name in "${built[@]}"; do
  size=$(wc -c < "dist/$name" | tr -d ' ')
  desc=$(file -b "dist/$name" | head -n 1 | cut -c1-60)
  printf '%-40s %10s  %s\n' "${name#mysh-$version-}" "$size" "$desc"
done
echo
echo "dist/SHA256SUMS: $(wc -l < dist/SHA256SUMS | tr -d ' ') entries, verified"
