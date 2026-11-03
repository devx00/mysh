#!/usr/bin/env bash
# Run every Linux release binary in dist/ under docker + qemu-user (binfmt)
# and do a keygen + loopback serve/exec round trip inside the container.
#
#   scripts/validate-dist.sh [VERSION]
#
# VERSION defaults to the workspace version. Needs docker with multi-arch
# binfmt handlers (`docker run --privileged --rm tonistiigi/binfmt --install all`).
# Prints one line per artifact: PASS <target>, FAIL <target> <reason>, or
# SKIP <target> (no emulator) for darwin/freebsd/netbsd/openbsd/android/universal.
# Exits non-zero on any FAIL. MYSH_DOCKER_LIBRARY (default
# `docker.io/library`) prefixes the official images, e.g.
# `mirror.gcr.io/library` when Docker Hub rate-limits unauthenticated pulls.
set -euo pipefail
cd "$(dirname "$0")/.."

version="${1:-$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -n 1)}"
library="${MYSH_DOCKER_LIBRARY:-docker.io/library}"

# target → docker platform. Slow emulations get a longer round-trip budget.
# armv5te runs on the arm/v6 image: qemu-arm executes ARMv5 code and the
# musl binary is static, so the image only has to supply `sh`. `native`
# means no `--platform`: the binary runs inside the host-arch image either
# through the binfmt handler (mips64le, which no registry publishes an
# image for) or through a qemu-user package installed in the container
# (`emulator_for`; binfmt ships no 32-bit MIPS handler). `uname -m` then
# reports the host, on both sides of the round trip.
platform_for() {
  case "$1" in
    x86_64-*) echo linux/amd64 ;;
    aarch64-*) echo linux/arm64 ;;
    i686-*) echo linux/386 ;;
    armv7-*) echo linux/arm/v7 ;;
    arm-* | armv5te-*) echo linux/arm/v6 ;;
    riscv64gc-*) echo linux/riscv64 ;;
    powerpc64le-*) echo linux/ppc64le ;;
    s390x-*) echo linux/s390x ;;
    loongarch64-*) echo linux/loong64 ;;
    mips64el-* | mipsel-* | mips-*) echo native ;;
    *) echo "" ;;
  esac
}

# Alpine `qemu-<arch>` package used as an explicit interpreter.
emulator_for() {
  case "$1" in
    mipsel-*) echo qemu-mipsel ;;
    mips-*) echo qemu-mips ;;
    *) echo "" ;;
  esac
}

# `debian:bookworm-slim` no longer publishes s390x; trixie does. Docker Hub
# has no loong64 image; the loong64 project's debian mirror only has to
# supply `sh` (the musl binary is static).
image_for() {
  case "$1" in
    loongarch64-*) echo ghcr.io/loong64/debian:trixie-slim ;;
    *-linux-gnu*) echo "$library/debian:trixie-slim" ;;
    *) echo "$library/alpine:3.20" ;;
  esac
}

roundtrip_timeout() {
  case "$1" in
    riscv64gc-* | s390x-* | powerpc64le-* | loongarch64-* | mips64el-*) echo 120 ;;
    *) echo 30 ;;
  esac
}

if ! command -v docker >/dev/null 2>&1; then
  echo "validate-dist: docker not found" >&2
  exit 2
fi

# Runs inside the container; $1 = binary name, $2 = round-trip timeout,
# $3 = qemu-user package to install and prefix the binary with (or empty).
read -r -d '' inner <<'EOF' || true
set -eu
bin="/dist/$1"; rt="$2"; emu="${3:-}"
[ -z "$emu" ] || apk add -q "$emu"
echo "uname -m: $(uname -m)"
timeout 30 $emu "$bin" --version
mkdir -p /tmp/c /tmp/s
timeout 30 $emu "$bin" keygen -o /tmp/c/id >/dev/null
MYSH_CONFIG_DIR=/tmp/s HOME=/tmp timeout "$rt" $emu "$bin" serve -vv --listen 127.0.0.1:7722 \
  --no-ssh-authorized-keys --authorized-key "$(cat /tmp/c/id.pub)" >/tmp/serve.log 2>&1 &
spid=$!
i=0
while ! grep -q listening /tmp/serve.log 2>/dev/null && [ "$i" -lt "$rt" ]; do
  sleep 1; i=$((i + 1))
  kill -0 "$spid" 2>/dev/null || { cat /tmp/serve.log; echo "serve exited early"; exit 1; }
done
out=$(MYSH_CONFIG_DIR=/tmp/c HOME=/tmp timeout "$rt" $emu "$bin" --accept-new -i /tmp/c/id \
  127.0.0.1:7722 'echo ok-from-$(uname -m)' 2>/tmp/client.log) || {
  cat /tmp/client.log /tmp/serve.log; echo "exec failed"; exit 1; }
kill "$spid" 2>/dev/null || true
echo "exec output: $out"
[ "$out" = "ok-from-$(uname -m)" ] || { echo "unexpected exec output: $out"; exit 1; }
EOF

fail=0
pass=0
skip=0
shopt -s nullglob
for path in dist/mysh-"$version"-*; do
  name=$(basename "$path")
  target="${name#mysh-$version-}"
  case "$target" in
    *-linux-musl* | *-linux-gnu*) ;;
    *)
      echo "SKIP $target (no emulator)"
      skip=$((skip + 1))
      continue
      ;;
  esac
  platform=$(platform_for "$target")
  if [ -z "$platform" ]; then
    echo "SKIP $target (no docker platform mapping)"
    skip=$((skip + 1))
    continue
  fi
  image=$(image_for "$target")
  rt=$(roundtrip_timeout "$target")
  emu=$(emulator_for "$target")
  run=(docker run --rm)
  [ "$platform" = native ] || run+=(--platform "$platform")
  echo "==> $target ($platform, $image${emu:+, $emu})"
  if "${run[@]}" -v "$PWD/dist:/dist:ro" "$image" \
      sh -c "$inner" validate "$name" "$rt" "$emu" 2>&1 | sed 's/^/    /'; then
    echo "PASS $target"
    pass=$((pass + 1))
  else
    echo "FAIL $target (see output above)"
    fail=$((fail + 1))
  fi
done

echo
echo "validate-dist: $pass passed, $fail failed, $skip skipped"
[ "$fail" -eq 0 ]
