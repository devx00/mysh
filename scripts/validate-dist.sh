#!/usr/bin/env bash
# Run every Linux release binary in dist/ under docker + qemu-user (binfmt)
# and do a keygen + loopback serve/exec round trip inside the container.
#
#   scripts/validate-dist.sh [VERSION]
#
# VERSION defaults to the workspace version. Needs docker with multi-arch
# binfmt handlers (`docker run --privileged --rm tonistiigi/binfmt --install all`).
# Prints one line per artifact: PASS <target>, FAIL <target> <reason>, or
# SKIP <target> (no emulator) for darwin/freebsd/android/universal. Exits
# non-zero on any FAIL.
set -euo pipefail
cd "$(dirname "$0")/.."

version="${1:-$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -n 1)}"

# target → docker platform. Slow emulations get a longer round-trip budget.
platform_for() {
  case "$1" in
    x86_64-*) echo linux/amd64 ;;
    aarch64-*) echo linux/arm64 ;;
    i686-*) echo linux/386 ;;
    armv7-*) echo linux/arm/v7 ;;
    arm-*) echo linux/arm/v6 ;;
    riscv64gc-*) echo linux/riscv64 ;;
    powerpc64le-*) echo linux/ppc64le ;;
    s390x-*) echo linux/s390x ;;
    *) echo "" ;;
  esac
}

image_for() {
  case "$1" in
    *-linux-gnu*) echo debian:bookworm-slim ;;
    *) echo alpine:3.20 ;;
  esac
}

roundtrip_timeout() {
  case "$1" in
    riscv64gc-* | s390x-* | powerpc64le-*) echo 120 ;;
    *) echo 30 ;;
  esac
}

if ! command -v docker >/dev/null 2>&1; then
  echo "validate-dist: docker not found" >&2
  exit 2
fi

# Runs inside the container; $1 = binary name, $2 = round-trip timeout.
read -r -d '' inner <<'EOF' || true
set -eu
bin="/dist/$1"; rt="$2"
echo "uname -m: $(uname -m)"
timeout 30 "$bin" --version
mkdir -p /tmp/c /tmp/s
timeout 30 "$bin" keygen -o /tmp/c/id >/dev/null
MYSH_CONFIG_DIR=/tmp/s HOME=/tmp timeout "$rt" "$bin" serve -vv --listen 127.0.0.1:7722 \
  --no-ssh-authorized-keys --authorized-key "$(cat /tmp/c/id.pub)" >/tmp/serve.log 2>&1 &
spid=$!
i=0
while ! grep -q listening /tmp/serve.log 2>/dev/null && [ "$i" -lt "$rt" ]; do
  sleep 1; i=$((i + 1))
  kill -0 "$spid" 2>/dev/null || { cat /tmp/serve.log; echo "serve exited early"; exit 1; }
done
out=$(MYSH_CONFIG_DIR=/tmp/c HOME=/tmp timeout "$rt" "$bin" --accept-new -i /tmp/c/id \
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
  echo "==> $target ($platform, $image)"
  if docker run --rm --platform "$platform" -v "$PWD/dist:/dist:ro" "$image" \
      sh -c "$inner" validate "$name" "$rt" 2>&1 | sed 's/^/    /'; then
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
