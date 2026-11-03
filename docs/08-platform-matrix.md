# 08 — Platform matrix

What `scripts/release.sh` builds, how each artifact was validated, and what
it would take to add the rest. The target table lives in `scripts/release.sh`
(`TARGETS=`); this file is its human-readable mirror and the record of the
M11 validation run. Keep both in sync when adding a target.

Validation methods:

- **native** — the full test suite runs on that OS/arch (macOS arm64 host;
  aarch64 Linux in the lima VM via `scripts/lima-test.sh`).
- **qemu-user** — `scripts/validate-dist.sh`: the release artifact runs under
  qemu user-mode emulation (docker + `tonistiigi/binfmt`): `mysh --version`,
  `mysh keygen`, a loopback `mysh serve`, and `mysh HOST 'echo ok-from-$(uname
  -m)'` must all succeed.
- **link only** — the artifact links and `file`/`readelf` show the expected
  arch, ABI, and interpreter; no emulator or OS is available here to execute
  it. Behaviour is inferred from `cargo check` on that target plus the
  platform notes in `docs/04-sessions.md`.

## Required set — always built

| target | artifact | linker | validation |
| --- | --- | --- | --- |
| `x86_64-unknown-linux-musl` | ELF static-pie | zig | qemu-user (amd64) |
| `aarch64-unknown-linux-musl` | ELF static | zig | **native** (lima, 444 tests) + qemu-user |
| `i686-unknown-linux-musl` | ELF static | zig | qemu-user (386) |
| `armv7-unknown-linux-musleabihf` | ELF static, EABI5 hard-float | zig | qemu-user (arm/v7) |
| `arm-unknown-linux-musleabihf` (armv6, Pi Zero/1) | ELF static, EABI5 hard-float | zig | qemu-user (arm/v6) |
| `riscv64gc-unknown-linux-musl` | ELF static-pie, RVC double-float | zig | qemu-user (riscv64) |
| `x86_64-unknown-freebsd` | ELF pie, `/libexec/ld-elf.so.1` | zig | link only |
| `aarch64-unknown-freebsd` | ELF pie | zig | link only |
| `aarch64-linux-android` | ELF pie, bionic (`libc`, `libm`, `libdl`) | NDK clang, API 24 | link only |
| `armv7-linux-androideabi` | ELF pie, bionic | NDK clang, API 24 | link only |
| `x86_64-linux-android` | ELF pie, bionic | NDK clang, API 24 | link only |
| `aarch64-apple-darwin` | Mach-O arm64 | host clang | **native** (host, 444 tests) |
| `x86_64-apple-darwin` | Mach-O x86_64 | host clang | link only (Rosetta would run it; not exercised) |
| `universal-apple-darwin` | Mach-O universal (both slices, `lipo`) | `lipo` | `lipo -info`; arm64 slice is the native host binary |

## Stretch set — `scripts/release.sh --stretch`

| target | tier | artifact | linker | validation |
| --- | --- | --- | --- | --- |
| `i686-linux-android` | 2 | ELF pie, bionic | NDK clang | link only |
| `armv5te-unknown-linux-musleabi` | 2 | ELF static, soft-float | zig | qemu-user (arm/v6 image; qemu-arm executes ARMv5) |
| `powerpc64le-unknown-linux-musl` | 2 | ELF static | zig | qemu-user (ppc64le) |
| `s390x-unknown-linux-gnu` | 2 | ELF pie, glibc (`/lib/ld64.so.1`) | zig | qemu-user (s390x, `debian:trixie-slim`) |
| `s390x-unknown-linux-musl` | 3 | ELF static-pie | nightly `build-std` + zig | qemu-user (s390x) |
| `loongarch64-unknown-linux-musl` | 2 | ELF static-pie | zig | qemu-user (loong64, `ghcr.io/loong64/debian`) |
| `mipsel-unknown-linux-musl` | 3 | ELF static | nightly `build-std` + zig, `+crt-static`, `link-self-contained=no` | qemu-user (Alpine `qemu-mipsel`; binfmt has no 32-bit MIPS handler) |
| `mips-unknown-linux-musl` | 3 | ELF static, big-endian | same | qemu-user (Alpine `qemu-mips`) |
| `x86_64-unknown-netbsd` | 2 | ELF pie, `/libexec/ld.elf_so`, NetBSD 10.1 | `zig cc -target x86_64-netbsd` wrapper (cargo-zigbuild rejects netbsd) | link only |
| `aarch64-unknown-netbsd` | 3 | ELF pie, NetBSD 10.1 | nightly `build-std` + zig wrapper | link only |
| `x86_64-unknown-openbsd` | 3 | ELF pie, `/usr/libexec/ld.so`, OpenBSD 7.8 | nightly `build-std` + zig wrapper | link only |
| `aarch64-unknown-openbsd` | 3 | ELF pie, OpenBSD 7.8 | same | link only |

Tier 3 targets are checked by `scripts/check-tier3.sh` (nightly + `rust-src`);
tier 2 stretch targets by `cargo check-matrix-stretch`.

## Not shipped

| target | blocker | what it would take |
| --- | --- | --- |
| `mips64el-unknown-linux-muslabi64` | Links (nightly `build-std`), but under qemu-mips64el `serve` fails with `bind: Protocol not available`: libc 0.2.191 selects asm-generic socket constants (`SOL_SOCKET=1`, `SO_REUSEADDR=2`) for `mips64` instead of the MIPS values (`0xffff`/`0x0004`). Fixed on libc `main`, unreleased. | The next `libc` release (or a `[patch.crates-io]` on libc git, which would change every target's lockfile — not worth it for one stretch arch). The release-script row is one line. |
| `x86_64-unknown-illumos` | `cargo check` passes; no linker can produce the binary here: zig has no illumos libc, Apple `ld` rejects the GNU flags, `rust-lld` refuses the target flavor and `-C link-self-contained` is unsupported. | An illumos sysroot (`libc.so`, `crt1.o`, `libsocket`, `libnsl`, … extracted from OmniOS/OpenIndiana `pkg`) plus a `clang --sysroot` wrapper as the linker, or building on an illumos host. |
| Windows | Out of scope by design: no pty/`openpt`, no Unix sockets, different process model — an architecture port, not a target. | — |

## Runtime notes per family

- **Linux musl (static)**: no dependencies at all; DNS goes through musl's
  resolver (`/etc/resolv.conf`, no `nsswitch`). Validated end to end under
  qemu for every shipped arch.
- **Linux glibc** (`s390x` only, because musl is tier 3 there): dynamic
  against the system glibc; built against zig's glibc 2.x stubs, so it runs
  on any distribution newer than the pinned symbol versions.
- **Android**: dynamic only against bionic; `PIE` as Android requires;
  `/system/bin/sh`, `/data/local/tmp` fallbacks (04). Not executed here: no
  Android emulator in this environment.
- **FreeBSD**: `kern.proc.cwd` sysctl cwd probe, `getpwuid_r`, rustix pty
  calls — all compile-checked on both arches, none executed. The two
  artifacts link against FreeBSD's `libc.so.7` through zig's stubs.
- **NetBSD / OpenBSD**: tier-2/3 artifacts that link against zig's libc
  stubs for NetBSD 10.1 / OpenBSD 7.8 (OpenBSD binaries are release-bound).
  `ptsname` fallbacks and (OpenBSD) `KERN_PROC_CWD` cwd probe compile but
  were never executed; NetBSD's cwd probe is `Unsupported` until the `libc`
  crate exposes `KERN_PROC_CWD`.
- **macOS**: the universal binary is what to distribute; it is not signed or
  notarised (roadmap).

## Targets lacking runtime validation

Anything marked **link only** above: both FreeBSD, all four Android, both
NetBSD, both OpenBSD, and `x86_64-apple-darwin` (as its own slice). The
reasons are the absence of an emulator or OS here, not a known defect. See
"Not shipped" for the one target that *was* emulated and failed.

## Adding a target

1. `rustup target add T` (tier 2) or confirm `cargo +nightly check -Z
   build-std=std,panic_abort --target T` (tier 3).
2. `cargo check --workspace --target T`; fix `cfg` gaps in `mysh-pty` first.
3. Add a row to `TARGETS` in `scripts/release.sh` with the right family
   (`linux-musl`/`linux-gnu`/`freebsd`/`netbsd`/`openbsd` → zig,
   `android` → NDK, `darwin` → host).
4. Add it to `cargo check-matrix[-stretch]` or `scripts/check-tier3.sh`, to
   `rust-toolchain.toml` (tier 2), to the workflows, and — if qemu-user has
   a handler and an image exists — to the platform map in
   `scripts/validate-dist.sh`.
5. Run `scripts/release.sh T` and `scripts/validate-dist.sh`; add the row
   here with the validation method actually achieved.

## Tooling facts (M11 run, macOS arm64)

- `tonistiigi/binfmt --install all` registers qemu for arm, i386,
  loongarch64, mips64, mips64el, ppc64le, riscv64, s390x, x86_64 — **no
  32-bit MIPS**; `validate-dist.sh` runs Alpine's `qemu-mips`/`qemu-mipsel`
  packages inside a host-arch container for those two.
- Images: `alpine:3.20` covers 386/amd64/arm/arm64/ppc64le/riscv64/s390x;
  `debian:trixie-slim` for glibc targets (bookworm dropped s390x);
  `ghcr.io/loong64/debian:trixie-slim` for loong64 (Docker Hub has none).
  `MYSH_DOCKER_LIBRARY` points `validate-dist.sh` at a mirror when Docker
  Hub rate-limits.
- MIPS musl needs `-C target-feature=+crt-static -C link-self-contained=no`:
  rustc's MIPS musl specs default to dynamic linking, zig 0.16's libc layer
  only resolves statically, and nightly ships no self-contained crt objects
  for targets without `rust-std`.
