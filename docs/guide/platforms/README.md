# Platforms

mysh ships one static or dynamically linked binary per target; the client
and the server are the same executable. This page is the map; the
per-platform pages say how to install, run as a service, and what differs.
The authoritative record of what is built and how each artifact was
validated is [docs/08-platform-matrix.md](../../08-platform-matrix.md);
the table below mirrors it.

Artifacts are named `mysh-<version>-<target>` (for example
`mysh-0.1.0-aarch64-unknown-linux-musl`) and come with a `SHA256SUMS`
file. Validation means:

| status | meaning |
| --- | --- |
| **native** | the full test suite runs on that OS and architecture |
| **qemu-user** | the release artifact ran `--version`, `keygen`, a loopback `serve` and a remote `exec` under qemu user-mode emulation |
| **link only** | the artifact links and has the expected arch, ABI and interpreter; it has not been executed anywhere |

## Required set

Built by every release.

| OS | arch | artifact | linking | validation |
| --- | --- | --- | --- | --- |
| [Linux](linux.md) | x86_64 | `x86_64-unknown-linux-musl` | static-pie | qemu-user |
| Linux | aarch64 | `aarch64-unknown-linux-musl` | static | native (lima VM) + qemu-user |
| Linux | i686 | `i686-unknown-linux-musl` | static | qemu-user |
| Linux | armv7 hard-float | `armv7-unknown-linux-musleabihf` | static | qemu-user |
| Linux | armv6 hard-float | `arm-unknown-linux-musleabihf` | static | qemu-user |
| Linux | riscv64 | `riscv64gc-unknown-linux-musl` | static-pie | qemu-user |
| [FreeBSD](freebsd.md) | x86_64 | `x86_64-unknown-freebsd` | dynamic (`libc.so.7`) | link only |
| FreeBSD | aarch64 | `aarch64-unknown-freebsd` | dynamic | link only |
| [Android](android.md) | aarch64 | `aarch64-linux-android` | dynamic (bionic, API 24) | link only |
| Android | armv7 | `armv7-linux-androideabi` | dynamic (bionic, API 24) | link only |
| Android | x86_64 | `x86_64-linux-android` | dynamic (bionic, API 24) | link only |
| [macOS](macos.md) | arm64 | `aarch64-apple-darwin` | dynamic (system libs) | native (host) |
| macOS | x86_64 | `x86_64-apple-darwin` | dynamic | link only |
| macOS | both | `universal-apple-darwin` | `lipo` of the two above | `lipo -info`; the arm64 slice is the native binary |

## Stretch set

Built with `scripts/release.sh --stretch`; best effort.

| OS | arch | artifact | linking | validation |
| --- | --- | --- | --- | --- |
| Android | i686 | `i686-linux-android` | dynamic (bionic) | link only |
| Linux | armv5 soft-float | `armv5te-unknown-linux-musleabi` | static | qemu-user |
| Linux | ppc64le | `powerpc64le-unknown-linux-musl` | static | qemu-user |
| Linux | s390x | `s390x-unknown-linux-gnu` | dynamic (glibc) | qemu-user |
| Linux | s390x | `s390x-unknown-linux-musl` | static-pie | qemu-user |
| Linux | loongarch64 | `loongarch64-unknown-linux-musl` | static-pie | qemu-user |
| Linux | mipsel | `mipsel-unknown-linux-musl` | static | qemu-user |
| Linux | mips (big-endian) | `mips-unknown-linux-musl` | static | qemu-user |
| [NetBSD](netbsd-openbsd.md) | x86_64 | `x86_64-unknown-netbsd` | dynamic (NetBSD 10.1) | link only |
| NetBSD | aarch64 | `aarch64-unknown-netbsd` | dynamic (NetBSD 10.1) | link only |
| [OpenBSD](netbsd-openbsd.md) | x86_64 | `x86_64-unknown-openbsd` | dynamic (OpenBSD 7.8) | link only |
| OpenBSD | aarch64 | `aarch64-unknown-openbsd` | dynamic (OpenBSD 7.8) | link only |

## Not shipped

| target | why |
| --- | --- |
| `mips64el-unknown-linux-muslabi64` | Links, but `serve` fails under emulation with `bind: Protocol not available`: the `libc` crate release in use picks the wrong socket constants for mips64. Fixed upstream, not yet released. |
| illumos (`x86_64-unknown-illumos`) | Type-checks, but no linker available in the release environment can produce the binary; it needs an illumos sysroot or an illumos build host. |
| Windows | Out of scope by design: no pty, no Unix sockets, a different process model. |

Details and what it would take: [docs/08 "Not shipped"](../../08-platform-matrix.md#not-shipped).

## Picking a binary

```sh
uname -sm
```

| `uname -sm` | artifact |
| --- | --- |
| `Linux x86_64` | `x86_64-unknown-linux-musl` |
| `Linux aarch64` | `aarch64-unknown-linux-musl` |
| `Linux armv7l` | `armv7-unknown-linux-musleabihf` |
| `Linux armv6l` | `arm-unknown-linux-musleabihf` |
| `Linux i686` | `i686-unknown-linux-musl` |
| `Linux riscv64` | `riscv64gc-unknown-linux-musl` |
| `Darwin arm64` / `Darwin x86_64` | `universal-apple-darwin` |
| `FreeBSD amd64` / `FreeBSD arm64` | `x86_64-unknown-freebsd` / `aarch64-unknown-freebsd` |
| Android (`adb shell uname -m` → `aarch64`) | `aarch64-linux-android` |

Every Linux artifact is musl and static (except the s390x glibc one), so
the same file runs on any distribution and on systems without a libc at
all. The install procedure is identical everywhere: copy the file, make it
executable, run it. See [building](building.md) to build any of these from
source, and [library](../library.md) to embed the client in a Rust program.
