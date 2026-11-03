# Building from source

mysh is a Rust workspace with no C dependencies: a native build needs only
the pinned toolchain, and a cross build needs only a *linker* for the
target. The design notes are in
[docs/01 "Build"](../../01-architecture.md#build); this page is the
operator's version.

## Native build

```sh
git clone https://github.com/zachhanson94/mysh && cd mysh
cargo build --release
./target/release/mysh --version
```

`rust-toolchain.toml` pins the compiler (`channel = "1.99.1"` with
`rustfmt` and `clippy`); rustup installs it on the first `cargo` call,
together with every tier-2 cross target listed in the same file. The
workspace's `rust-version` matches, so an older stable toolchain refuses
to build it rather than failing halfway. The result is one binary,
`target/release/mysh`, which is both the client and the server; the
`mysh-client` library crate builds as part of it
([library](../library.md)).

## Cross builds: `scripts/release.sh`

```sh
scripts/release.sh                     # the required set (13 targets + universal macOS)
scripts/release.sh --stretch           # plus the 12 stretch rows
scripts/release.sh aarch64-unknown-linux-musl x86_64-unknown-freebsd   # just these
```

Output goes to `dist/mysh-<version>-<target>` plus `dist/SHA256SUMS`
(written and verified). The script owns the single target table (target,
linker family, Rust tier, required/stretch); `docs/08` mirrors it. The
linker is chosen by family:

| family | targets | what you need |
| --- | --- | --- |
| `darwin` | `aarch64-apple-darwin`, `x86_64-apple-darwin` | a Mac with Xcode command-line tools; `lipo` merges both into `universal-apple-darwin` when both were built |
| `linux-musl`, `linux-gnu`, `freebsd` | every Linux row, both FreeBSD rows | `brew install zig && cargo install cargo-zigbuild` (`cargo zigbuild` drives zig as the cross linker from any host) |
| `netbsd`, `openbsd` | the four BSD stretch rows | zig, used through a generated `zig cc -target <arch>-<os>` wrapper under `target/zig-cc/`, because cargo-zigbuild knows no BSD but FreeBSD |
| `android` | the four `*-android` rows | an Android NDK: `ANDROID_NDK_HOME`, or the Homebrew cask path (`/opt/homebrew/share/android-ndk`); API level 24 by default (`ANDROID_API`) |

Tier-3 rows (`s390x`/`mipsel`/`mips` musl, `aarch64` NetBSD, both OpenBSD)
have no prebuilt standard library; the script switches to
`cargo +nightly … -Z build-std=std,panic_abort`, which needs

```sh
rustup toolchain install nightly --component rust-src
```

The script stops with the exact install command when zig, cargo-zigbuild,
the NDK or nightly is missing. Two more knobs: `MUSL_LINKER_AARCH64` /
`MUSL_LINKER_X86_64` name a musl cross gcc to use instead of zig for those
two targets, and `MYSH_STRETCH=1` is the same as `--stretch`. Zig prints
`argument unused during compilation: '-nostartfiles'` on 32-bit ARM musl;
the link succeeds.

### One Android target by hand

```sh
ANDROID_NDK_HOME=/path/to/ndk scripts/android-build.sh aarch64-linux-android 24
# built: target/aarch64-linux-android/release/mysh
adb push target/aarch64-linux-android/release/mysh /data/local/tmp/
```

The script only exports `CARGO_TARGET_<T>_LINKER` pointing at the NDK's
`<triple><api>-clang` and runs `cargo build --release --target`; extra
arguments after `API` pass through to cargo.

### Type-checking the matrix without linkers

```sh
cargo check-matrix            # every required target
cargo check-matrix-stretch    # tier-2 stretch targets
scripts/check-tier3.sh        # tier-3 stretch targets (nightly + rust-src)
cargo lint                    # clippy --workspace --all-targets -D warnings
```

These are cargo aliases from `.cargo/config.toml`; `check` needs no
linker, so they run anywhere the targets are installed
(`rust-toolchain.toml` installs the tier-2 ones).

## Validating artifacts: `scripts/validate-dist.sh`

```sh
docker run --privileged --rm tonistiigi/binfmt --install all   # once per host
scripts/validate-dist.sh [VERSION]
```

For every Linux artifact in `dist/` the script starts a container of the
matching architecture under qemu user-mode emulation (`alpine:3.20` for
musl, `debian:trixie-slim` for glibc, `ghcr.io/loong64/debian` for
loongarch64) and runs `mysh --version`, `mysh keygen`, a loopback `mysh
serve` and a remote `echo` through it. It prints one line per artifact:

```
PASS x86_64-unknown-linux-musl
PASS aarch64-unknown-linux-musl
SKIP x86_64-unknown-freebsd (no emulator)
…
```

and exits non-zero on any `FAIL`. Darwin, FreeBSD, NetBSD, OpenBSD,
Android and the universal binary are always `SKIP` — nothing here can
execute them, which is why [docs/08](../../08-platform-matrix.md) lists
them as link-only. 32-bit MIPS has no binfmt handler; those two run
through Alpine's `qemu-mips`/`qemu-mipsel` package inside a host-arch
container. `MYSH_DOCKER_LIBRARY=mirror.gcr.io/library` avoids Docker Hub's
pull limit.

## Baked builds

A baked binary carries an identity and a set of trusted peer keys inside
the executable, so a device can serve and connect with no key files on
disk ([keys and trust](../keys-and-trust.md),
[docs/02](../../02-security.md)). It is a build-time feature:

```sh
mysh keygen -o fleet                                  # fleet (private), fleet.pub (public)
MYSH_BAKED_IDENTITY=fleet MYSH_BAKED_PEERS=fleet.pub \
  cargo build --release --features baked
```

| variable | content |
| --- | --- |
| `MYSH_BAKED_IDENTITY` | a private key file (mysh native or OpenSSH format) |
| `MYSH_BAKED_PEERS` | an `authorized_keys`-format file of trusted public keys |

`build.rs` embeds both files verbatim; building with `--features baked`
and either variable unset is an error. Any binary built from one keypair
this way trusts every other binary from the same build — one
self-trusting set. Asymmetric trust (clients that are not servers) is two
builds with different inputs. At run time `--baked-only` makes the binary
ignore key files on disk entirely. `scripts/release.sh` does not pass the
feature; set the variables and run `cargo build --target` (or
`cargo zigbuild --target`) yourself for a baked cross build.

## Tests

```sh
cargo test --workspace          # unit + integration tests, natively
scripts/lima-test.sh            # the same suite on aarch64 Linux in a lima VM
scripts/fuzz-all.sh [SECONDS]   # every fuzz target for SECONDS each (default 5)
```

The integration tests in `crates/mysh/tests` start real servers on
loopback and drive them through the binary, so they need a working pty
(`/dev/pts`) and a few seconds. `scripts/lima-test.sh` expects a lima
instance named `mysh-ci` created from the template:

```sh
limactl start --name mysh-ci scripts/lima.yaml
```

The template mounts the checkout read-only at `/mnt/mysh` and installs
rustup with the pinned toolchain; the script rsyncs the tree into the VM
(excluding `target/`) and runs `cargo test --workspace` there, so the host
checkout is never touched. This is the "native (lima)" validation of the
aarch64 Linux artifact in `docs/08`.

`fuzz/` is a separate cargo workspace of libFuzzer targets for the
parsers (frames, protocol messages, keys, `config.toml`, host specs, JSON
output). It needs `cargo install cargo-fuzz` and a nightly toolchain;
`scripts/fuzz-all.sh` selects `+nightly` itself, builds every target, runs
each for the given number of seconds and prints the passed/failed lists.

## Related

[Platforms overview](README.md) — which artifact runs where and how each
was validated.
