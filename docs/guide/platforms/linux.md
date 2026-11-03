# Linux

## Artifacts

| arch | artifact | notes | validation |
| --- | --- | --- | --- |
| x86_64 | `mysh-<v>-x86_64-unknown-linux-musl` | static-pie | qemu-user |
| aarch64 | `mysh-<v>-aarch64-unknown-linux-musl` | static | native (full test suite in a lima VM) + qemu-user |
| i686 | `mysh-<v>-i686-unknown-linux-musl` | static | qemu-user |
| armv7 (hard-float) | `mysh-<v>-armv7-unknown-linux-musleabihf` | static, EABI5 | qemu-user |
| armv6 (hard-float) | `mysh-<v>-arm-unknown-linux-musleabihf` | static, EABI5 | qemu-user |
| riscv64 | `mysh-<v>-riscv64gc-unknown-linux-musl` | static-pie | qemu-user |
| armv5 (soft-float) | `mysh-<v>-armv5te-unknown-linux-musleabi` | stretch, static | qemu-user |
| ppc64le | `mysh-<v>-powerpc64le-unknown-linux-musl` | stretch, static | qemu-user |
| s390x | `mysh-<v>-s390x-unknown-linux-gnu` | stretch, **dynamic against glibc** | qemu-user |
| s390x | `mysh-<v>-s390x-unknown-linux-musl` | stretch, static-pie | qemu-user |
| loongarch64 | `mysh-<v>-loongarch64-unknown-linux-musl` | stretch, static-pie | qemu-user |
| mipsel | `mysh-<v>-mipsel-unknown-linux-musl` | stretch, static | qemu-user |
| mips (big-endian) | `mysh-<v>-mips-unknown-linux-musl` | stretch, static | qemu-user |

"qemu-user" means the artifact itself ran `mysh --version`, `mysh keygen`,
a loopback `mysh serve` and a remote command under qemu user-mode
emulation inside an Alpine (musl) or Debian trixie (glibc) container; see
[docs/08](../../08-platform-matrix.md). Only aarch64 has had the full test
suite run on real Linux.

Every musl artifact is fully static: no interpreter, no shared libraries,
no minimum glibc. It runs on any kernel the Rust target supports, inside
`FROM scratch` containers, and on initramfs-style systems. DNS resolution
goes through musl's own resolver: `/etc/resolv.conf` is honoured,
`nsswitch.conf` and `systemd-resolved`'s NSS module are not — name a
nameserver or use IP addresses on hosts that rely on those.

The s390x glibc build is the exception: it links dynamically against the
system glibc and was built against zig's glibc stubs, so it needs a
distribution at least as new as the symbol versions it was linked
against (Debian trixie is what validated it).

## Install

```sh
install -m 755 mysh-0.1.0-aarch64-unknown-linux-musl /usr/local/bin/mysh
mysh --version
```

```
mysh 0.1.0
```

Without root, `~/.local/bin` or `~/bin` work the same way — the binary
has no files to install besides itself. Verify the download against
`SHA256SUMS` (`sha256sum -c --ignore-missing SHA256SUMS`).

## Run the server as a service

`contrib/mysh.service` is a systemd unit that runs `mysh serve` as a
dynamic `mysh` user with `/var/lib/mysh` as its home and config dir:

```sh
install -m 755 mysh /usr/local/bin/mysh
install -m 644 contrib/mysh.service /etc/systemd/system/mysh.service
systemctl daemon-reload && systemctl enable --now mysh
```

The host key is generated on first start under
`/var/lib/mysh/.config/mysh/`. Authorise clients in
`/var/lib/mysh/.config/mysh/authorized_keys` or append `--authorized-key`
to `ExecStart`. The unit listens on `[::]:7722`, hardens the service
(`ProtectSystem=strict`, `NoNewPrivileges`, private `/tmp`) and keeps
`/dev/pts` reachable, which sessions need. Change `User=` to `root` (and
drop `DynamicUser=`) when the shells it serves must be root; the server
serves whichever user it runs as. See [server](../server.md) for the
flags.

## Platform behaviour

- **Shell**: `--shell PATH`, else `$SHELL`, else the passwd entry
  (`getpwuid`), else `/bin/sh`.
- **Home**: `$HOME`, else the passwd entry, else `/`.
- **PATH** for remote commands: the server's own `PATH` if set, else
  `/usr/local/bin:/usr/bin:/bin`. Under systemd the unit's environment is
  what the server sees; a systemd `Environment=PATH=…` line widens it.
- **Working directory tracking**: the meta shell reads the foreground
  process's cwd through `readlink("/proc/<pid>/cwd")`. If `/proc` is not
  mounted the prompt falls back to the server home and says so.
- **Config dir**: `$MYSH_CONFIG_DIR`, else `$XDG_CONFIG_HOME/mysh`, else
  `~/.config/mysh` — identity `id`, `known_hosts`, `authorized_keys`,
  `config.toml`.
- **Runtime dir** (control sockets): `$XDG_RUNTIME_DIR/mysh`, else
  `$XDG_CACHE_HOME/mysh`, else `~/.cache/mysh`.

Details: [docs/04 "Shell and home resolution"](../../04-sessions.md#shell-and-home-resolution).

## Containers

The static binary needs nothing from the image. A minimal server image:

```dockerfile
FROM scratch
COPY mysh-0.1.0-x86_64-unknown-linux-musl /mysh
ENTRYPOINT ["/mysh", "serve", "--listen", "[::]:7722"]
```

Sessions open a pty, so the container needs a `/dev/pts` (Docker provides
one by default); a shell to run inside the session must exist in the
image, which `scratch` does not provide — use it for a server that only
runs `exec`-style commands, or base on `alpine`.

## Related

[macOS](macos.md), [Android](android.md), [FreeBSD](freebsd.md),
[building from source](building.md).
