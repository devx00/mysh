# FreeBSD

## Artifacts

| arch | artifact | validation |
| --- | --- | --- |
| amd64 | `mysh-<v>-x86_64-unknown-freebsd` | link only |
| arm64 | `mysh-<v>-aarch64-unknown-freebsd` | link only |

Both are position-independent ELF executables linked dynamically against
the base system's `libc.so.7` (interpreter `/libexec/ld-elf.so.1`) through
zig's FreeBSD libc stubs; no ports or packages are needed. They are part of
the required set and are built on every release, but **neither has been
run**: the release environment has no FreeBSD host or emulator. The
FreeBSD-specific code (the `kern.proc.cwd` sysctl, `getpwuid_r`, the
rustix pty calls) is compile-checked on both arches and nothing more. See
[docs/08](../../08-platform-matrix.md#targets-lacking-runtime-validation)
and [docs/04 "Cwd probe"](../../04-sessions.md#cwd-probe) for exactly
what was inferred rather than observed. Rust's own `x86_64-unknown-freebsd` and
`aarch64-unknown-freebsd` targets track supported FreeBSD releases; mysh
states no narrower minimum because it has not measured one.

## Install

```sh
install -m 755 mysh-0.1.0-x86_64-unknown-freebsd /usr/local/bin/mysh
mysh --version
```

`sha256 -c` (base) or `shasum -a 256 -c --ignore-missing SHA256SUMS`
(ports `p5-Digest-SHA`) verifies the download.

## Run the server as a service

No `rc.d` script is shipped. The server needs no privileges beyond the
user it serves; a minimal `/usr/local/etc/rc.d/mysh` using the base
`daemon(8)` supervisor is:

```sh
#!/bin/sh
# PROVIDE: mysh
# REQUIRE: NETWORKING
# KEYWORD: shutdown
. /etc/rc.subr
name=mysh
rcvar=mysh_enable
load_rc_config $name
: ${mysh_enable:=NO}
: ${mysh_user:=root}
: ${mysh_listen:="[::]:7722"}
pidfile="/var/run/${name}.pid"
command="/usr/sbin/daemon"
command_args="-f -P ${pidfile} -r -u ${mysh_user} /usr/local/bin/mysh serve --listen ${mysh_listen}"
run_rc_command "$1"
```

then `sysrc mysh_enable=YES` and `service mysh start`. `daemon -r`
restarts the server if it exits, `-u` picks the user whose home holds
`~/.config/mysh` (host key generated on first start, `authorized_keys`
read from there and from `~/.ssh/authorized_keys`). This sketch follows the
standard `rc.subr` pattern but, like the binary, has not been exercised on
a FreeBSD host.

## Platform behaviour

- **Shell**: `--shell PATH` → `$SHELL` → the passwd entry (`getpwuid_r`)
  → `/bin/sh`. FreeBSD's default user shell is `/bin/sh`; root's is
  `/bin/csh` unless changed.
- **Home**: `$HOME` → passwd → `/`.
- **PATH** for remote commands: the server's own `PATH` if set, else
  `/usr/local/bin:/usr/bin:/bin:/usr/local/sbin:/usr/sbin:/sbin` — the
  sbin directories are included because base tools such as `ifconfig`
  live there and are usable unprivileged.
- **Working directory tracking**: the meta shell asks the kernel with
  `sysctl kern.proc.cwd.<pid>` and reads `kf_path` from the returned
  `kinfo_file`; no `procfs` mount is needed.
- **Pty**: `posix_openpt` on `pts(4)`.
- **Config dir**: `~/.config/mysh`; `$MYSH_CONFIG_DIR` /
  `$XDG_CONFIG_HOME` override. Control sockets in `$XDG_RUNTIME_DIR/mysh`,
  else `$XDG_CACHE_HOME/mysh`, else `~/.cache/mysh`.

If you run mysh on FreeBSD, the useful report is whether `mysh HOST` lands
at a prompt whose directory tracks `cd` — that is the one path that
depends on inferred kernel behaviour.

## Related

[NetBSD and OpenBSD](netbsd-openbsd.md) (stretch targets),
[building](building.md) — `scripts/release.sh x86_64-unknown-freebsd`
cross-links from Linux or macOS with zig.
