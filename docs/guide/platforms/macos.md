# macOS

## Artifacts

| arch | artifact | validation |
| --- | --- | --- |
| Apple silicon | `mysh-<v>-aarch64-apple-darwin` | **native**: the full test suite runs on this host |
| Intel | `mysh-<v>-x86_64-apple-darwin` | link only (Rosetta would run it; not exercised) |
| both | `mysh-<v>-universal-apple-darwin` | `lipo -info`; its arm64 slice is the native binary |

Distribute the universal binary: it contains both slices and the kernel
picks the right one. Mach-O binaries link dynamically against the system
libraries (`libSystem`), as every macOS executable does; there is nothing
to install alongside. The binaries are not signed or notarised; Gatekeeper
does not intervene for a binary copied with `install`/`cp` and run from a
terminal, but a browser download gets the quarantine attribute — clear it
with `xattr -d com.apple.quarantine mysh` if macOS refuses to run it.

## Install

```sh
install -m 755 mysh-0.1.0-universal-apple-darwin /usr/local/bin/mysh
mysh --version
```

```
mysh 0.1.0
```

Homebrew users may prefer `/opt/homebrew/bin`; any directory on `PATH`
works. `shasum -a 256 -c --ignore-missing SHA256SUMS` checks the
download.

## Run the server as a service

`contrib/com.mysh.serve.plist` is a launchd agent that runs `mysh serve`
as the logged-in user:

```sh
install -m 755 mysh /usr/local/bin/mysh
cp contrib/com.mysh.serve.plist ~/Library/LaunchAgents/
launchctl bootstrap gui/$(id -u) ~/Library/LaunchAgents/com.mysh.serve.plist
```

It listens on `[::]:7722`, restarts on failure (`KeepAlive` unless the
exit was clean, 5 s throttle) and logs to `/tmp/mysh.log`. Keys live in
`~/.config/mysh` — the host key is generated on first start; authorise
clients in `~/.config/mysh/authorized_keys` or `~/.ssh/authorized_keys`.
The plist sets `PATH` to
`/usr/local/bin:/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin`, which is
what remote commands inherit.

Stop it with `launchctl bootout gui/$(id -u)/com.mysh.serve`. For a system
daemon that is up before anyone logs in, place the file in
`/Library/LaunchDaemons` and add a `UserName` key; the server serves the
user it runs as.

## Platform behaviour

- **Shell**: `--shell PATH`, else `$SHELL` (`/bin/zsh` for a normal
  account), else the directory-services passwd entry, else `/bin/sh`.
- **Home**: `$HOME`, else passwd, else `/`.
- **PATH** for remote commands: the server's own `PATH` if set, else
  `/usr/local/bin:/usr/bin:/bin`. A server started from a terminal passes
  that terminal's `PATH` on; one started by launchd gets the plist's.
- **Working directory tracking**: the meta shell uses
  `proc_pidinfo(PROC_PIDVNODEPATHINFO)` on the foreground process; no
  `/proc` is needed and SIP does not interfere.
- **Config dir**: `~/.config/mysh` (not `~/Library`), the same path as on
  Linux; `$MYSH_CONFIG_DIR` or `$XDG_CONFIG_HOME` override it.
- **Control sockets**: `$XDG_RUNTIME_DIR/mysh` when set; macOS does not
  set it, so the client falls back to `$XDG_CACHE_HOME/mysh`, then
  `~/.cache/mysh`.

Running the server and client on the same Mac works for testing:

```sh
mysh keygen
mysh serve --listen 127.0.0.1:0 --authorized-key "$(cat ~/.config/mysh/id.pub)" -v
```

```
INFO generated new host key path=~/.config/mysh/host_key fingerprint=SHA256:…
INFO authorized client keys loaded keys=1
INFO listening addr=127.0.0.1:53032
```

then `mysh --accept-new 127.0.0.1:53032 'uname -sm'` prints `Darwin arm64`.

## Related

[Linux](linux.md), [building from source](building.md) (the universal
binary is produced by `scripts/release.sh` on a Mac).
