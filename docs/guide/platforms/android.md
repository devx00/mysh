# Android

## Artifacts

| arch | artifact | set | validation |
| --- | --- | --- | --- |
| arm64 | `mysh-<v>-aarch64-linux-android` | required | link only |
| armv7 | `mysh-<v>-armv7-linux-androideabi` | required | link only |
| x86_64 (emulators) | `mysh-<v>-x86_64-linux-android` | required | link only |
| i686 | `mysh-<v>-i686-linux-android` | stretch | link only |

All four are position-independent executables linked with the NDK's clang
against bionic at **API level 24 (Android 7.0)** — `libc`, `libm`, `libdl`
only, nothing from a package manager. None of them has been executed in
the release environment, which has no Android device or emulator; the
Android code paths (`/system/bin/sh`, `/data/local/tmp`, the `/proc` cwd
probe) are compile-checked and inferred from
[docs/04](../../04-sessions.md#shell-and-home-resolution). Treat the
Android build as *expected to work, unconfirmed* — see
[docs/08](../../08-platform-matrix.md#targets-lacking-runtime-validation).

Nearly every phone and tablet made since 2016 is arm64; `adb shell uname
-m` prints `aarch64` for those. `armv7l` means the 32-bit build.

## Install

Three environments run mysh; which one decides where the binary and its
keys live.

### `adb shell` (the `shell` uid)

```sh
adb push mysh-0.1.0-aarch64-linux-android /data/local/tmp/mysh
adb shell chmod 755 /data/local/tmp/mysh
adb shell /data/local/tmp/mysh --version
```

```
mysh 0.1.0
```

`/data/local/tmp` is the one writable, executable location the `shell`
user has. Nothing sets `$HOME` here, so mysh uses `/data/local/tmp` as the
home and `/data/local/tmp/.config/mysh` as the config dir (host key,
`authorized_keys`). To serve from there:

```sh
adb shell 'cd /data/local/tmp && HOME=/data/local/tmp nohup ./mysh serve --listen 0.0.0.0:7722 --authorized-key "ssh-ed25519 AAAA… you@laptop" >serve.log 2>&1 &'
adb forward tcp:7722 tcp:7722      # or reach the device's Wi-Fi address directly
mysh --accept-new 127.0.0.1:7722 'id'
```

The server runs as `shell` with that uid's permissions (SELinux domain
`shell`): it can read `/sdcard`, run `am`/`pm`/`logcat`/`dumpsys`, and
not much under `/data`. It dies when the device reboots; there is no
service mechanism at this level.

### Termux

Install into Termux's own prefix; `$HOME` is Termux's home and `$SHELL`
is set, so paths look like Linux:

```sh
mkdir -p ~/bin && cp /sdcard/Download/mysh-0.1.0-aarch64-linux-android ~/bin/mysh && chmod +x ~/bin/mysh
~/bin/mysh keygen
~/bin/mysh serve --listen '[::]:7722'
```

Keys go to `~/.config/mysh`. Remote sessions get Termux's shell
(`$SHELL`, bash by default) and Termux's `PATH`, so `pkg`-installed tools
are available to clients.

To start the server at boot, use the Termux:Boot script in
`contrib/termux-boot/mysh.sh`:

```sh
mkdir -p ~/.termux/boot
cp contrib/termux-boot/mysh.sh ~/.termux/boot/
chmod +x ~/.termux/boot/mysh.sh
```

Install the Termux:Boot app once and open it so Android lets it run at
boot. The script expects the binary at `~/bin/mysh` (override with
`MYSH_BIN`), listens on `[::]:7722` (`MYSH_LISTEN`), logs to
`~/.config/mysh/serve.log`, and takes a `termux-wake-lock` for as long as
the server runs so the CPU stays awake. Listening on the wildcard address
is fine behind NAT; narrow `--listen` if the device has a public address.
Android still kills background apps under memory pressure — exclude Termux
from battery optimisation if the server must stay up.

### Rooted device

`su` then put the binary anywhere executable (`/data/local/tmp`,
`/data/adb`, a Magisk module's `system/bin`), and start it from the root
shell or an init script of your root solution. The server then hands out
root shells to every authorised key; restrict them with `authorized_keys`
options (`command=`, `no-pty`, `no-forward`) — see
[keys and trust](../keys-and-trust.md).

## Platform behaviour

| | Android |
| --- | --- |
| shell | `--shell PATH` → `$SHELL` (Termux sets it) → `/system/bin/sh`; the passwd lookup is skipped because bionic returns synthetic entries |
| home | `$HOME` → `/data/local/tmp` → `/` |
| default `PATH` | the server's own `PATH` if set, else `/system/bin:/system/xbin` |
| config dir | `~/.config/mysh` under whatever home resolved |
| cwd tracking | `readlink("/proc/<pid>/cwd")`, same as Linux; SELinux can deny it for other uids, never for the server's own sessions |
| pty | `/dev/ptmx` + `devpts`, present under both `adb shell` and Termux |

No `getpwnam` data exists on Android, so `~user` expansion and the
passwd-derived shell/home are not available; set `$HOME` and `$SHELL`
explicitly when they matter.

## Related

[Linux](linux.md) for the general Linux notes, [building](building.md)
for building with the NDK (`scripts/android-build.sh`).
