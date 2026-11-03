# mysh

A minimal, encrypted remote shell for administering personal servers and
devices. One static binary that is both client and server, for Linux, macOS,
and Android.

- Mutually authenticated `Noise_XX_25519_ChaChaPoly_BLAKE2s`; reuses OpenSSH
  ed25519 keys, `authorized_keys`, and `known_hosts`; or bake keys into the
  binary for zero-config devices.
- Every connection starts at a meta shell: `shell` opens a real remote
  shell (PTY, follows your terminal size), `Ctrl-]` brings you back without
  dropping anything; `put`, `get`, `forward`, `info`, and friends live
  there too, and double as CLI subcommands (which reuse a live client's
  connection through its control socket).
- Sessions survive a dropped connection: `mysh --attach HOST` picks them up
  with the output you missed.
- Per-key `authorized_keys` options (`command=`, `from=`, `no-pty`, …),
  per-IP handshake rate limiting, automatic rekeying, fuzzed parsers.

**Status:** milestones M1–M5 of [docs/06-roadmap.md](docs/06-roadmap.md)
are implemented and tested on Linux, macOS and Android; static release
binaries are built by `scripts/release.sh`. Next up: M6–M10 turn mysh into
a remote process API for agents and orchestrators (`--json` everywhere, a
session read/write API with offsets, file primitives, fleet fan-out, an
MCP server) — see the roadmap.

| doc                                              | contents                                  |
| ------------------------------------------------ | ----------------------------------------- |
| [01-architecture](docs/01-architecture.md)       | goals, crates, layering, platform matrix, build |
| [02-security](docs/02-security.md)               | keys, ssh key reuse, baked keys, trust, threat model |
| [03-protocol](docs/03-protocol.md)               | preamble, handshake, framing, streams, messages |
| [04-sessions](docs/04-sessions.md)               | pty lifecycle, terminal driver, forwarding, files |
| [05-meta-shell](docs/05-meta-shell.md)           | meta key, prompt, commands, CLI, config   |
| [06-roadmap](docs/06-roadmap.md)                 | milestones, decisions log, testing        |

## Quickstart

```sh
cargo build --release

# on the server: generate a host key on first run and trust your client key
mysh serve --listen 0.0.0.0:7722 --authorized-key "$(cat ~/.config/mysh/id.pub)"

# on the client
mysh keygen                 # ~/.config/mysh/id, id.pub
mysh pi.lan                 # meta prompt; `shell` for a shell, Ctrl-] to come back
mysh -s pi.lan              # straight to a shell, like ssh
mysh pi.lan 'uptime'        # one command, exits with its status
mysh put pi.lan ./file '~'  # one-shot transfer
mysh forward pi.lan -L 8080:localhost:80
```

## Build and test

```sh
cargo build --release        # native
cargo lint                   # clippy, -D warnings
cargo test --workspace       # unit + integration (loopback, real ptys)
cargo check-matrix           # type-check every supported target
scripts/release.sh           # all five release binaries + SHA256SUMS in dist/
scripts/android-build.sh     # link an Android binary with the NDK clang
scripts/lima-test.sh         # run the suite on Linux in a lima VM
scripts/fuzz-all.sh 60       # every fuzz target for 60 s (needs nightly + cargo-fuzz)
```

Deploy as a service with the files in [`contrib/`](contrib/) (systemd,
launchd, Termux:Boot).

Cross-compilation and baked (keyless) builds: see `docs/01-architecture.md`
and `docs/02-security.md`.

## License

MIT or Apache-2.0, at your option.
