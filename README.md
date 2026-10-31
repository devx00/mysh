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
  there too, and double as CLI subcommands.

**Status:** scaffold. The design is in [`docs/`](docs/); nothing connects yet.

| doc                                              | contents                                  |
| ------------------------------------------------ | ----------------------------------------- |
| [01-architecture](docs/01-architecture.md)       | goals, crates, layering, platform matrix, build |
| [02-security](docs/02-security.md)               | keys, ssh key reuse, baked keys, trust, threat model |
| [03-protocol](docs/03-protocol.md)               | preamble, handshake, framing, streams, messages |
| [04-sessions](docs/04-sessions.md)               | pty lifecycle, terminal driver, forwarding, files |
| [05-meta-shell](docs/05-meta-shell.md)           | meta key, prompt, commands, CLI, config   |
| [06-roadmap](docs/06-roadmap.md)                 | milestones, decisions log, testing        |

## Build

```sh
cargo build --release        # native
cargo lint                   # clippy, -D warnings
cargo check-matrix           # type-check every supported target
```

Cross-compilation and baked builds: see `docs/01-architecture.md`.

## License

MIT or Apache-2.0, at your option.
