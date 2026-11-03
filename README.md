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
- A remote process API for programs: `--json` everywhere, sessions read by
  byte offset, file primitives, fleet fan-out, and `mysh mcp`, an MCP
  server that hands the same tools to an AI agent over stdio
  (`contrib/mcp/`).
- Embeddable: the `mysh-client` crate is the same client code behind a
  Rust API with no terminal dependencies (`docs/07-embedding.md`).

**Status:** milestones M1–M11 of [docs/06-roadmap.md](docs/06-roadmap.md)
are implemented. M6–M10 turned mysh into a remote process API for agents and
orchestrators (`--json` everywhere, a session read/write API with offsets,
file primitives, fleet fan-out, the `mysh-client` crate, an MCP server); M11
made it build for 25 targets out of the box — see "Targets" below.

| doc                                              | contents                                  |
| ------------------------------------------------ | ----------------------------------------- |
| [01-architecture](docs/01-architecture.md)       | goals, crates, layering, platform matrix, build |
| [02-security](docs/02-security.md)               | keys, ssh key reuse, baked keys, trust, threat model |
| [03-protocol](docs/03-protocol.md)               | preamble, handshake, framing, streams, messages |
| [04-sessions](docs/04-sessions.md)               | pty lifecycle, terminal driver, forwarding, files |
| [05-meta-shell](docs/05-meta-shell.md)           | meta key, prompt, commands, CLI, config   |
| [06-roadmap](docs/06-roadmap.md)                 | milestones, decisions log, testing        |
| [07-embedding](docs/07-embedding.md)             | `mysh-client` library API, MCP server tools and schemas |
| [08-platform-matrix](docs/08-platform-matrix.md) | every target, how it was validated, what does not ship |
| [skills/mysh](skills/mysh/SKILL.md)              | agent skill: driving a running server from the CLI with `--json` |

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
mysh mcp --hosts pi.lan     # MCP server over stdio for an agent (docs/07-embedding.md)
```

## Embedding

```rust
use std::sync::Arc;
use mysh_client::{Client, ExecRequest, NullReporter, RefuseUnknown, config, identity::Baked};

let paths = config::Paths::from_env();
let config = config::Config::load(&paths.config_file)?;
let target = config::resolve_target("pi.lan", &Default::default(), &config)?;
let client = Client::connect(&target, &paths, &Baked::default(),
    Arc::new(NullReporter), Arc::new(RefuseUnknown)).await?;
let out = client.exec(ExecRequest::argv(["uname", "-sm"])).await?;
println!("{} exit={:?}", out.stdout.as_bytes().escape_ascii(), out.exit);
```

## Build and test

```sh
cargo build --release        # native
cargo lint                   # clippy, -D warnings
cargo test --workspace       # unit + integration (loopback, real ptys)
cargo check-matrix           # type-check the required targets (check-matrix-stretch, scripts/check-tier3.sh for the rest)
scripts/release.sh           # required set: 13 targets + universal, SHA256SUMS in dist/ (needs zig + cargo-zigbuild, the NDK)
scripts/release.sh --stretch # plus the 12 stretch targets (nightly + rust-src for tier 3)
scripts/validate-dist.sh     # run every Linux artifact under qemu-user (docker + binfmt)
scripts/lima-test.sh         # run the suite on Linux in a lima VM
scripts/fuzz-all.sh 60       # every fuzz target for 60 s (needs nightly + cargo-fuzz)
```

Deploy as a service with the files in [`contrib/`](contrib/) (systemd,
launchd, Termux:Boot).

Cross-compilation details and baked (keyless) builds: `docs/01-architecture.md`
and `docs/02-security.md`.

## Targets

One `scripts/release.sh` run produces the required set; `--stretch` adds the
rest. Full table, validation method per artifact, and the two targets that
do not ship (`mips64el`, illumos) are in
[docs/08-platform-matrix.md](docs/08-platform-matrix.md).

| OS | required | stretch |
| --- | --- | --- |
| Linux (static musl) | x86_64, aarch64, i686, armv7, armv6, riscv64 | armv5te, ppc64le, loongarch64, s390x (musl + glibc), mips, mipsel |
| macOS | aarch64, x86_64, universal | — |
| Android (bionic, API 24) | aarch64, armv7, x86_64 | i686 |
| FreeBSD | x86_64, aarch64 | — |
| NetBSD / OpenBSD | — | x86_64, aarch64 each |

Every Linux artifact is exercised under qemu-user by `scripts/validate-dist.sh`
(`--version`, `keygen`, a loopback `serve` + `exec`); macOS arm64 and aarch64
Linux run the full test suite natively. Windows is out of scope.

## License

MIT or Apache-2.0, at your option.
