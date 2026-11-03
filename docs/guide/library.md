# Library: `mysh-client`

`mysh-client` is the client half of the `mysh` binary as a Rust crate: the
same connect, trust, session, file and forward code, with every terminal
concern removed. It never reads stdin, never prompts, never prints. A
program using it behaves exactly like `mysh --json` — same error codes,
same JSON shapes, same `config.toml`, `known_hosts` and identity files.
The design notes are [docs/07 "Library"](../07-embedding.md#library-mysh-client);
this page is the quickstart.

## Add the crate

The crate is not on crates.io. Depend on it by path from a checkout, and
on tokio for the runtime:

```toml
[dependencies]
mysh-client = { path = "../mysh/crates/mysh-client" }
tokio = { version = "1", features = ["rt-multi-thread", "macros"] }
```

Two protocol types you may need to name — `Signal` (for
`Sessions::kill`) and `WinSize` (for `ExecRequest::pty`) — live in the
`mysh-proto` crate, which `mysh-client` depends on but does not
re-export; add `mysh-proto = { path = "../mysh/crates/mysh-proto" }` when
you use them. The workspace pins Rust 1.99.1 in `rust-toolchain.toml`,
and the crates declare `rust-version = "1.99"`: an older toolchain refuses
to build them.

The facade is `mysh_client::Client`; the crate root re-exports
`Client`, `ExecRequest`, `Sessions`, `Files`, `Error`, `Result`,
`Reporter`, `NullReporter`, `TrustPrompt` and `RefuseUnknown`. Everything
else is reachable through the modules listed in docs/07 (`config`,
`identity`, `session_api`, `files`, `forward`, `fleet`, `pair`, `types`,
…).

## A complete program

This runs as written against a server whose key is already in
`known_hosts` (connect once with `mysh --accept-new box true`, or set
`accept_new` on the target — see "Trust" below).

```rust
use std::{sync::Arc, time::Duration};

use mysh_client::{
    Client, ExecRequest, NullReporter, RefuseUnknown,
    config::{Config, ForwardSpec, Paths, resolve_target},
    identity::Baked,
    session_api::NewArgs,
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // ~/.config/mysh/{id,known_hosts,config.toml}, like the CLI.
    let paths = Paths::from_env();
    let config = Config::load(&paths.config_file)?;
    // "box" is an alias from config.toml or a host[:port]; the second
    // argument carries the CLI's connection flags (-p, -i, --accept-new, …).
    let target = resolve_target("box", &Default::default(), &config)?;
    let client = Client::connect(
        &target,
        &paths,
        &Baked::default(),
        Arc::new(NullReporter),
        Arc::new(RefuseUnknown),
    )
    .await?;

    // One command, output collected. A non-zero exit is not an error.
    let mut req = ExecRequest::argv(["uname", "-sm"]);
    req.timeout = Some(Duration::from_secs(10));
    let out = client.exec(req).await?;
    println!(
        "{} (exit {:?}, {} ms)",
        String::from_utf8_lossy(out.stdout.as_bytes()).trim(),
        out.exit,
        out.duration_ms
    );

    // Files: relative paths are under the remote home.
    client.files().write("notes.txt", b"hello\n", None, false).await?;
    let (attrs, bytes) = client.files().read("notes.txt", 0, None).await?;
    println!("{} bytes (mode {:o})", bytes.len(), attrs.mode);
    for e in client.files().list(".", false).await? {
        println!("{:>8} {}", e.size, e.name);
    }

    // A long-running process, read by absolute offset until it exits.
    let s = client
        .sessions()
        .new(&NewArgs {
            command: vec!["sh".into(), "-c".into(), "for i in 1 2 3; do echo $i; sleep 1; done".into()],
            ..NewArgs::default()
        })
        .await?;
    let mut offset = 0;
    loop {
        let r = client.sessions().read(s.id, offset, 65536, Duration::from_secs(2)).await?;
        for c in &r.chunks {
            print!("{}", String::from_utf8_lossy(c.data.as_bytes()));
        }
        offset = r.next;
        if let Some(exit) = r.exited {
            println!("session {} exited: {:?}", s.id, exit.exit);
            break;
        }
    }

    // A local forward: an ephemeral port here → 127.0.0.1:7722 on the host.
    let spec = ForwardSpec::parse_local("0:127.0.0.1:7722")?;
    let id = client.forwards().add_local(&spec).await?;
    for f in client.forwards().list() {
        println!("forward {} {} {} -> {:?}", f.id, f.kind, f.bind, f.target);
    }
    client.forwards().remove(id).await;

    // Errors carry a stable code.
    if let Err(e) = client.files().read("/nope", 0, None).await {
        eprintln!("{}: {}", e.code, e);
    }

    client.close().await;
    Ok(())
}
```

Output against a loopback server on macOS:

```
Darwin arm64 (exit Some(0), 3 ms)
6 bytes (mode 644)
       6 notes.txt
1
2
3
session 3 exited: Some(0)
forward 1 local 127.0.0.1:53350 -> Some(("127.0.0.1", 7722))
not_found: read /nope: not found: No such file or directory (os error 2)
```

## Connecting

```rust
pub async fn connect(target: &Target, paths: &Paths, baked: &Baked,
                     reporter: Arc<dyn Reporter>, prompt: Arc<dyn TrustPrompt>) -> Result<Client>;
```

| argument | where it comes from |
| --- | --- |
| `Target` | `config::resolve_target(host, &ConnectOpts, &Config)`: an alias from `config.toml` or `host`, `host:port`, `[v6]:port`; `ConnectOpts` is the CLI's shared connection flags as a plain struct (`port`, `identity`, `pin`, `accept_new`, `strict`, `env`, `cwd`, …), `Default::default()` for none. `Target` itself is a public struct, so you can also build or edit one directly (`target.accept_new = true`). |
| `Paths` | `Paths::from_env()`: `$MYSH_CONFIG_DIR` → `$XDG_CONFIG_HOME/mysh` → `~/.config/mysh` for `id`, `known_hosts`, `config.toml`; `$XDG_RUNTIME_DIR/mysh` for control sockets. Fields are public — point them anywhere. |
| `Baked` | compiled-in identity and peers; `Baked::default()` is "none" ([keys and trust](keys-and-trust.md) for baked binaries). |
| `Reporter` | receives every event the CLI would print with `--json-stream` (`Progress`, `Notice`, `Stdout`/`Stderr`, `Error`, `Result`, `Host`, …). `NullReporter` drops them. |
| `TrustPrompt` | decides about an unknown server key and supplies passphrases for encrypted key files. `RefuseUnknown` says no to both. |

Identities resolve as for the CLI: `-i`/alias identity, `~/.config/mysh/id`,
then ed25519 keys from `$SSH_AUTH_SOCK`. `Client::connect_or_ctl(…, exe)`
is the same call after honouring the target's `master` setting (it may
start a background `mysh master` through `exe`, the `mysh` binary) —
only useful when your program shares a host with interactive `mysh`
sessions.

After a lost connection `is_connected()` is false; `reconnect(&mut self)`
opens a fresh one to the same target (forwards do not survive). `close()`
stops the forwards and closes gracefully; dropping the `Client` just lets
the connection go.

### Trust

| situation | result |
| --- | --- |
| server key in `known_hosts`, pinned (`target.pin`) or baked, and matching | connects |
| known but different | `Err` with code `trust_mismatch`; nothing bypasses this |
| unknown, `target.strict` | `trust_unknown` without asking |
| unknown, `target.accept_new` | pinned into `known_hosts` silently (TOFU) |
| unknown, neither | `prompt.confirm_unknown(host, port, &fingerprint)` decides; `RefuseUnknown` → `trust_unknown` |

A program that wants an interactive confirmation implements `TrustPrompt`
itself:

```rust
struct AskOnTty;
impl mysh_client::TrustPrompt for AskOnTty {
    fn confirm_unknown(&self, host: &str, port: u16, fp: &mysh_net::keys::Fingerprint) -> bool {
        eprintln!("new host {host}:{port} with key {fp}; trusting it");
        true
    }
}
```

(`Fingerprint` is `mysh_net::keys::Fingerprint`, so this needs a
`mysh-net` path dependency too; `fp.to_string()` is the
`SHA256:…` form the CLI shows.) `passphrase(&self, source) ->
io::Result<String>` has a default that fails, which makes an encrypted
key file unusable unless you override it.

## Running commands

```rust
pub struct ExecRequest {
    pub argv: Vec<String>,            // one element runs through the remote shell
    pub cwd: Option<String>,          // `~`-relative allowed; server falls back to home
    pub env: Vec<(String, String)>,   // subject to the server's accept list
    pub pty: Option<WinSize>,         // Some → pty of that size, stderr merged into stdout
    pub timeout: Option<Duration>,    // TERM, then KILL 2 s later; sets `timed_out`
    pub stdin: Option<Vec<u8>>,       // sent, then stdin closed (unless pty)
}
impl ExecRequest { pub fn argv<S: Into<String>>(argv: impl IntoIterator<Item = S>) -> Self; }

pub async fn exec(&self, req: ExecRequest) -> Result<ExecResult>;
pub async fn exec_stream(&self, req: ExecRequest, sink: impl FnMut(Event) + Send) -> Result<ExecResult>;
```

`ExecResult` has `stdout`, `stderr` (`types::Bytes`, text or binary;
`.as_bytes()`), `exit: Option<i32>`, `signal: Option<i32>`,
`duration_ms` and `timed_out`. `exec_stream` additionally hands
`Event::Started { session, pid }`, `Stdout`, `Stderr` and `Exit` to `sink`
as they arrive — the shape of `mysh --json-stream HOST CMD`:

```rust
let res = client
    .exec_stream(ExecRequest::argv(["tail", "-n", "100", "/var/log/syslog"]), |ev| {
        if let mysh_client::types::Event::Stdout { data } = ev {
            std::io::Write::write_all(&mut std::io::stdout(), data.as_bytes()).ok();
        }
    })
    .await?;
```

A command that exits non-zero is `Ok` with `exit: Some(n)`; a command that
cannot start, or a connection lost mid-way, is `Err` (`not_found`,
`connect_failed`, …). `client.info().await?` returns the server's facts,
the connection's and the active forwards (`InfoOut`, the `info --json`
document).

## Sessions

`client.sessions()` is the remote process API — the same calls as
`mysh session new/send/read/list/kill/wait`
([sessions](sessions.md)). A session outlives the call that started it and
is addressed by id:

```rust
pub async fn new(&self, args: &NewArgs) -> Result<NewSessionOut>;        // {id, pid}
pub async fn send(&self, id: u32, bytes: &[u8], eof: bool) -> Result<()>;
pub async fn read(&self, id: u32, offset: u64, max: u32, wait: Duration) -> Result<ReadOut>;
pub async fn list(&self) -> Result<Vec<ApiSessionRow>>;
pub async fn kill(&self, id: u32, signal: Signal) -> Result<()>;         // mysh_proto::session::Signal
pub async fn wait(&self, id: u32, timeout: Option<Duration>) -> Result<Option<ExitOut>>;
```

`NewArgs` (`session_api::NewArgs`, `Default`): `command`, `cwd`, `pty:
bool`, `size: Option<WinSize>`, `env: Vec<String>` (`NAME[=VALUE]`).
`read` is idempotent per offset — the same `offset` returns the same
bytes until they age out of the server's ring — and blocks up to `wait`
(capped by the server at 30 s) for new output; `ReadOut` has `offset`,
`next` (pass it back), `oldest`, `chunks: [{stream, data}]` and `exited:
Option<ExitOut>`. `max` is capped at 1 MiB. `wait` returns `Ok(None)`
when its timeout passes first and the session keeps running.
`Signal::parse("TERM")` turns a name into a `Signal`.

## Files

`client.files()` — relative paths are under the remote home, `~` is
expanded by the server ([files](files.md)):

| call | returns |
| --- | --- |
| `stat(path)` | `Option<StatOut>` (`None` when missing — not an error) |
| `list(path, all)` | `Vec<LsEntry>` sorted by name; `all` includes dot files |
| `read(path, offset, max: Option<u64>)` | `(Attrs, Vec<u8>)` |
| `read_to(path, offset, &mut impl AsyncWrite)` | `(Attrs, bytes_written)` |
| `write(path, data, mode: Option<u32>, append)` | bytes written; atomic replace unless `append`; `mode` for new files (0644) |
| `put(local: &Path, remote, checksum)` | `TransferOut`; one regular file, progress to the reporter |
| `get(remote, local: &Path, checksum)` | `TransferOut`; temp file + rename |
| `mkdir(path, mode: Option<u32>)` | `()`; existing directory is fine |
| `remove(path, recursive)` | `()` |
| `rename(from, to)` | `()`; replaces `to` |
| `realpath(path)` | `String` |
| `hash(path)` | `HashOut` (`algo: "blake2s256"`, `size`, `digest` hex) |
| `tail(path, lines)` | `Vec<u8>` |
| `sync(&SyncArgs, local_cwd: &Path)` | `SyncOutcome::Plan` for a dry run, `::Summary` otherwise |

Recursive `put -r`/`get -r` are the `files::put`/`files::get` runners
with `args::PutArgs`/`GetArgs`; they report through the `Reporter`
(`Result` event carries the `TransferOut`) instead of returning it.

## Forwards

`client.forwards()` returns `&forward::Forwards`
([forwarding](forwarding.md)):

```rust
pub async fn add_local(&self, spec: &ForwardSpec) -> Result<u32>;    // -L  [bind:]port:host:hostport
pub async fn add_remote(&self, spec: &ForwardSpec) -> Result<u32>;   // -R
pub async fn add_dynamic(&self, spec: &ForwardSpec) -> Result<u32>;  // -D  [bind:]port  (SOCKS5)
pub fn list(&self) -> Vec<ForwardInfo>;                              // id, kind, bind (as actually bound), target, accepted
pub async fn remove(&self, id: u32) -> bool;
pub async fn shutdown(&self);
```

`ForwardSpec::parse_local("8080:localhost:80")` and
`ForwardSpec::parse_dynamic("1080")` build specs from the CLI syntax; the
struct is also public (`bind`, `port`, `target: Option<(String, u16)>`).
Port `0` binds an ephemeral port; `list()` shows the real one. Forwards
end with `close()` or `shutdown()`, and do not survive `reconnect()`.

## Errors

Every facade call returns `mysh_client::Result<T>` =
`Result<T, mysh_client::Error>`:

```rust
pub struct Error { pub code: &'static str, /* anyhow chain */ }
impl Error {
    pub fn message(&self) -> String;        // the whole chain, same as Display
    pub fn inner(&self) -> &anyhow::Error;
    pub fn into_inner(self) -> anyhow::Error;
}
```

`code` is one of the constants in `mysh_client::types::codes` — the same
stable set the CLI prints in `{"error":{"code","message"}}`
([automation](automation.md)):

| code | meaning |
| --- | --- |
| `not_found` | no such path, session or forward on the server |
| `denied` | policy: the feature is switched off (`--deny`, `authorized_keys` options) |
| `unauthorized` | the server refused every identity |
| `unsupported` | the server does not implement the stream kind |
| `io` | server-side I/O failure, or the connection went away mid-command |
| `limit` | a per-connection quota (sessions, listeners, streams) |
| `protocol` | malformed or out-of-order message |
| `trust_unknown` | unknown server key and nothing accepted it |
| `trust_mismatch` | the server key differs from `known_hosts`/pin; never bypassable |
| `connect_failed` | DNS, TCP connect, or handshake timeout; also a connection lost during `exec` |
| `timeout` | a transfer's timeout expired (an exec reports `timed_out` in its result instead) |
| `usage` | bad arguments: a bad forward spec, an unparsable host, bad config |
| `internal` | anything else |

`Display` renders the chain (`read /nope: not found: No such file or
directory`), `std::error::Error::source` exposes it, and an `Error`
wrapped into another `anyhow::Error` keeps its code for
`types::code_for`. Match on the constants:

```rust
use mysh_client::types::codes;
match client.files().stat("/etc/motd").await {
    Ok(Some(st)) => println!("{} bytes", st.size),
    Ok(None) => println!("absent"),
    Err(e) if e.code == codes::DENIED => eprintln!("files are denied for this key"),
    Err(e) => return Err(e.into()),
}
```

## Many hosts

`fleet::run(targets, req, jobs, paths, baked, reporter, prompt) ->
Vec<RunResult>` connects to each target with its own `Client`, `jobs` at a
time, wraps every host's events in `Event::Host { host, data }`, and never
fails as a whole: an unreachable host is a `RunResult` whose `error.code`
is `connect_failed`. `fleet::parse_hosts`/`expand_hosts` turn `--hosts`
and `--group` strings into targets using `config.toml`. This is what
`mysh run` does ([automation](automation.md)).

## Related

[MCP](mcp.md) exposes the same operations to an agent over stdio;
[building](platforms/building.md) covers the toolchain pin.
