# Embedding mysh (M10)

Three ways to drive a mysh server from a program: the `mysh-client` library
crate (a Rust API with no terminal dependencies), `mysh mcp`, a Model
Context Protocol server over stdio that any MCP client can use as a set of
tools, and — for an agent that already has a shell — the plain CLI with
`--json`, described for that audience in [`skills/mysh/SKILL.md`](../skills/mysh/SKILL.md).
All three run the same client code as the `mysh` binary, so behaviour,
error codes and JSON shapes match the CLI (05-meta-shell.md "Agent
interface").

## Library: `mysh-client`

`crates/mysh-client` is the client half of the binary as a library: the
same `connect`, trust, session, file and forward code `mysh HOST …` runs,
with every terminal concern removed. It depends on `mysh-net`,
`mysh-proto`, tokio, serde and clap (for the shared request structs), never
on `mysh-pty`; it never reads stdin, never prompts, never spawns itself.
`#![forbid(unsafe_code)]`, every public item documented.

```toml
[dependencies]
mysh-client = { path = "crates/mysh-client" }   # not on crates.io
```

### Layout

| module        | contents                                                                                         |
| ------------- | ------------------------------------------------------------------------------------------------ |
| `config`      | `Paths` (config dir, identity, known_hosts, runtime dir), `Config` (`config.toml`: aliases, groups, defaults), `Target` + `resolve_target`, `ForwardSpec`, `MasterMode` |
| `identity`    | `Baked` (compiled-in keys as text), `ClientIdentity`, `client_identities` (key files, `ssh-agent`), `ClientTrust` / `TrustDecision` (pin → baked → `known_hosts`) |
| `conn`        | `connect` and `Connection` (the Noise session, control stream, `open`, `ping`, `info`, `close`)  |
| `session`     | the session stack with its output ring (what the prompt foregrounds)                             |
| `session_api` | the remote process API by id: `session_new/read/send/list/kill/wait` and their `--json` shapes   |
| `files`, `fileops`, `sync` | file primitives (`stat`, `list_all`, `read_range`, `write_bytes`, `get_to`, `put_from`, `remove`, `rename`, `hash`, `tail_lines`, …), the `put`/`get`/`ls`/`cat`/… runners, and `sync` with `SyncOutcome` |
| `forward`     | `Forwards`: `-L`/`-R`/`-D` listeners on a connection                                              |
| `accept`      | `Acceptor`, `AcceptOpts`, `Inbound`: connections servers open themselves ("Accepting connections") |
| `ctl`         | the control-socket requester (`request`, `socket_ready`) and `ensure` (start a `mysh master`)   |
| `fleet`       | `parse_hosts`/`expand_hosts` (`--hosts`/`--group`) and `run`: one exec on many hosts             |
| `pair`        | `pair`: SPAKE2 first contact with a one-time code (02-security.md "Pairing")                     |
| `types`       | every `--json` document (`ExecResult`, `InfoOut`, `LsEntry`, `StatOut`, `TransferOut`, `RunResult`, `PairOut`, …), the `Event` stream, `ErrorOut` and the `codes` |
| `args`        | the request structs shared with the CLI (`PutArgs`, `GetArgs`, `SyncArgs`, `SessionArgs`, `ConnectOpts`, …); plain structs with `Default`, clap `Args` for the binary |
| `report`      | `Reporter`, `NullReporter`, `TrustPrompt`, `RefuseUnknown`                                        |
| `client`      | `Client`, `ExecRequest`, `Sessions`, `Files` — the facade                                         |

### Reporting and trust

The library talks back through two traits (`mysh_client::report`):

```rust
pub trait Reporter: Send + Sync {
    fn event(&self, ev: &types::Event);          // progress, notice, stdout/stderr, error, result
    fn is_interactive(&self) -> bool { false }   // the binary's Console: true on a tty
    // + hooks with event-based defaults the binary's console overrides:
    // mode(), print(), println(), result(), emit(), write_raw*(), progress_done(), flush()
}
pub trait TrustPrompt: Send + Sync {
    fn confirm_unknown(&self, host: &str, port: u16, fp: &Fingerprint) -> bool;   // TOFU
    fn passphrase(&self, source: &str) -> io::Result<String> { Err(..) }           // encrypted keys
}
```

`NullReporter` drops everything and `RefuseUnknown` says no, so a program
that passes the defaults only reaches hosts whose key is already in
`known_hosts` (or pinned, or baked), with unencrypted keys — exactly what
`mysh --json` does without a terminal. A `Target` with `accept_new` set
pins unknown keys without asking; `strict` refuses before asking. The
binary implements both traits on its console (`ConsolePrompt` asks on the
tty, `passphrase_prompt` uses `rpassword`).

### `Client`

```rust
impl Client {
    pub async fn connect(target: &Target, paths: &Paths, baked: &Baked,
                         reporter: Arc<dyn Reporter>, prompt: Arc<dyn TrustPrompt>) -> Result<Client>;
    pub async fn connect_or_ctl(.., exe: &Path) -> Result<Client>;   // honours target.master first
    pub fn connection(&self) -> &Connection;     pub fn is_connected(&self) -> bool;
    pub async fn reconnect(&mut self) -> Result<()>;                // after a loss; forwards are dropped
    pub async fn exec(&self, req: ExecRequest) -> Result<ExecResult>;
    pub async fn exec_stream(&self, req: ExecRequest, sink: impl FnMut(Event) + Send) -> Result<ExecResult>;
    pub async fn info(&self) -> Result<InfoOut>;
    pub fn sessions(&self) -> Sessions<'_>;      // new / send / read / list / kill / wait
    pub fn files(&self) -> Files<'_>;            // stat / list / read / read_to / write / put / get / mkdir / remove / rename / realpath / hash / tail / sync
    pub fn forwards(&self) -> &Forwards;         // add_local / add_remote / add_dynamic / list / remove
    pub async fn close(self);
}
pub struct ExecRequest { argv, cwd, env: Vec<(String, String)>, pty: Option<WinSize>, timeout: Option<Duration>, stdin: Option<Vec<u8>> }
```

`exec` is `session_new` + `session_read` polling: it starts a persisted
session, sends `stdin` (and closes the process's stdin unless a pty was
asked for), streams `Started`/`Stdout`/`Stderr`/`Exit` events to the sink,
and returns the `ExecResult` the CLI prints. `timeout` sends TERM, then
KILL two seconds later, and sets `timed_out` (`code()` is then 124). A
pty merges stderr into stdout and has the size you pass. Environment
variables are subject to the server's accept list, like `--env`.

`files()` resolves relative remote paths against the remote home (`~` is
expanded by the server); `put`/`get` move one regular file (progress goes
to the reporter as `Progress` events) and `sync` takes the CLI's
`SyncArgs` (`src`/`dst` plus `pull`/`delete`/`dry_run`/`checksum`/`jobs`)
and returns `SyncOutcome::Plan` for a dry run or `::Summary`. Recursive
`put -r`/`get -r` are the `files::put`/`files::get` runners with
`PutArgs`/`GetArgs`; they report through the `Reporter` instead of
returning (`result` carries the `TransferOut` document).

`sessions()` is the remote process API of 04-sessions.md: `read` is
idempotent per offset and blocks up to `wait` for new output; `wait`
returns `None` when its timeout passes and the session keeps running.

`fleet::run(targets, req, jobs, paths, baked, reporter, prompt) ->
Vec<RunResult>` connects to each target with its own `Client`, `jobs` at a
time, wraps every host's events in `Event::Host { host, data }` for the
reporter, and never fails as a whole: an unreachable host is a `RunResult`
with `error.code = "connect_failed"`.

### Example

```rust
use std::{sync::Arc, time::Duration};
use mysh_client::{Client, ExecRequest, NullReporter, RefuseUnknown,
                  config::{Config, Paths, resolve_target}, identity::Baked,
                  session_api::NewArgs};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let paths = Paths::from_env();                                   // ~/.config/mysh/…
    let config = Config::load(&paths.config_file)?;
    let target = resolve_target("pi", &Default::default(), &config)?; // alias or host[:port]
    let client = Client::connect(&target, &paths, &Baked::default(),
                                 Arc::new(NullReporter), Arc::new(RefuseUnknown)).await?;

    // One command, collected.
    let mut req = ExecRequest::argv(["uname", "-sm"]);
    req.timeout = Some(Duration::from_secs(10));
    let out = client.exec(req).await?;
    println!("{} (exit {:?})", String::from_utf8_lossy(out.stdout.as_bytes()).trim(), out.exit);

    // A file.
    let (attrs, bytes) = client.files().read("/etc/hostname", 0, Some(4096)).await?;
    println!("{} bytes of {}", bytes.len(), attrs.size);

    // A long-running process, polled by offset.
    let s = client.sessions().new(&NewArgs {
        command: vec!["sh".into(), "-c".into(), "for i in 1 2 3; do echo $i; sleep 1; done".into()],
        ..NewArgs::default()
    }).await?;
    let mut offset = 0;
    loop {
        let r = client.sessions().read(s.id, offset, 65536, Duration::from_secs(2)).await?;
        for c in &r.chunks { print!("{}", String::from_utf8_lossy(c.data.as_bytes())); }
        offset = r.next;
        if let Some(exit) = r.exited { println!("exited: {exit:?}"); break; }
    }
    client.close().await;
    Ok(())
}
```

### Accepting connections

A server started with `mysh serve --connect-back ADDR` dials the client
instead of waiting to be dialed; after TCP nothing changes, so an accepted
connection is an ordinary [`Client`]. `mysh_client::accept` is that side:

```rust
use std::{net::SocketAddr, sync::Arc};
use mysh_client::{AcceptOpts, Acceptor, ExecRequest, NullReporter,
                  config::Paths, identity::{Callers, client_identities}};

let paths = Paths::from_env();
let callers = Callers::load(&paths);                 // ~/.config/mysh/callers
let identity = client_identities(&Default::default(), &paths, &Default::default(),
                                 &mut |_| Err(std::io::Error::other("no passphrase")))
    .await?.remove(0);
let mut acceptor = Acceptor::bind(
    "[::]:7722".parse::<SocketAddr>()?,
    identity,
    callers,
    Arc::new(NullReporter),
    AcceptOpts { accept_new: false, handshakes_per_minute: 30 },
).await?;

while let Some(inbound) = acceptor.next().await {
    println!("{} from {}", inbound.caller.label(), inbound.peer);
    let out = inbound.client.exec(ExecRequest::argv(["uname", "-sm"])).await?;
    println!("{}", String::from_utf8_lossy(out.stdout.as_bytes()));
    inbound.client.close().await;   // the server goes back to its period
}
```

- Trust is by **key**, not by address: the server's static key is looked
  up in the [`Callers`] store (`~/.config/mysh/callers`, `authorized_keys`
  line format, the comment is the name) plus the baked peers. An unknown
  key is refused before the client reveals its own in Noise message 3, and
  reported as `Event::Refused`; `AcceptOpts::accept_new` records it
  instead (02-security.md "Callers"). The server still authorizes the
  client's key as usual, so both ends are checked.
- `Inbound { client, caller, peer, name }`: `caller.label()` is the name
  (or fingerprint label) the connection is known by, `name` is the
  informational `ServerHello.name`.
- Handshakes run concurrently and are released in arrival order; a slow
  consumer never eats into a handshake deadline, and refused or failed
  handshakes never reach `next()`. Queued connections stay alive (their
  pinger runs), so release them promptly: holding one keeps that server
  from going back to its period, and the server will close it itself after
  `--connect-max`.
- The reporter receives `Event::Accepted { name, fingerprint, addr, server }`,
  `Event::Closed { name, fingerprint, reason }` and `Event::Refused
  { fingerprint, addr, reason }`.
- `Client::from_connection(conn, reporter)` wraps any existing
  [`Connection`] the same way; such a client cannot `reconnect()` (an
  accepted connection is only re-established by the server).
- `Connection::bind(addr, idle)` / `unbind()` ask the server for a
  listener of its own (`serve --allow-bind-request`), so ordinary clients
  can dial it; a refusal carries the `denied` code.

### Errors

Every facade call returns `mysh_client::Error`:

```rust
pub struct Error { pub code: &'static str, /* anyhow chain */ }
impl Error { fn message(&self) -> String; fn inner(&self) -> &anyhow::Error; fn into_inner(self) -> anyhow::Error; }
```

`code` is one of `types::codes` — the same stable set the CLI prints in
`{"error":{"code","message"}}` (05-meta-shell.md "Error codes"):
`not_found`, `denied`, `unauthorized`, `unsupported`, `io`, `limit`,
`protocol`, `trust_unknown`, `trust_mismatch`, `connect_failed`,
`timeout`, `usage`, `internal`. `Display` renders the whole chain
(`"stat: /nope: no such file"`), `std::error::Error::source` exposes it, and
an `Error` wrapped into another `anyhow::Error` keeps its code for
`types::code_for`. A non-zero exit is not an error: `exec` returns
`Ok(ExecResult { exit: Some(3), .. })`.

Inside the crate the modules keep `anyhow::Result` with `types::coded`
tags, so a program using them directly classifies with
`types::code_for(&err)`.

### What stays in the binary

The console (`Mode`-aware writer, progress line, prompt redraw), the
terminal driver and line editor, the meta shell and its jobs, the
control-socket *server* and `mysh master`, `mysh serve`, `keygen` /
`fingerprint`, the baked-key `build.rs`, and the `HelpTree` of
`help --json`. The binary's old paths (`mysh::client::conn`,
`mysh::config`, `mysh::output`, …) re-export the library, so the
integration tests in `crates/mysh/tests` drive both.

## MCP server: `mysh mcp`

```
mysh mcp (--hosts a,b | --group NAME)... [--accept-new] [-i PATH] [--allow-local-paths]
```

`mysh mcp` reads JSON-RPC 2.0 from stdin and writes replies to stdout, one
JSON document per line (a message that starts with a `Content-Length:`
header is accepted too and answered with the same framing). Logs go to
stderr. It exits 0 when stdin closes. An example client configuration lives
in `contrib/mcp/`.

### Protocol

| method                     | result                                                                                                       |
| -------------------------- | ------------------------------------------------------------------------------------------------------------ |
| `initialize`               | `protocolVersion` (the client's if it is `2024-11-05`, `2025-03-26` or `2025-06-18`, else `2025-06-18`), `capabilities {tools:{listChanged:false}, resources:{subscribe:false, listChanged:false}}`, `serverInfo {name:"mysh", version}`, `instructions` (the hosts, the default host, the trust and local-path rules) |
| `notifications/initialized` | no reply                                                                                                     |
| `ping`                     | `{}`                                                                                                         |
| `tools/list`               | every tool below with `inputSchema` and `outputSchema`                                                        |
| `tools/call`               | `{content:[{type:"text", text}], structuredContent, isError}`; `text` is `structuredContent` serialized        |
| `resources/list`           | one `mysh://HOST/` per configured host                                                                        |
| `resources/templates/list` | `mysh://{host}/{path}`                                                                                        |
| `resources/read`           | `{contents:[{uri, mimeType, text | blob}]}`                                                                   |

Errors at the protocol level are JSON-RPC errors: `-32700` parse error,
`-32600` invalid request, `-32601` unknown method, `-32602` invalid params
(the validation message says which field; also an unknown tool or an
unconfigured `host`), `-32603` internal. A failure *on the host* is never a
JSON-RPC error: the tool result has `isError: true`, and both
`content[0].text` and `structuredContent` carry `{"error":{"code","message"}}`
with the stable codes of 05-meta-shell.md "Error codes" (`not_found`,
`denied`, `connect_failed`, `trust_unknown`, `timeout`, …). A command that
exits non-zero is **not** an error: `exec` returns `isError: false` with
`exit: 3`. Batches (`[…]`) are answered with a batch; notifications get no
reply.

Requests are served one at a time, in order. A tool that waits (`exec` with
its timeout, `session_read` with `wait_ms`) holds the queue; keep waits
short and poll.

### Hosts and connections

`--hosts`/`--group` name the hosts the tools may reach, exactly as for
`mysh run` (aliases from `config.toml` or `host[:port]`, duplicates dropped,
order kept). Every tool takes `host` — one of those names — except when a
single host was configured, in which case `host` is optional and the schemas
say so. The `hosts` tool lists the names with their resolved `host:port` and
whether each is connected right now.

Connections open lazily on first use, stay up across calls, and are reopened
on the next call after a loss. A host that cannot be reached fails the call
with `connect_failed`; the other hosts are unaffected.

### Trust and identity

Stdin is the protocol, so nothing ever prompts. Identities resolve as usual
(`-i`, the alias, `~/.config/mysh/id`, agent keys); a passphrase-protected
key file cannot be unlocked here and fails like it does under `mysh --json`.
The server key is checked against `known_hosts`/pins as always:

- known and matching: fine (`trusted_via` in `info` says how);
- known and different: `trust_mismatch`, no bypass;
- unknown: `trust_unknown` — unless `mysh mcp --accept-new` was given, which
  pins the key on first use (TOFU). The `instructions` string states which
  of the two applies, so an agent can tell the user to pin the host (`mysh
  HOST` once interactively, `mysh pair`, or a `pin =` in the alias) instead
  of retrying.

`put` and `get` touch files on the machine running `mysh mcp`. They are off
by default (`denied`) and enabled with `--allow-local-paths`; relative local
paths resolve against the server process's working directory. Every other
tool only ever touches the remote host, under whatever `authorized_keys`
options and `--deny` flags the server applies to the key.

### Tools

Inputs are JSON objects (`additionalProperties: false`); `host` is described
above and omitted from the table. "Bytes" below means the `--json`
convention: a string when the data is UTF-8, else `{"base64": "…"}`.

| tool           | input                                                                                              | result                                                                                                                      |
| -------------- | -------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------- |
| `exec`         | `command` (string: a shell line; array: argv), `cwd?`, `env?` (object), `timeout_ms?` (default 60000, 0 = none), `stdin?` (text) | `ExecResult`: `stdout`/`stderr` (bytes), `exit`, `signal`, `duration_ms`, `timed_out`. The timeout sends TERM, KILL 2 s later |
| `read_file`    | `path`, `offset?` (0), `max_bytes?` (1 MiB)                                                        | `content`, `encoding` (`utf-8` or `base64`), `size` (whole file), `offset`, `truncated` (more follows at `offset + len`)      |
| `write_file`   | `path`, `content`, `encoding?`, `mode?` (octal string, new files only, default `0644`), `append?`  | `written` (bytes). Atomic replace unless `append`                                                                           |
| `list_dir`     | `path`, `all?` (dot-files)                                                                         | `entries`: `LsEntry[]` (`name`, `kind`, `size`, `mode`, `mtime`, `target`), sorted by name                                   |
| `stat`         | `path`                                                                                             | `StatOut` (`path`, `kind`, `size`, `mode`, `mtime`, `uid`, `gid`, `target`); missing → `not_found`                            |
| `session_new`  | `command`, `cwd?`, `pty?` (80×24), `env?`                                                          | `{id, pid}`; the session persists on the server (04-sessions.md "Remote process API")                                        |
| `session_send` | `id`, `data`, `encoding?`, `eof?`                                                                  | `{ok: true}`                                                                                                                |
| `session_read` | `id`, `offset?` (0), `max_bytes?` (1 MiB), `wait_ms?` (0; the server caps it)                      | `{offset, next, oldest, chunks: [{stream, data}], exited: {exit, signal} \| null}` — idempotent per offset; pass `next` back |
| `session_kill` | `id`, `signal?` (`TERM`)                                                                           | `{ok: true}`                                                                                                                |
| `session_list` | —                                                                                                  | `{sessions: ApiSessionRow[]}` (`session list --json` rows)                                                                   |
| `put`          | `local`, `remote`, `checksum?`                                                                     | `TransferOut` (`files`, `skipped`, `bytes`, `duration_ms`); needs `--allow-local-paths`                                      |
| `get`          | `remote`, `local`                                                                                  | `TransferOut`; needs `--allow-local-paths`                                                                                   |
| `info`         | —                                                                                                  | `InfoOut` (`server` = `Open::Info` or null, `connection`, empty `sessions`/`forwards`)                                       |
| `hosts`        | —                                                                                                  | `{hosts: [{host, target, connected, connection \| null}]}`                                                                  |

The schemas are hand-written in `crates/mysh/src/mcp/schema.rs` and mirror
the `--json` types in `mysh::output` and `session_api`; a change there is a
change here.

### Resources

Files are also readable as resources: `mysh://HOST/` is the remote home
(listed in `resources/list` as `inode/directory`), `mysh://HOST/etc/hosts`
an absolute path and `mysh://HOST/~/notes.txt` a path under the home. A
directory reads as `application/json` text `{"path", "entries": [LsEntry]}`
(dot-files included); a UTF-8 file as `text/plain`; anything else as an
`application/octet-stream` base64 `blob`. Reads are capped at 1 MiB (use
the `read_file` tool with `offset` for more). A missing path is JSON-RPC
error `-32002` with `data.code = "not_found"`; other remote failures are
`-32603` with `data.code` set the same way.

### Example session

```
→ {"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"x","version":"0"}}}
← {"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-06-18","capabilities":{…},"serverInfo":{"name":"mysh","version":"0.1.0"},"instructions":"…"}}
→ {"jsonrpc":"2.0","method":"notifications/initialized"}
→ {"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"exec","arguments":{"host":"pi","command":"uname -sm"}}}
← {"jsonrpc":"2.0","id":2,"result":{"content":[{"type":"text","text":"{\"stdout\":\"Linux aarch64\\n\",…}"}],"structuredContent":{"stdout":"Linux aarch64\n","stderr":"","exit":0,"signal":null,"duration_ms":41,"timed_out":false},"isError":false}}
→ {"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"stat","arguments":{"host":"pi","path":"/nope"}}}
← {"jsonrpc":"2.0","id":3,"result":{"content":[{"type":"text","text":"{\"error\":{\"code\":\"not_found\",\"message\":\"/nope: no such file\"}}"}],"structuredContent":{"error":{"code":"not_found","message":"/nope: no such file"}},"isError":true}}
```
