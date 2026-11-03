# 03 — Wire protocol (v1)

Everything below is implemented by `mysh-proto` (types) and `mysh-net`
(framing, handshake, mux). Byte orders are stated per field; postcard handles
its own encoding (varints, little-endian).

## 1. Preamble (cleartext)

```
client → server:  "MYSH"  u16-LE version         (version = highest the client speaks)
server → client:  "MYSH"  u16-LE version         (min(client, server max)) — or close
```

The agreed version is bound into the Noise **prologue** `b"mysh" ‖ u16-LE
version`, so a middlebox that rewrites the preamble causes handshake failure
rather than a silent downgrade. Unknown magic → close without reply.

## 2. Handshake

`Noise_XX_25519_ChaChaPoly_BLAKE2s`, client = initiator.

| msg | dir | tokens          | payload (postcard)                                     |
| --- | --- | --------------- | ------------------------------------------------------ |
| 1   | →   | `e`             | empty                                                  |
| 2   | ←   | `e, ee, s, es`  | `ServerHello { name: String, caps: u32 }`              |
| 3   | →   | `s, se`         | `ClientHello { caps: u32, auth: AuthProof }`           |

```rust
enum AuthProof {
    Static,                                                // the Noise static is the identity
    Ed25519 { public_key: [u8; 32], signature: Vec<u8> },  // 64-byte signature
}
```

Between 2 and 3 the client runs the server-trust check (02-security.md) on
`get_remote_static()`. On failure it closes without sending 3.

**Signature authentication** (02-security.md "Signature authentication"):
with `AuthProof::Ed25519` the client's `s` is a fresh random key for this
connection and the proof is `signature = Ed25519(sk, SIG_AUTH_LABEL ‖ h2)`
where `SIG_AUTH_LABEL = "mysh-sig-auth-v1"` and `h2` is the Noise handshake
hash (`get_handshake_hash()`) after message 2 has been processed and before
message 3 is written — the same value on both sides, committing to the
prologue, both ephemerals and the server static. The server snapshots `h2`
before reading 3, requires `signature.len() == 64`, decodes `public_key`
with `ed25519-dalek` and checks `verify_strict`; a failure is
`Denied { Unauthorized, "bad signature" }`. A proof sent to a server whose
`ServerHello.caps` lacks `SIG_AUTH` is `Denied { Unsupported }`; the client
checks the bit first and never sends 3 in that case. The authorized identity
is then the ed25519 key (`Peer::Ed25519`), not the Noise static.

After 3 the server runs authorization. Then both sides call
`into_stateless_transport_mode()` and maintain independent send/recv nonce
counters, which is what lets the read and write halves run concurrently
without a lock.

`caps` is a bitfield of optional features that need no version bump
(`mysh_proto::caps`): `SIG_AUTH` (1, server → client: `AuthProof::Ed25519`
is accepted; set unless `--no-signature-auth`) and `PERSIST` (2, server →
client: detached PTY sessions are kept, see §10bis; set when
`--detach-grace` is not 0). Unknown bits are ignored. `name` is the
server's hostname (informational, shown by `info`).

Timeouts: the server allows 5 s from TCP accept to the end of message 3.

## 3. Transport framing

Each Noise transport message on the wire:

```
u16-BE ciphertext_len ‖ ciphertext         (ciphertext_len ≤ 65535, includes 16-byte tag)
```

`NoiseStream` implements `AsyncRead + AsyncWrite`: writes are chunked at
65519 plaintext bytes; reads surface one decrypted message at a time with
internal buffering. A decryption failure is fatal for the connection.

The first transport-mode message is always `Msg<Verdict>`, server → client:
`Accepted`, after which yamux frames begin, or `Denied { code, message }`
(`Unauthorized` for an untrusted client static) followed by close. The
client reads it before starting the mux, so the two are never ambiguous on
the wire.

**Rekey.** Either side rotates its *sending* key in-band, below yamux: a
transport message with empty plaintext (`u16-BE 16 ‖ 16-byte tag`) means
"every later message from me is under `REKEY(k)`" (Noise §4.2; snow
`rekey_outgoing` / `rekey_incoming`). The sender emits it right after the
data message that crosses its policy (`REKEY_BYTES` plaintext sent under the
key, or `REKEY_INTERVAL` since the key came into use; checked on every
sealed frame, no timer), then rekeys; the receiver rekeys its receiving
state and surfaces nothing to the reader. Nonces are **not** reset by a
rekey: both counters keep running, which keeps the two directions
independent and needs no message ordering between them. A data message is
never empty, so there is no ambiguity. Each side's thresholds are its own
(`NoiseStream::set_rekey_policy`); counts are exposed in `TransferStats`
(`rekeys_out`, `rekeys_in`). A header of `0` (shorter than the tag) is a
protocol error.

## 4. Multiplexing

**yamux** (crate `yamux` 0.14, protocol spec v0.1) runs over `NoiseStream`.
Client in `Mode::Client` (odd stream ids), server in `Mode::Server`.
Both sides open streams.

Config: receive window starts at 256 KiB and may grow to 4 MiB per stream
(yamux auto-tuning); max 512 concurrent streams; yamux's own keep-alive is
off, mysh pings on the control stream instead (§6).

Why yamux rather than a hand-rolled mux: per-stream flow control is the part
of a multiplexer that is easy to get subtly wrong (one busy forward must not
stall the interactive session), and the crate is small and widely exercised.
Cost: one `futures-io` ↔ tokio compat layer. If this becomes painful the
mux can be replaced without touching any message types, since all
mysh-level framing lives inside streams.

## 5. Stream prologue

Every stream begins with a message from the opener, answered by the acceptor:

```
Msg<Open>        opener → acceptor
Msg<OpenReply>   acceptor → opener
```

`Msg<T>` = `u32-LE len ‖ postcard(T)`, `len ≤ 262144`. The same framing is
used for every message-mode stream below. Raw-mode streams carry bytes with
no further framing after the prologue.

```rust
enum Open {
    Control,                                   // exactly one per connection, opened by the client first
    Session(SessionRequest),                   // client → server
    DirectTcp { host: String, port: u16 },     // client → server; raw after Ok
    ForwardListen { host: String, port: u16 }, // client → server; message mode, lives as long as the listener
    ForwardedTcp { listener: u32, peer: String }, // server → client; raw after Ok
    File { op: FileOp, cwd: Option<String> },  // client → server; see 04-sessions.md
    Cwd { session: u32 },                      // client → server; one CwdReply then close
    Attach { session: u32 },                   // client → server; reattach a detached PTY session (§10bis)
    ListSessions,                              // client → server; one Msg<Vec<DetachedSession>> then close (§10bis)
    Info,                                      // client → server; one Msg<Info> then close (§10quater)
    Read { session: u32, offset: u64, max: u32, wait_ms: u32 }, // client → server; one Msg<ReadReply> then close (§10ter)
    Write { session: u32, eof: bool },         // client → server; raw stdin, then close (§10ter)
    Signal { session: u32, signal: Signal },   // client → server; kill(pid, signal), then close (§10ter)
}

enum OpenReply {
    Ok,
    Err { code: ErrorCode, message: String },
}

enum ErrorCode { Unauthorized, Denied, NotFound, Unsupported, Io, Limit, Protocol }
```

`Denied` is a policy refusal (`--deny …`), `Unsupported` an unknown or
unimplemented `Open` variant, `Limit` a quota (streams, listeners).

The acceptor must answer within 10 s of accepting the stream or the opener
resets it.

## 6. Control stream

Opened by the client immediately after the handshake; message mode in both
directions. The server closes the connection if the first stream it accepts
is anything else, so the client's `connect` does not return until the
control stream's `OpenReply::Ok` has arrived — no other stream can be
opened earlier.

```rust
enum ControlMsg {
    Ping { nonce: u64 },
    Pong { nonce: u64 },
    Notice(String),                 // server → client; shown on stderr ("server shutting down")
    Shutdown { reason: String },    // either side; peer finishes in-flight streams, then closes
}
```

Keep-alive: the client pings every 30 s; three consecutive unanswered pings →
the client declares the connection dead (exit 255). The server closes a
connection whose control stream has been silent for 120 s (`--idle-timeout`).
TCP keep-alive is not set in v1 (tokio exposes no API for it; the pings
cover liveness).

RTT shown by `info`/`ping` is measured here.

## 7. Session stream

One stream per session; message mode in both directions. Both PTY and
non-PTY (exec) sessions share it; stderr is only used without a PTY. A
connection may have many sessions open at once (the client's `shell`
command). Session ids are **server-wide**: one counter per server process,
starting at 1, never reused, so a detached PTY session (§10bis) keeps its
id across the connections that attach to it. The per-connection quota
(§12) still applies to the sessions a connection currently holds.

```rust
struct SessionRequest {
    kind: SessionKind,
    env: Vec<(String, String)>,        // filtered by the server (02-security.md)
    pty: Option<PtyRequest>,
    cwd: Option<String>,               // start directory; `~/` expanded, relative to home; unusable → home
    persist: bool,                     // register the session server-side and keep it when this stream closes (§10ter)
}
enum SessionKind { Shell, Exec { argv: Vec<String> } }
struct PtyRequest { term: String, size: WinSize }
struct WinSize { cols: u16, rows: u16, xpixel: u16, ypixel: u16 }

// client → server
enum SessionIn {
    Stdin(Vec<u8>),
    StdinEof,                 // exec: close child's stdin; pty: send EOT is the client's business, ignored
    Resize(WinSize),          // pty only
    Signal(Signal),           // kill(child_pid, sig)
}
enum Signal { Int, Term, Hup, Kill, Quit, Usr1, Usr2, Winch }

// server → client
enum SessionOut {
    Started { session: u32, pid: u32, cwd_fallback: bool },  // cwd_fallback: requested cwd was unusable, started in home
    Stdout(Vec<u8>),
    Stderr(Vec<u8>),          // exec without pty only
    Exited(ExitStatus),       // last message; server then closes its write side
    Attached { session: u32, pid: u32, buffered: u64, dropped: u64 },  // first message on an Attach stream (§10bis)
}
enum ExitStatus { Code(i32), Signal { signal: i32, core_dumped: bool } }
```

Ordering guarantees: `Started` precedes any output; `Exited` follows all
output (the server drains the pty/pipes to EOF before sending it). Data is
chunked at ≤ 64 KiB per message. A `Stdin` message after `Exited` is
ignored.

Why one message-mode stream instead of a control stream plus a raw data
stream: a single stream keeps control and data ordered, avoids cross-stream
id matching, and the per-message overhead (≤ 5 bytes on a 64 KiB chunk) is
negligible. Backpressure comes from the yamux window: a client that reads
slowly throttles the remote process instead of growing buffers on either
side.

The `session` id in `Started` is referenced by `Open::Cwd` and
`Open::Attach`.

**Attach semantics.** When a PTY session's stream ends without `Exited` —
the connection dropped, or the client half-closed the stream (`detach`) —
and the server's detach grace window is open, the server does not hang the
session up: it keeps the master and the child, drains output into a bounded
ring, and lists the session as detached (§10bis). The next `Open::Attach`
turns the new stream into the session stream: `Attached` (in place of
`Started`), the ring as `Stdout` chunks, then live traffic with the same
`SessionIn`/`SessionOut` rules, ending in `Exited`. A client should send
`Resize` right after `Attached`, since its terminal is not the one the
session last saw. Exec (non-PTY) sessions never persist.

**Offsets.** Every *registered* session — a PTY session (which may be
detached and reattached) and any session opened with `persist: true` —
has a server-side output ring addressed by **absolute byte offsets**:
`next` counts every byte the session ever produced on either stream,
`oldest` is the first byte still retained (the ring keeps 1 MiB), and the
pump fills it whether or not a stream is attached. The attached stream
still receives live `SessionOut` messages; the ring only records what was
produced, so a reader using `Open::Read` (§10ter) and an attached client
see the same bytes. Offsets are per session and never restart.

A `persist: true` session is registered at `Started` and survives the
stream that opened it: dropping that stream is a detach (for a PTY
session, exactly as in §10bis), not a hang-up, and the session stays
addressable until the grace window passes — including after its process
exits, so a reader can still collect the output and the status. The
server answers `Err { Unsupported }` to `persist: true` when its grace
window is 0.

## 8. TCP forwarding streams

- `DirectTcp { host, port }`: server dials; on success `Ok` then raw bytes
  both ways. Half-close maps to `shutdown(SHUT_WR)` on the TCP side and to
  yamux's write-close on the stream side, in both directions. Dial failure →
  `Err { Io | NotFound }` with the OS message.
- `ForwardListen { host, port }`: server binds; replies `Ok` then one
  message `Bound { listener: u32, port: u16 }` (port is the actual port when
  0 was requested). The stream stays open; the client closing it cancels the
  listener. Server-side bind failures → `Err`.
- `ForwardedTcp { listener, peer }`: opened by the server for each accepted
  connection. The client dials its configured target and replies `Ok` (raw
  thereafter) or `Err` (server closes the accepted socket).

SOCKS5 (`-D`) is implemented purely in the client: it parses `CONNECT`
(IPv4, IPv6, domain) and opens `DirectTcp`. No authentication, no `BIND`,
no UDP.

## 9. File streams

`Open::File { op, cwd }`. `cwd` is an optional base directory for relative
paths (the client passes the session's probed cwd); absent → server home.
A leading `~/` is expanded server-side. Reply is `OpenReply` followed by an
op-specific body:

```rust
enum FileOp {
    Stat { path: String },                                  // → Msg<Attrs>
    List { path: String },                                  // → Msg<Vec<DirEntry>> pages of ≤ 1000 entries, last page has `more: false`
    Mkdir { path: String, mode: u32 },                      // → Ok
    Remove { path: String, recursive: bool },               // → Ok
    Rename { from: String, to: String },                    // → Ok
    SetAttr { path: String, mode: Option<u32>, mtime: Option<i64> },  // → Ok
    Realpath { path: String },                              // → Msg<String>
    Get { path: String, offset: u64 },                      // → Msg<Attrs>, then raw bytes until server closes
    Put { path: String, mode: u32, mtime: Option<i64>, offset: u64, truncate: bool, atomic: bool },
                                                            // client streams raw bytes, half-closes; → Msg<PutDone { written: u64 }>
}
struct Attrs { kind: FileKind, size: u64, mode: u32, mtime: i64, uid: u32, gid: u32 }
enum FileKind { File, Dir, Symlink { target: String }, Other }
struct DirEntry { name: String, attrs: Attrs }
```

`Put` with `atomic: true` writes to `<path>.mysh-tmp.<rand>` and renames on
success; the client sets `atomic` when the destination is absent or a
regular file, and clears it for devices/FIFOs. Integrity is provided by the
transport; no per-file checksum in v1.

## 10. Cwd probe

`Open::Cwd { session }` → `Ok` → `Msg<Option<String>>` → close. The server
resolves the foreground process group of the session's pty
(`tcgetpgrp(master)`) and probes that pid's cwd, falling back to the shell
pid, then `None` (04-sessions.md). Used by the meta shell so that
`put foo` lands where the remote shell currently is.

## 10bis. Detached sessions

Advertised by `caps::PERSIST` in the `ServerHello`; both opens answer
`Err { Unsupported }` when the server's grace window is 0.

`Open::ListSessions` → `Ok` → `Msg<Vec<DetachedSession>>` → close. Only the
sessions opened by **the connecting client key** are listed: detached ones
(`detached: Some(unix seconds)`, `buffered` = ring bytes) first, then the
ones currently attached by any connection (`detached: None`, so the client
can show the full picture). Other keys' sessions do not exist from the
client's point of view.

```rust
struct DetachedSession {
    id: u32,
    pid: u32,
    kind: String,            // "shell" or the exec command line
    started: i64,            // unix seconds
    detached: Option<i64>,   // unix seconds; None while attached
    buffered: u64,           // produced but not yet handed to a session stream
    pty: bool,               // false for a `session new` exec session
    next: u64,               // absolute offset past the newest byte (§7)
    oldest: u64,             // absolute offset of the oldest byte still readable
    exited: Option<ExitStatus>, // set once the process ended; the entry stays for the grace window
}
```

`Open::Attach { session }` → `Ok` when `session` belongs to this client key
and is detached, else `Err { NotFound }` (unknown, expired, or another
key's) or `Err { Limit, "attached by another connection" }`; `Denied` under
`no-pty`; `Limit` at the per-connection session quota, which the attached
session now counts towards. After `Ok`: `SessionOut::Attached { session,
pid, buffered, dropped }`, `buffered` bytes of `Stdout` (what the session
printed while detached; `dropped` bytes older than the 1 MiB ring were
lost), then the normal session stream (§7). If the process exited while
detached, the entry stays listable until the grace window ends and an
attach replays the ring and then sends `Exited` with the recorded status.

Server side the detached session is owned by the server, not by any
connection: a grace timer (default 10 min, `--detach-grace SECS`) hangs it
up (close the master → `SIGHUP`, reap) when nobody reattaches; server
shutdown hangs every detached session up.

## 10ter. Reading, writing and signalling a session

The three streams of the remote process API (05-meta-shell.md, "Session
command family"). Each addresses a **registered** session (§7) by id and
is refused with `Err { NotFound }` unless the connecting client key owns
it — another key's sessions do not exist. Every call is a short-lived
stream, so one connection serves any number of sessions and readers.

`Open::Read { session, offset, max, wait_ms }` (kind 10) → `Ok` →
`Msg<ReadReply>` → close.

```rust
struct ReadReply {
    offset: u64,             // first byte returned: max(requested offset, oldest)
    next: u64,               // offset to pass next
    oldest: u64,             // oldest offset the server still has
    chunks: Vec<Chunk>,      // runs of bytes in arrival order
    exited: Option<ExitStatus>,
}
struct Chunk { stream: OutStream, bytes: Vec<u8> }
enum OutStream { Stdout, Stderr }
```

`max` is clamped to 1 MiB and further to what one control message can
carry (256 KiB less framing); the reader continues from `next`. `wait_ms`
is clamped to 60 s: when nothing at or after `offset` is buffered and the
process is still running, the server waits that long for new output
before answering (an empty reply is a legitimate answer). Reads are
**idempotent**: the same offset returns the same bytes until they age out
of the ring, and `offset > requested` says exactly how much was lost.
Non-PTY sessions keep stdout and stderr apart through `Chunk.stream`; a
PTY session has one stream, as a terminal does.

`Open::Write { session, eof }` (kind 11) → `Ok` → raw bytes until the
client half-closes → close. The bytes go to the session's stdin (the pty
master, or the child's stdin pipe); with `eof` the child's stdin is
closed afterwards, which is how a `cat` session is ended. Without it the
session keeps accepting further writes. A write that the child does not
read within 5 s is dropped rather than stalling the pump that drains its
output.

`Open::Signal { session, signal }` (kind 13) → `Ok` → close, after
`kill(child_pid, signal)`; `Err { Io }` carries the OS message. It is the
streamless form of `SessionIn::Signal`, usable while no stream is open.

## 10quater. Server info

`Open::Info` (kind 9) → `Ok` → `Msg<Info>` → close. Nothing runs on the
server: the reply is assembled from the connection's effective policy
(per-key options applied, §2), the process environment and `uname(2)`. A
client — or a program driving one (05-meta-shell.md "Agent interface") —
learns what it is talking to before opening a session.

```rust
struct Info {
    name: String,            // ServerHello.name
    version: String,         // mysh version of the server binary
    platform: Platform,      // { os: "linux"|"macos"|"android", arch: "aarch64"|…, kernel: "6.8.0-…" (uname -r; "" if unknown) }
    shell: String,           // what a Shell session runs (--shell → $SHELL → passwd → /bin/sh)
    home: String,
    user: String,
    caps: u32,               // the ServerHello.caps bits
    limits: Limits,          // { max_sessions, max_listeners, max_streams, detach_grace_secs, idle_timeout_secs, handshakes_per_minute, denied: ["exec", …] }
    uptime_secs: u64,        // since the server process started
}
```

`limits.denied` lists the features switched off for **this** connection
by `--deny` and the key's options, with the `--deny` spellings (`pty`,
`exec`, `files`, `forward-local`, `forward-remote`). No `Denied` case: the
reply is always answered for an authorized client.

## 11. Versioning and extensibility

- Incompatible changes bump `PROTOCOL_VERSION`; the preamble negotiates
  down, and a server may refuse old versions with a closed socket.
- postcard enums are extended by **appending** variants only. A peer
  receiving an unknown `Open` variant cannot decode it and must reply
  `Err { Unsupported }`; to make that possible the `Open` message is sent
  with a 1-byte kind tag first (`u8 kind ‖ postcard(body)`) so the acceptor
  can answer without decoding the body.
- `caps` bitfields in the hellos are reserved for optional features that do
  not warrant a version bump.

## 12. Limits (v1 constants)

| limit                         | value    |
| ----------------------------- | -------- |
| Noise message (ciphertext)    | 65535 B  |
| control/stream message        | 256 KiB  |
| session data chunk            | 64 KiB   |
| open streams per connection   | 512      |
| sessions per connection       | 32       |
| remote listeners per connection | 32     |
| handshake deadline            | 5 s      |
| open-reply deadline           | 10 s     |
| ping interval / dead after    | 30 s / 3 |
| server idle close             | 120 s (`--idle-timeout`) |
| rekey (bytes / age of key)    | 1 GiB / 1 h |
| detach grace / detached ring  | 600 s (`--detach-grace`) / 1 MiB |
| `Open::Read` max / wait       | 1 MiB / 60 s |
| master idle exit              | 600 s (`--idle`) |
