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

| msg | dir | tokens          | payload (postcard)                          |
| --- | --- | --------------- | ------------------------------------------- |
| 1   | →   | `e`             | empty                                       |
| 2   | ←   | `e, ee, s, es`  | `ServerHello { name: String, caps: u32 }`   |
| 3   | →   | `s, se`         | `ClientHello { caps: u32 }`                 |

Between 2 and 3 the client runs the server-trust check (02-security.md) on
`get_remote_static()`. On failure it closes without sending 3.

After 3 the server runs authorization. Then both sides call
`into_stateless_transport_mode()` and maintain independent send/recv nonce
counters, which is what lets the read and write halves run concurrently
without a lock.

`caps` is a reserved bitfield, zero in v1. `name` is the server's hostname
(informational, shown by `info`).

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
command); session ids are unique per connection and never reused.

```rust
struct SessionRequest {
    kind: SessionKind,
    env: Vec<(String, String)>,        // filtered by the server (02-security.md)
    pty: Option<PtyRequest>,
    cwd: Option<String>,               // start directory; `~/` expanded, relative to home; unusable → home
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

The `session` id in `Started` is referenced by `Open::Cwd`.

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
