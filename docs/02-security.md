# 02 — Identity, keys, trust

## Primitives

The transport is **`Noise_XX_25519_ChaChaPoly_BLAKE2s`** via `snow`, used
exactly as specified by the Noise framework. Nothing is negotiated: no cipher
suites, no auth methods, no extensions. A protocol version bump is the only
upgrade mechanism.

Why XX:

- Both peers authenticate with long-term X25519 static keys; ephemeral keys
  give forward secrecy per session.
- The server's static is sent encrypted (message 2), the client's static is
  sent encrypted and only **after** the client has verified the server
  (message 3). A client never reveals its identity to an unverified server.
- Works for first contact (TOFU); IK would require knowing the server key up
  front.
- 1.5 RTT handshake. Acceptable for an admin tool over TCP.

Rejected: TLS (certificate plumbing, PKI-shaped trust, large dependency),
SSH transport (the thing being replaced), anything bespoke.

## Key material

### Native keys

X25519 keypairs. Text formats, one line each:

```
mysh-x25519-secret <base64 32B>            # private key file, mode 0600
mysh-x25519 <base64 32B> [comment]         # public key; also the authorized_keys / known_hosts entry form
```

Fingerprint: `SHA256:<base64-unpadded(sha256(raw 32-byte public key))>`,
same shape as OpenSSH so it reads naturally.

`mysh keygen [-o PATH] [-C comment]` writes `PATH` and `PATH.pub`
(default `~/.config/mysh/id`). `mysh fingerprint [PATH]` prints the
fingerprint of a public/private key file (either format).

### OpenSSH ed25519 keys (reuse)

Accepted anywhere a mysh key is accepted:

- private: OpenSSH private key files containing an `ssh-ed25519` key
  (`~/.ssh/id_ed25519`, `/etc/ssh/ssh_host_ed25519_key`), including
  passphrase-encrypted ones (prompted; `ssh-key` crate with `encryption`).
- public: `ssh-ed25519 AAAA... comment` lines in `authorized_keys`,
  `known_hosts` (plain or `|1|` hashed hostnames), and `-i`/`--pin` args.

Conversion to X25519 is the standard birational map, identical to what `age`
does for `ssh-ed25519` recipients:

- secret scalar: `clamp(SHA-512(seed)[0..32])` (the ed25519 signing scalar)
- public: Edwards `(x, y)` → Montgomery `u = (1 + y) / (1 − y)`

Using one ed25519 key for both signing (ssh) and X25519 DH (mysh) is a
cross-protocol use; it has been analysed and found safe
(Thormarker, *On using the same key pair for Ed25519 and an X25519 based
KEM*, IACR ePrint 2021/509). mysh never signs with a key it has loaded
itself; it only asks an `ssh-agent` to sign (below).

**Not supported:** `ssh-rsa`, `ecdsa-*`, `sk-*` (FIDO). Keys that cannot
be exported (agent-only, hardware-backed) are usable through the agent via
signature authentication, ed25519 only.

### Signature authentication (`ssh-agent`)

An agent holds a key but never reveals it, so it cannot take part in the
Noise DH. For an agent-held ed25519 key the client therefore proves its
identity by **signature**, inside the same `XX` handshake:

- the client's Noise static is a **fresh random X25519 key per connection**
  (no long-term secret on the client side at all);
- after message 2, once the server is verified, the client snapshots the
  Noise handshake hash `h2` and asks the agent to sign
  `"mysh-sig-auth-v1" ‖ h2` (`SIG_AUTH_LABEL`);
- message 3 carries `ClientHello { caps, auth: Ed25519 { public_key, signature } }`
  (03-protocol.md §2); the server takes the same `h2` snapshot before
  reading message 3, verifies the signature (`ed25519-dalek`,
  `verify_strict`) and authorizes the **ed25519 key** directly against the
  `ssh-ed25519` entries of `authorized_keys` (no X25519 conversion is
  involved; the Noise static is discarded).

Properties: `h2` commits to both ephemerals, the server's static and the
prologue, so a signature is bound to one handshake and cannot be replayed
into another; the signature travels encrypted in message 3, so the client's
identity is still hidden from an unverified server; forward secrecy is
unchanged (`ee` is still mixed in). The signature does not cover the Noise
static because that key is ephemeral and carries no identity. Static-key
authentication (`auth: Static`) is the default for key files and is
unchanged.

Capability: the server advertises `caps::SIG_AUTH` in its `ServerHello`
(on by default, `--no-signature-auth` switches it off). A client with only
agent keys against a server without the bit stops before sending anything
identifying and reports that the server does not support agent keys; a
server that receives an `Ed25519` proof while the bit is off refuses it
with `Denied { Unsupported }` without consulting `authorized_keys`.

Client order: `-i PATH` is the only identity when given; a `.pub` file (or
any file whose first line is `ssh-ed25519 …`) names the agent key to use
and is an error if the agent does not hold it. Otherwise the first existing
key file (table below) is tried first and then up to five ed25519 keys from
`$SSH_AUTH_SOCK`, in the agent's order; a key is only skipped on
`Denied { Unauthorized }`, any other failure stops the attempt. Each
identity is one TCP connection and handshake (the rate limiter counts
them). `--baked-only` never consults the agent. `info` shows which identity
was accepted (`x25519 SHA256:… (path)` or `ssh-ed25519 SHA256:… (agent:
comment)`), and `authorize` installs an `ssh-ed25519` line for an agent
identity. Fingerprints of agent keys are the OpenSSH ones (`ssh-add -l`).

The server logs `ssh-ed25519 SHA256:…` for such a peer and treats that key
as the owner of its detached sessions, exactly like an X25519 static.

### Baked keys

`cargo build --features baked` with:

- `MYSH_BAKED_IDENTITY=<path>`: a private key file (native or OpenSSH).
- `MYSH_BAKED_PEERS=<path>`: an `authorized_keys`-format file of trusted
  public keys.

`build.rs` embeds both files verbatim (`include_str!`) and the runtime parses
them with the same parsers used for on-disk files. Semantics, for **both**
roles:

- the baked identity is the default identity (lowest precedence after
  explicit flags, see below);
- baked peers are trusted as clients (server role) and as servers (client
  role).

A self-trusting fleet needs one keypair: `mysh keygen -o fleet`, then build
with `MYSH_BAKED_IDENTITY=fleet MYSH_BAKED_PEERS=fleet.pub`. Any device
running that binary can serve and connect to any other. Asymmetric trust is
two builds with different inputs.

`--baked-only` (both roles) ignores every file on disk. Without it, files
extend the baked set when present, so a baked fleet binary can still accept
an admin's personal key via `authorized_keys`.

Threat note: the binary **is** a credential. Anyone holding it holds the
identity. Rotate by rebuilding. Do not commit baked inputs (`.gitignore`
covers `baked-*` and `*.secret`).

## Identity resolution

First match wins.

| role   | order                                                                                   |
| ------ | --------------------------------------------------------------------------------------- |
| client | `-i PATH` (a private key, or a `.pub` naming an agent key) → first of `$MYSH_IDENTITY` → baked → `~/.config/mysh/id` → `~/.ssh/id_ed25519`, then ed25519 keys from `$SSH_AUTH_SOCK` (above) |
| server | `--key PATH` → `$MYSH_HOST_KEY` → baked → `~/.config/mysh/host_key` (auto-generated 0600 on first `serve`) |

`--key /etc/ssh/ssh_host_ed25519_key` lets the server present the same
identity as `sshd`, which in turn lets clients verify it through their
existing `~/.ssh/known_hosts` (below). Generation of `host_key` is skipped
with `--no-generate-key` (fail instead).

## Authorization (server)

The set of trusted client keys is the union of:

1. baked peers;
2. `~/.config/mysh/authorized_keys` (`mysh-x25519` and `ssh-ed25519` lines;
   unknown key types are skipped with a warning);
3. `~/.ssh/authorized_keys`, `ssh-ed25519` (and `mysh-x25519`) entries;
   other key types skipped (default on; `--no-ssh-authorized-keys` disables);
4. `--authorized-key <pubkey>` and `--authorized-keys <path>`, repeatable.

Files are re-read on every connection; no reload signal needed. A server
whose trusted set is empty refuses to start (fail closed).

The check runs after the Noise handshake completes, on the authenticated
remote static — or, for signature authentication, on the ed25519 key whose
signature was just verified (above). An unauthorized client receives
`Verdict::Denied { code: Unauthorized }` as the first transport message and
the connection is closed; the fingerprint is logged at `warn`. Authorization
precedes every service: no stream is accepted from an unauthenticated peer.

### Per-key options

An `authorized_keys` line may start with the OpenSSH option prefix
(comma-separated, values optionally double-quoted with `\"` escapes, names
case-insensitive). Parsed by `mysh-net` into `trust::KeyOptions`; enforced
by the server as a per-connection narrowing of its `Policy`:

| option                | effect                                                                 |
| --------------------- | ---------------------------------------------------------------------- |
| `command="…"`         | forced command: every session runs it; the requested command is passed in `MYSH_ORIGINAL_COMMAND` |
| `no-pty`              | PTY sessions denied for this key (`Feature::Pty`)                      |
| `no-files`            | file streams denied (`Feature::Files`); mysh-specific                  |
| `no-forward`          | local and remote forwarding denied; `no-port-forwarding` is an alias   |
| `from="pat,…"`        | source-address filter, see below                                       |
| `restrict`            | `no-pty,no-files,no-forward`; a later `pty`, `files` or `port-forwarding` re-enables one |

Other OpenSSH options (`environment=`, `permitopen=`, `agent-forwarding`,
…) are ignored with a `debug` log. A malformed option list (unterminated
quote, `command`/`from` without a value) skips the whole line with a
warning, so a typo never widens access.

`from=` patterns are matched against the peer's IP address only — never a
reverse-DNS name. A pattern is an exact address (`192.0.2.7`, `::1`,
compared numerically), a CIDR block (`10.0.0.0/8`, `fd00::/8`; same address
family only, no v4-mapped tricks), or a glob over the textual address (`*`,
`?`; `192.168.1.*`). A leading `!` negates. OpenSSH semantics: if any
negated pattern matches the connection is refused; otherwise at least one
positive pattern must match. An empty list allows any source. The check
runs in the authorization callback, so a refused source gets
`Denied { Unauthorized }` exactly like an unknown key, and the pattern list
is logged at `warn`.

## Server trust (client)

After Noise message 2 the client knows the server static. It is checked, in
order:

1. `--pin <fingerprint|pubkey>`;
2. baked peers;
3. `~/.config/mysh/known_hosts`: lines `host[:port] mysh-x25519 <b64>` or
   `host[:port] ssh-ed25519 <b64>`; `host:port` entries match before bare
   `host` entries;
4. `~/.ssh/known_hosts`, `ssh-ed25519` entries for `host`, `[host]:port`,
   plain or `|1|`-hashed (HMAC-SHA1 over the hostname), converted to X25519;
5. TOFU: if the key is unknown and stdin is a terminal, show
   `host:port` and the fingerprint and ask `yes/no`; on yes append to
   `~/.config/mysh/known_hosts`. `--accept-new` answers yes silently;
   `--strict` fails.

A **mismatch** against any known entry is a hard failure with a loud message
naming the file and line. There is no bypass flag; the user edits the file.
On failure the client closes the connection without sending message 3.

**Connect-back.** With `mysh serve --connect-back ADDR` the server opens
the TCP connection to a client that accepts connections (`mysh accept`);
the protocol roles and everything above are unchanged — the server still
authorizes the client's key against its `authorized_keys` (per-key options
and `from=` included, applied to the accepting client's address), and the
client still verifies the server's static key before revealing its own.
Only the lookup differs on the accepting side: the source address of a
server that dialed in means nothing, so the client identifies callers by
key fingerprint through its `callers` store, never by `host:port` (see
"Callers"). A server never dials more than one connection per address at
a time, retries failures with backoff, and closes a connection the client
holds longer than `--connect-max` itself.

## Callers

A **caller** is a server allowed to connect back to a client that accepts
connections (`mysh accept`, `mysh_client::Acceptor`). The client lists them
in `~/.config/mysh/callers`, in `authorized_keys` line format:

```
mysh-x25519 <base64> host-a
ssh-ed25519 AAAAC3Nza… host-b
# unnamed: addressed by fingerprint
mysh-x25519 <base64>
```

The comment is the **name**: the accepted connection is served at
`<runtime>/mysh/@NAME.sock` and addressed as `@NAME` by every other
command (`mysh @host-a uptime`, `put … @host-a`, `run --hosts @host-a,@host-b`).
A line without a comment is addressed by the first twelve base64 characters
of its fingerprint (`SHA256:` stripped), and so is a key recorded by
`--accept-new`; naming such a caller is an edit to the file. Baked peers
count as callers too, named by their comment.

The store is keyed by **key**, never by address: the source address of a
connecting-back server is meaningless, and two servers behind the same
address are still two callers. A key that is in neither the file nor the
baked peers is refused (`trust_unknown`) before the client reveals its own
static key in Noise message 3 — the handshake's identity hiding favours the
accepting side. `mysh accept --accept-new` instead records the key (without
a name) and accepts it; this is first contact, with the same caveat as
TOFU. Unknown, refused and accepted connections are all reported
(`refused`, `accepted`, `closed` events) and rate limited per source
address (`--handshakes-per-minute`, default 30).

The client's own identity and the server's `authorized_keys` check are
unchanged: an accepting client authenticates exactly as a dialing one.

## Pairing

First contact without copying key files by hand: a one-time code typed on
both sides establishes mutual trust. `mysh serve --pair [DURATION]`
(default 5 min) prints

```
pairing code: apple-bread-cat-dog-eagle-fish (valid 5m, single use)
```

to stderr and the log; `SIGUSR1` opens a fresh window on a running server
(replacing any). Codes are 6 words from the BIP-39 English list
(`mysh::wordlist`, 2048 words, 66 bits), drawn with `OsRng`; typing them
with spaces or in any case is fine (`normalize_code`).

Flow (`mysh pair HOST CODE`, wire details in 03-protocol.md §10quinquies):

1. The client connects with its normal identity (key file or agent key),
   **accepts the server static unverified** (no `known_hosts` write yet)
   and sets `caps::PAIR_REQUEST` in its `ClientHello`.
2. If a window is open (not used, not expired) the server skips
   authorization and answers `Verdict::Pairing`: the connection is
   pairing-only, `Open::Control` and one `Open::Pair` stream and nothing
   else. Without an open window the bit is ignored and the client is
   treated like any other (an unknown key is `Denied`; the client reports
   "server has no pairing window open").
3. On the `Pair` stream both run **SPAKE2** (`spake2` crate, Ed25519
   group) with password = the normalized code and identities = the two
   Noise static keys of this very connection, then confirm the derived key
   with HMAC-SHA256 tags over `client_static ‖ server_static ‖ A ‖ B`,
   client first, compared in constant time.
4. Only after the client's tag verifies does the server append the
   client's public line (`mysh-x25519 … paired <date>` or `ssh-ed25519 …`
   for an agent key) to `~/.config/mysh/authorized_keys` and send its own
   tag; only after that tag verifies does the client append the server key
   to `~/.config/mysh/known_hosts`. The server then reports both installed
   lines (`Done`); `mysh pair` prints both fingerprints and the lines
   (`--json`: `{host, server_fingerprint, client_fingerprint,
   authorized_line, host_line}`).

Properties:

- **single use**: the window closes on the first `Pair` attempt, success
  or failure; a wrong code therefore gives an attacker exactly one guess
  per code the operator prints (2048⁶ possibilities), and the operator
  sees the refusal in the log and the audit log (`denied`, `pair`);
- **expiry**: checked when the window is used, default 5 min;
- **channel binding**: the SPAKE2 identities and the confirmation
  transcript are the connection's static keys, so a man-in-the-middle who
  relays the exchange between two Noise sessions derives different keys on
  each side and both confirmations fail — nothing is written anywhere;
- **no identity leak beyond today's**: the client sends its static (or
  ed25519 proof) in message 3 to an unverified server exactly as a TOFU
  `--accept-new` connection does; the server learns the key but trusts it
  only after the PAKE;
- **nothing new for normal clients**: an open window changes nothing for a
  connection without `PAIR_REQUEST`, and a pairing-only connection can run
  no session, file or forward (`Denied`).

Threat notes: the code is the only secret, so it must travel over a
channel the attacker cannot read within the window (read it off the
server's terminal; do not paste it into a chat the attacker can see). A
server with a window open accepts one PAKE run from *anyone* who can reach
it; the rate limiter and the single-use rule bound this to one guess per
window. `--pair` lets `mysh serve` start with an empty `authorized_keys`
(the usual "no authorized client keys" refusal is waived), which is the
intended bootstrap on a fresh host.

## Audit log

`mysh serve --audit PATH` records what every client did, one JSON object
per line, appended to `PATH` (created `0600`, `O_APPEND`, flushed per
line; `-` writes to stderr). There is no rotation: use `logrotate`-style
copy-truncate or point the server at a new path on restart. The log is
written by one task on the server (`server/audit.rs`), independent of
`tracing` and `-v`, so its schema is stable:

```json
{"ts":"2026-11-02T10:41:07.512Z","peer":"192.0.2.9:51022","key":"SHA256:…","kind":"x25519",
 "direction":"inbound","event":"exec","detail":{"id":1,"pid":4242,"pty":false,"signal":null},
 "exit":0,"bytes_in":null,"bytes_out":null,"duration_ms":38}
```

| field         | value                                                                 |
| ------------- | --------------------------------------------------------------------- |
| `ts`          | RFC 3339 UTC with milliseconds, stamped when the line is written (so lines are in non-decreasing order) |
| `peer`        | client `ip:port`                                                      |
| `key`, `kind` | the client's key fingerprint (`SHA256:…`) and `x25519` / `ssh-ed25519`; `"?"` and `""` when a connection was refused before any key was offered |
| `direction`   | `inbound` (a listener accepted the client) or `outbound` (the server dialed the client: `--connect-back`); absent in logs written before this field existed, meaning `inbound` |
| `event`       | one of the kinds below                                                |
| `detail`      | event-specific object (always present)                                |
| `exit`        | exit code of an `exec` (null when killed by a signal — see `detail.signal`) |
| `bytes_in`, `bytes_out` | bytes from / to the client where known                      |
| `duration_ms` | how long the thing took where known                                   |

| event        | when                                                 | `detail`                                                                 |
| ------------ | ---------------------------------------------------- | ------------------------------------------------------------------------ |
| `connect`    | handshake done, key authorized (or pairing admitted) | `{version, pairing: bool}`                                               |
| `disconnect` | the connection ended                                 | `{}`; `bytes_in`/`bytes_out` are the whole connection's plaintext counters, `duration_ms` since the handshake |
| `session`    | a session's child was spawned (PTY shell or exec)    | `{id, pid, pty, program, argv, cwd}`                                     |
| `exec`       | a session's child exited while its client was attached | `{id, pid, pty, signal}` plus `exit`, `duration_ms` since the spawn. A session that exits while detached (persistence window, no reader) is reported when a client reattaches and sees it end; otherwise not at all |
| `file`       | a file op finished or failed after authorization     | `{op: stat\|list\|mkdir\|remove\|rename\|setattr\|realpath\|get\|hash\|put, path, to?, error?}`; `get` sets `bytes_out`, `put` `bytes_in` |
| `forward`    | `direct` (`-L`/`-D`) dial finished or failed, `listen` (`-R`) bound and later `closed: true`, `forwarded` (one accepted connection) relayed or refused | `{kind, host, port}` / `{kind, listener, host, port, closed?}` / `{kind, listener, peer, error?}` with the relayed bytes and duration |
| `pair`       | a pairing run (see "Pairing")                        | its outcome                                                              |
| `denied`     | something was refused                                | `{what: handshake\|session\|file\|forward\|pair, why}` — an unknown or address-restricted key, a feature switched off by `--deny` or the key's options, a bad pairing code |

The log is the server's view only: it never contains session output or
file contents, and the client cannot write to it. Every connection-level
line carries the authenticated key, so one `jq 'select(.key == "SHA256:…")'`
reconstructs a client's activity.

## Threat model

Protects against:

- passive and active network attackers: confidentiality, integrity, replay
  protection (AEAD nonces), forward secrecy per session;
- server impersonation (pinning / known_hosts / TOFU / pairing);
- unauthorized clients (authorization on the authenticated static key, or
  on the ed25519 key behind a verified handshake-bound signature);
- disclosure of client identity to unverified servers;
- offline guessing of a pairing code (SPAKE2: one online guess per window).

Does not protect against:

- compromised endpoints (a malicious server owns the session; a stolen
  client key or baked binary is full access);
- denial of service beyond basic limits (below);
- traffic analysis (no padding; frame sizes reveal interactive typing).

Limits and hardening:

- handshake must complete within 5 s; at most 64 concurrent handshakes per
  server, further connections are closed immediately;
- per-address handshake rate limit: a token bucket per client IP with
  capacity `--handshake-rate N` (default 10) refilled at `N` per minute,
  checked on accept before the handshake; an over-limit socket is dropped
  without a reply (the client sees EOF before the preamble) and logged at
  `warn` at most once per 10 s per address. Buckets idle for 10 min are
  forgotten. `--handshake-rate 0` disables the limiter;
- idle timeout: a connection whose control stream carries nothing for
  `--idle-timeout SECS` (default 120 s) is closed; the client's 30 s
  keep-alive pings reset it;
- Noise frames are capped at 65535 bytes by construction; control messages at
  256 KiB; open streams at 512 per connection (yamux `max_num_streams`,
  counting the control stream and every half-closed stream the local side
  still holds). The cap is enforced on both ends: an opener that exceeds it
  gets `TooManyStreams` and yamux closes that connection, so a client must
  stay under it. Remote listeners are capped at 32 per connection
  (`Rejected{Limit}`), sessions at 32;
- per-key options narrow the policy for one connection (above): `no-pty`,
  `no-files`, `no-forward`, `command=`, `from=`;
- the PTY child's environment is built from scratch: `HOME`, `USER`,
  `LOGNAME`, `PATH`, `SHELL`, `MYSH_CONNECTION`, plus client-supplied
  `TERM`, `LANG`, `LC_*`, `COLORTERM`. Other client variables require
  `--accept-env NAME` on the server; `MYSH_*` names are always set by the
  server (`MYSH_ORIGINAL_COMMAND` only under a forced command, and never
  taken from the client);
- feature switches on the server: `--deny pty|exec|files|forward-local|forward-remote`,
  repeatable;
- secrets are `zeroize`d on drop; key files are written `0600`, config dir
  `0700`; the server refuses a private key file that is group/world readable;
- logs contain fingerprints and addresses, never key bytes.

Rekeying within a session is in-band in the Noise layer (03-protocol.md
§3): each direction rotates its key after 1 GiB or 1 h, whichever first.
Not in v1, tracked in 06-roadmap.md: post-quantum hybrid KEX.
