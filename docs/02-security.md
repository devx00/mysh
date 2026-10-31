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
KEM*, IACR ePrint 2021/509). mysh never signs with the key.

**Not supported:** `ssh-rsa`, `ecdsa-*`, `sk-*` (FIDO), and `ssh-agent`.
Agent keys only sign; they cannot do DH. Supporting them means a different
authentication method (ephemeral-only Noise `NN` plus an ed25519 signature
over the handshake hash, TLS-1.3 style). That is a clean addition later — an
`Auth` message after the handshake with a method enum — and is tracked in
06-roadmap.md. v1 chooses the single-mechanism design.

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
| client | `-i PATH` → `$MYSH_IDENTITY` → baked → `~/.config/mysh/id` → `~/.ssh/id_ed25519`           |
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
remote static. An unauthorized client receives
`Verdict::Denied { code: Unauthorized }` as the first transport message and
the connection is closed; the fingerprint is logged at `warn`. Authorization
precedes every service: no stream is accepted from an unauthenticated peer.

Per-key options (`command=`, `no-forward`, `from=`) are not in v1
(06-roadmap.md).

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

## Threat model

Protects against:

- passive and active network attackers: confidentiality, integrity, replay
  protection (AEAD nonces), forward secrecy per session;
- server impersonation (pinning / known_hosts / TOFU);
- unauthorized clients (authorization on the authenticated static key);
- disclosure of client identity to unverified servers.

Does not protect against:

- compromised endpoints (a malicious server owns the session; a stolen
  client key or baked binary is full access);
- denial of service beyond basic limits (below);
- traffic analysis (no padding; frame sizes reveal interactive typing).

Limits and hardening in v1:

- handshake must complete within 5 s; at most 64 concurrent handshakes per
  server, further connections are closed immediately;
- Noise frames are capped at 65535 bytes by construction; control messages at
  256 KiB; open streams at 512 per connection;
- the PTY child's environment is built from scratch: `HOME`, `USER`,
  `LOGNAME`, `PATH`, `SHELL`, `MYSH_CONNECTION`, plus client-supplied
  `TERM`, `LANG`, `LC_*`, `COLORTERM`. Other client variables require
  `--accept-env NAME` on the server;
- feature switches on the server: `--deny pty|exec|files|forward-local|forward-remote`,
  repeatable;
- secrets are `zeroize`d on drop; key files are written `0600`, config dir
  `0700`; the server refuses a private key file that is group/world readable;
- logs contain fingerprints and addresses, never key bytes.

Not in v1, tracked in 06-roadmap.md: rekeying within a session (ChaChaPoly
nonce space is 2^64 messages; sessions are far shorter), per-IP handshake
rate limiting, per-key options, post-quantum hybrid KEX.
