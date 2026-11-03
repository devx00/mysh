# Keys and trust

Every mysh connection authenticates both ends with long-term keys: the server proves it is the host you meant, the client proves it is a key the server trusts. There are no passwords, no certificates and no negotiation. This page covers where keys come from, how the server decides whom to let in, how the client decides whether to talk, and the two ways to get the first keys across (copying a line, or pairing with a code). The design and the cryptography are in [02-security.md](../02-security.md).

## Identities

An *identity* is a private key the client or server uses in the handshake. mysh accepts four kinds.

### Native key files

`mysh keygen` writes an X25519 key pair as two one-line text files:

```
mysh keygen -o ~/.config/mysh/id -C "you@laptop"
```

| file | contents | mode |
| --- | --- | --- |
| `id` | `mysh-x25519-secret <base64>` | 0600 |
| `id.pub` | `mysh-x25519 <base64> you@laptop` | 0644 |

The `.pub` line is also the entry format for `authorized_keys` and `known_hosts`. Without `-o` the key goes to `~/.config/mysh/id`.

### OpenSSH ed25519 keys

Anywhere a mysh key is accepted, an OpenSSH ed25519 key is accepted too:

- private key files (`~/.ssh/id_ed25519`, `/etc/ssh/ssh_host_ed25519_key`), including passphrase-protected ones (you are prompted for the passphrase);
- public `ssh-ed25519 AAAA… comment` lines in `authorized_keys`, `known_hosts` (plain or `|1|`-hashed) and as `--pin` values.

The key is converted to X25519 internally (the same mapping `age` uses). mysh never signs with a key it loaded from a file. `ssh-rsa`, `ecdsa-*` and `sk-*` (FIDO) keys are not supported.

### ssh-agent keys

A key held by `ssh-agent` (including hardware-backed ones) cannot be read, so the client proves it instead by asking the agent for a signature bound to this one handshake. From the outside it works like any other key: the server authorizes the `ssh-ed25519` key against its `authorized_keys`, and `authorize` installs an `ssh-ed25519` line for it.

- Without `-i`, the client tries its key file first, then up to five ed25519 keys from `$SSH_AUTH_SOCK` in the agent's order. A key is only skipped when the server says *unauthorized*; any other failure stops the attempt. Each key tried is one TCP connection and one handshake, which counts against the server's [handshake rate limit](troubleshooting.md#connection-reset-after-a-burst-of-calls).
- `-i ~/.ssh/id_ed25519.pub` (a `.pub` file, or any file whose first line is `ssh-ed25519 …`) names one agent key and uses only that; it is an error if the agent does not hold it.
- Fingerprints of agent keys are the OpenSSH ones (`ssh-add -l`).
- The server must allow it: `serve --no-signature-auth` turns it off, and a client that only has agent keys then stops before sending anything identifying.

### Baked keys

A binary can carry its identity and its trusted peers compiled in, so a fleet of devices needs no key files at all:

```
mysh keygen -o fleet
MYSH_BAKED_IDENTITY=fleet MYSH_BAKED_PEERS=fleet.pub cargo build --release -p mysh --features baked
```

`MYSH_BAKED_IDENTITY` is a private key file (native or OpenSSH), `MYSH_BAKED_PEERS` an `authorized_keys`-format file. Both apply to both roles: the baked identity is the default identity for `serve` and for connecting, and the baked peers are trusted as clients (when serving) and as servers (when connecting). The example above makes a self-trusting set: any device running that binary can serve and connect to any other. Two builds with different inputs give asymmetric trust.

Files on disk still *extend* the baked set, so an admin's personal key in `authorized_keys` works alongside the baked one. `--baked-only` (both roles) ignores every file on disk, including the agent.

The binary is a credential: whoever has it has the key. Rotate by rebuilding; do not commit the inputs.

### Resolution order

First match wins.

| role | order |
| --- | --- |
| client | `-i PATH` → `$MYSH_IDENTITY` → baked → `~/.config/mysh/id` → `~/.ssh/id_ed25519` → ed25519 keys from `$SSH_AUTH_SOCK` |
| server | `--key PATH` → `$MYSH_HOST_KEY` → baked → `~/.config/mysh/host_key` (generated 0600 on first `serve`; `--no-generate-key` fails instead) |

`-i` is exclusive: when given, nothing else is tried. The `info` command at the prompt shows which identity was accepted (`our key: x25519 SHA256:… (/home/you/.config/mysh/id)` or `ssh-ed25519 SHA256:… (agent: comment)`).

`serve --key /etc/ssh/ssh_host_ed25519_key` makes the server present the same identity as `sshd`, which means clients that already have the host in `~/.ssh/known_hosts` verify it with no new trust step.

## Server trust: who may connect

The server's trusted set is the union of:

1. baked peers;
2. `~/.config/mysh/authorized_keys` (`mysh-x25519` and `ssh-ed25519` lines);
3. `~/.ssh/authorized_keys`, `ssh-ed25519` entries only (skip with `--no-ssh-authorized-keys`);
4. `--authorized-key LINE` and `--authorized-keys PATH`, both repeatable.

Files are re-read on every connection, so editing `authorized_keys` takes effect immediately with no reload. Lines of unsupported key types are skipped with a warning. A server whose set is empty refuses to start (`no authorized client keys: add one to … or pass --authorized-key`) unless `--pair` is given.

An unauthorized client is told so as the first message after the handshake and disconnected; the server logs the fingerprint at `warn` and, with `--audit`, writes a `denied` line:

```
mysh: error: server refused our key x25519 SHA256:gsjr… (/home/you/.config/mysh/id): key not authorized
```

### Per-key options

An `authorized_keys` line may start with OpenSSH-style options, comma-separated, values in double quotes:

```
command="/usr/local/bin/backup",no-pty,no-forward mysh-x25519 W9ge… backup-runner
from="10.0.0.0/8,!10.0.0.13" ssh-ed25519 AAAA… ops@lab
restrict,files mysh-x25519 ogW7… file-drop
```

| option | effect |
| --- | --- |
| `command="…"` | forced command: every session runs this through the shell; what the client asked for is passed in `MYSH_ORIGINAL_COMMAND` (empty for a `shell`). A PTY is still allocated if requested |
| `no-pty` | no PTY sessions (`shell`, `-t`); exec sessions still work |
| `no-files` | no file transfer (`put`, `get`, `cat`, `sync`, …, and `authorize`); mysh-specific |
| `no-forward` | no local, dynamic or remote forwards; `no-port-forwarding` is accepted as an alias |
| `from="pat,…"` | only from these source addresses (below) |
| `restrict` | `no-pty,no-files,no-forward`; a later `pty`, `files` or `port-forwarding` re-enables that one |

Options only ever narrow what `serve --deny` already allows. Unknown OpenSSH options (`environment=`, `permitopen=`, …) are ignored; a malformed option list (unterminated quote, `command` without a value) skips the whole line with a warning, so a typo never widens access.

`from=` matches the peer's IP address, never a reverse-DNS name. A pattern is an exact address (`192.0.2.7`, `::1`), a CIDR block (`10.0.0.0/8`, `fd00::/8`, same address family only) or a glob over the text (`192.168.1.*`). `!` negates: if any negated pattern matches the connection is refused, otherwise at least one positive pattern must match. A refused source looks exactly like an unknown key to the client.

## Client trust: is this the right server

After the second handshake message the client knows the server's key and checks it, in order:

1. `--pin KEY` (fingerprint or public key line), also `pin = "…"` in a [config alias](config.md#hostsname);
2. baked peers;
3. `~/.config/mysh/known_hosts`: `host:port mysh-x25519 <b64>` or `host:port ssh-ed25519 <b64>` lines; a `host:port` entry matches before a bare `host` entry;
4. `~/.ssh/known_hosts`, `ssh-ed25519` entries for `host` or `[host]:port`, plain or hashed;
5. otherwise the key is *unknown*: with a terminal the client asks (TOFU) and appends the answer to `~/.config/mysh/known_hosts`; `--accept-new` answers yes silently; `--strict`, or no terminal, fails with `trust_unknown`.

```
The authenticity of host box:7722 can't be established.
Fingerprint SHA256:I1JTosiEZOcK6moI+X7CAIuAYfU0CaHliYezhlCYDwk
Are you sure you want to continue connecting (yes/no)?
```

Compare that fingerprint with what `mysh serve -v` printed (`host identity fingerprint=…`) or with `mysh fingerprint ~/.config/mysh/host_key` run on the server. `accept_new = true` under `[defaults]` in `config.toml` makes `--accept-new` the default everywhere.

### When the key changes

A key that differs from any known entry or from `--pin` is fatal:

```
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@    WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!     @
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
The key presented by box:7722 does not match the one recorded in
/home/you/.config/mysh/known_hosts, line 1
expected: SHA256:6gIa…
actual:   SHA256:I1JT…
Someone could be eavesdropping on you right now, or the server's key was
replaced. There is no bypass flag: if the change is legitimate, remove or
fix that entry and connect again.
```

There is deliberately no `--no-host-checking`: the client never sends its own identity to a server it has not verified, so the only way past this message is to edit the named file and line (or correct the pin). The exit code is 2 and the JSON error code is `trust_mismatch`.

## Pairing

Pairing installs both keys at once from a short code, for first contact when neither side can easily copy a file to the other.

On the server, `mysh serve --pair` (or `--pair 10m`; default 5 minutes) prints to stderr:

```
pairing code: apple-bread-cat-dog-eagle-fish (valid 5m, single use)
```

`SIGUSR1` to a running server opens a fresh 5-minute window at any time, replacing any open one, and prints the new code. `--pair` also lets the server start with an empty `authorized_keys`, which is the intended bootstrap on a fresh host.

On the client, `mysh pair box apple bread cat dog eagle fish` (hyphens or spaces, any case). The client:

1. connects with its normal identity and accepts the server key *provisionally*, writing nothing yet;
2. runs a password-authenticated key exchange (SPAKE2) over the code, bound to the two keys of this very connection, so a relay in the middle derives different results on each side and both halves fail;
3. only after both confirmations verify, the server appends the client's line to its `authorized_keys` (`mysh-x25519 … paired <date>`, or `ssh-ed25519 …` for an agent key) and the client appends the server's line to its `known_hosts`.

What travels: the client's public key (the server learns it before trusting it, exactly as with `--accept-new`), the SPAKE2 messages and two confirmation tags. The code itself never leaves the terminals; it is the only secret, so read it off the server's screen rather than pasting it somewhere an attacker could see within the window.

| property | meaning |
| --- | --- |
| single use | the window closes on the first attempt, right or wrong; a wrong code is one guess per code the operator printed (6 words from a 2048-word list) |
| expiry | checked when the window is used; default 5 minutes |
| no side effects on failure | a bad code, an expired window or a relay attack writes nothing on either side |
| invisible to others | an open window changes nothing for ordinary clients; a pairing connection can run no session, file or forward |

On failure the client exits 2:

```
mysh: error: server did not know the code (bad code)
mysh: error: server has no pairing window open (unauthorized: key not authorized); run `mysh serve --pair` or send it SIGUSR1
```

`mysh pair --json` prints `{host, server_fingerprint, client_fingerprint, authorized_line, host_line}`.

## Fingerprints

A fingerprint is `SHA256:` followed by the unpadded base64 of the SHA-256 of the raw 32-byte public key, the same shape as OpenSSH's. It identifies a key in logs, prompts, `--pin`, the audit log and the `info` command.

```
mysh fingerprint ~/.config/mysh/id.pub       # public or private, native or OpenSSH
mysh fingerprint ~/.config/mysh/host_key
cat ~/.ssh/id_ed25519.pub | mysh fingerprint -
```

```
SHA256:6gIaFXtDcamPupzTf4VYouZGpo4JGabwg75BzbOFs/8
```

Logs contain fingerprints and addresses, never key bytes.
