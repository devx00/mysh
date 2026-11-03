# Troubleshooting

Most failures are one of a dozen named conditions. The client prints `mysh: error: <message>` on stderr and exits 2 for anything that stops a connection (trust, authorization, connect, usage), 1 for a command or file operation that failed, 124 after `--timeout`, and 255 when a live connection drops. With `--json` the same failure is one line on stderr, `{"error":{"code":"…","message":"…"}}`; the code is stable, the message is for humans.

## Error codes

| code | typical message | cause | fix |
| --- | --- | --- | --- |
| `trust_unknown` | `host key verification failed: box:7722 is not in known_hosts (key SHA256:…); use --accept-new or add it to …/known_hosts` or `server key SHA256:… is not known (--strict)` | first contact and the client cannot ask: stdin is not a terminal (script, cron, `--json`), or `--strict` | compare the fingerprint with the server's (`mysh serve -v` prints it; `mysh fingerprint host_key` on the server), then `--accept-new` once, or `--pin SHA256:…`, or add the line to `known_hosts`, or pair |
| `trust_mismatch` | `WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED! … recorded in …/known_hosts, line N` (or `pin, line 0`) | the server's key differs from the recorded one or from `--pin`: the host was reinstalled, the host key file was lost, another machine answers at that address, or a man-in-the-middle | there is no bypass flag. Confirm out of band why the key changed; if legitimate, delete that line of `known_hosts` (or fix the pin/alias) and connect again, which asks TOFU afresh. See [keys and trust](keys-and-trust.md#when-the-key-changes) |
| `unauthorized` | `server refused our key x25519 SHA256:… (/home/you/.config/mysh/id): key not authorized` | the server does not trust the identity that was presented; also a `from=` restriction, or an agent key against `--no-signature-auth` | install the key on the server: `mysh authorize box ~/.config/mysh/id.pub` from an identity that works, or append `id.pub` to the server's `authorized_keys`, or pair. Check *which* identity was used: the message names it; `-i` forces one |
| `connect_failed` | `box:7722: Connection refused`, `resolving box: …`, `handshake with box:7722 failed: … Connection reset by peer`, a 5 s handshake timeout | no server on that host:port, DNS failed, a firewall, or the rate limiter dropped the connection (below) | check `--listen` on the server and the port on the client (`HOST:PORT`, `-p`, alias `port`); for resets after a burst of calls see the next section |
| `denied` | `get /etc/hosts: denied by server policy: file transfer is disabled by server policy`, `pty sessions are disabled`, `exec sessions are disabled` | the server started with `--deny FEATURE`, or your key's `authorized_keys` line carries `no-pty`, `no-files`, `no-forward` or `restrict` | the `info` command at the prompt lists `denied: …`; change the server flags or the key's options. `authorize` needs `files` |
| `limit` | `at most 32 sessions per connection`, `at most 32 remote listeners per connection`, `attached by another connection` | a per-connection quota (32 sessions, 32 remote listeners, 512 open streams), or the session you want to attach is attached elsewhere | close sessions or forwards you no longer need, or spread work over several connections; `detach` the session in the other client first |
| `timeout` | `[mysh] timed out` | `--timeout D` expired: the command got `TERM`, then `KILL` 2 s later (exit 124); for `put`/`get` the whole transfer was bounded | raise or drop `--timeout`; for long-running commands use `session new` instead of waiting ([automation](automation.md)) |
| `usage` | clap's usage text, `no hosts: give --hosts a,b,… or --group NAME`, `no [groups.NAME] in the config file`, a TOML error naming the key | a bad flag, a missing `HOST`, an unknown key in `config.toml`, a bad `HOST` or forward spec | `mysh help CMD`; note that per-command flags go *after* the subcommand (`mysh cat --json box f`, not `mysh --json cat box f`, which treats `cat` as the host) |
| `not_found` | `no such session 7`, `PATH: no such file` | the remote path, session id or forward does not exist | `mysh stat box PATH`, `sessions -a`, `session list` |
| `unsupported` | `the server does not support agent keys (signature authentication is disabled), use a key file`, `session persistence is not enabled`, `unknown stream kind` | the server has the feature off (`--no-signature-auth`, `--detach-grace 0`) or is an older build | use a key file (`-i`), change the server flag, or update the server |
| `io` | `Connection reset by peer`, `connect timed out` (forwards) | the connection went away mid-command, a forward target did not answer, or a server-side I/O error | reconnect; detached PTY sessions can be resumed with `--attach` |
| `protocol` | a malformed or out-of-order message | a version or implementation mismatch | make sure both ends run the same `mysh --version` |

## Connection reset after a burst of calls

Symptom: a loop of `mysh box CMD` calls works about ten times, then:

```
mysh: error: handshake with box:7722 failed: i/o: Connection reset by peer (os error 54)
```

and the server (with `-v` or not — it is a warning) logs `WARN handshake rate limit peer=…`. The server allows `--handshake-rate` handshakes per minute per client address (default 10) and drops anything beyond that without a reply. Failed attempts count too: a run of `trust_unknown` or `unauthorized` errors, or a client trying several agent keys in turn, spends the budget as fast as successful calls.

Fix it on the client by not handshaking per call: run `mysh master box` (or `mysh box --master auto`, or `master = "auto"` in `config.toml`) and subsequent commands reuse that connection through the control socket; an interactive `mysh box` in another terminal serves the same purpose. See [automation](automation.md). For a host that legitimately takes many fresh connections from one address, raise `--handshake-rate` or set it to `0`.

## "server refused our key"

```
mysh: error: server refused our key x25519 SHA256:gsjr… (/home/you/other): key not authorized
```

The server completed the handshake, looked the key up and found nothing. The fingerprint and path in the message tell you which identity was tried; the server side logs `WARN unauthorized client key peer=… client=x25519 SHA256:…` and writes a `denied` audit line. Check, in order:

1. Is that the key you meant? `mysh fingerprint ~/.config/mysh/id.pub`; the [resolution order](keys-and-trust.md#resolution-order) explains why `~/.ssh/id_ed25519` or an agent key may have been chosen. `-i PATH` removes the doubt.
2. Is it in a file the server reads? `~/.config/mysh/authorized_keys` under the *serving* user's home, or `~/.ssh/authorized_keys` unless `--no-ssh-authorized-keys`. A server under systemd with `MYSH_CONFIG_DIR` set reads that directory, not `/root/.config/mysh`. Files are re-read per connection, no restart needed.
3. Was the line parsed? `mysh serve -v` warns about skipped entries (unsupported key type, malformed options). A `from=` pattern that does not match your source address is also reported as *not authorized*.
4. Agent key and `server does not support agent keys`: the server runs `--no-signature-auth`; use a key file.

## Terminal left in a bad state

After a full-screen program (an editor, `top`, `tmux`) exits abnormally, or a connection drops in the middle of one, your local terminal may stop echoing, ignore Enter, or show garbage. mysh restores the terminal mode it changed, but it cannot undo what the remote program sent. Type

```
reset
```

(blind, then Enter) in the local shell. `stty sane` is the lighter alternative. The same applies after `--attach` of a session that was in a full-screen program when it was detached: no screen state is replayed, so press `Ctrl-L` in the program to redraw.

## Seeing more

| what | how |
| --- | --- |
| client log, connection events | `mysh -v box …` (`info`: connect, trust source, sessions) |
| client handshake and stream detail | `mysh -vv box …` (`debug`, with module targets) |
| everything | `-vvv`, or `RUST_LOG=trace mysh …`; `RUST_LOG` takes precedence over `-v` and accepts `tracing` directives such as `RUST_LOG=mysh_net=debug,mysh=info` |
| server log | the same flags on `mysh serve`; warnings (unauthorized keys, rate limit, skipped `authorized_keys` lines, pairing failures) appear without `-v`. Under a service manager: `journalctl -u mysh`, `/tmp/mysh.log` (launchd plist), `~/.config/mysh/serve.log` (Termux) |
| what the server actually did | `mysh serve --audit PATH` (`-` for stderr): one JSON line per connect, session, exec, file op, forward, pairing and refusal, each with the client's fingerprint. Format in [server](server.md#audit-log) |
| what the client thinks | `info` at the prompt: server name, protocol version, both keys and where the server's was trusted from, cipher, traffic counters, sessions, forwards, the remote's shell, home, idle timeout, detach grace and denied features |
| structured errors for scripts | `--json`: the error code table above on stderr, exit codes unchanged |

Logs are written to stderr and never contain key material, only fingerprints and addresses. The pairing code, too, is printed on stderr: when a server runs detached, that is where to look for it.
