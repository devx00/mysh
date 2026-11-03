# Connect-back

Normally a client dials a server. With connect-back the **server opens the
TCP connection** to a client that is waiting for it, and after that nothing
is different: the server still authorizes the client's key, the client still
checks the server's key, sessions and files and forwards work as always. Use
it for a server with no inbound connectivity — behind NAT, on a mobile
network, or anywhere you would rather not open a port.

The two ends:

| end | command | trust it applies |
| --- | --- | --- |
| the server | `mysh serve --connect-back HOST[:PORT]` | the client's key must be in its `authorized_keys`, as always |
| the client | `mysh accept [ADDR]` | the server's **host key** must be in `~/.config/mysh/callers`, keyed by fingerprint — never by address |

## Server side

```sh
mysh serve --connect-back lab.example:7722 \
           --connect-period 5m --connect-jitter 10 --connect-max 30m \
           --authorized-key 'mysh-x25519 AAAA… operator'
```

| option | default | meaning |
| --- | --- | --- |
| `--connect-back ADDR` (repeatable) | — | dial this client; one independent loop per address |
| `--connect-period D` | `5m` | time from the start of one attempt to the start of the next |
| `--connect-jitter PERCENT` | `10` | random ± on the period, so many servers with the same period do not dial at once |
| `--connect-max D` | `30m` | a connection held longer than this is closed by the server with a `Shutdown` notice |
| `--allow-bind-request` | off | let the client ask this server to open a normal listener (see "Bind on request") |

With only `--connect-back`, nothing is bound: the server has no listening
port at all. Add `--listen` to have both.

The loop for one address is strictly sequential: dial → serve the
connection until *either side* closes it → sleep until `period` from the
start of the attempt → dial again. A server **never has two connections to
the same address open**, and never re-dials while one is open; there is no
runaway. Dial or handshake failures back off (5 s, doubling, capped at the
period) and are logged once at `warn`, then at `debug`.

`contrib/mysh-connect-back.service` is a systemd unit for this mode. Audit
lines (`--audit`) carry `"direction": "outbound"` for these connections.

## Client side

Put each server's **host key** (what `serve` presents: `host_key.pub` in its
config dir, or `mysh fingerprint host_key`) into `~/.config/mysh/callers`.
It is `authorized_keys` line format, and the comment is the name you will
address the connection by:

```
mysh-x25519 Lk…c= host-a
mysh-x25519 7N…k= host-b
```

Then accept:

```sh
mysh accept 0.0.0.0:7722 --json
{"event":"notice","text":"accepting connections on 0.0.0.0:7722 (callers: /home/me/.config/mysh/callers)"}
{"event":"accepted","name":"host-b","fingerprint":"SHA256:O6Ce…","addr":"203.0.113.9:51234","server":{"name":"host-b","version":"0.1.0"}}
{"event":"accepted","name":"host-a","fingerprint":"SHA256:7NmX…","addr":"198.51.100.4:40022","server":{"name":"host-a","version":"0.1.0"}}
```

| option | meaning |
| --- | --- |
| `ADDR` | `host:port` or a bare `PORT`; default `[::]:7722` |
| `--callers PATH` | another callers file |
| `--accept-new` | record an unknown server key in the callers file (unnamed: addressed by the first twelve characters of its fingerprint) instead of refusing it |
| `--handshakes-per-minute N` | per-address limit on inbound handshakes (default 30, 0 = off) |
| `--json` | events as NDJSON: `accepted`, `closed`, `refused` |

An unknown key is refused *before* the client reveals its own key, so
anything that port-scans the accepting port learns nothing. Without
`--accept-new` and with an empty callers file, `accept` refuses to start.

## Working with accepted connections

`mysh accept` holds every accepted connection open and serves a control
socket for each one (`$XDG_RUNTIME_DIR/mysh/@NAME.sock`). Every command that
takes a `HOST` takes `@NAME` instead, and goes through that socket:

```sh
mysh --json @host-a 'cat /var/lib/app/state'
mysh put @host-a job.tar.gz '~/inbox/'
mysh session @host-a new -- ./run-job
mysh session @host-a read 1 --since 0 --wait 10s
mysh run --json --hosts @host-a,@host-b -- 'uptime'
```

`@NAME` never dials: with no accepted connection of that name the call fails
with `connect_failed` (`no accepted connection named NAME`). Nothing else
changes — JSON shapes, exit codes, the session API, `sync`, forwards.

The server keeps the connection until you end it. Ending it is `mysh
accept` exiting (`SIGTERM`/`Ctrl-C`: every connection is closed cleanly and
each server goes back to its period) or, from a program, closing the
`Client` (see below). `--connect-max` on the server is the safety net if
the client never does.

## Bind on request

Sometimes you want to open a connecting-back server for ordinary dials for a
while — to let a colleague in, or to run something that needs its own
connection. If the server runs with `--allow-bind-request`:

```sh
mysh bind @host-b 0.0.0.0:7722 --for 1h --json
{"bound":"0.0.0.0:7722"}
mysh 203.0.113.9 'echo dialed-ok'      # a normal dial, now possible
mysh bind @host-b off --json
{"ok":true}
```

The listener closes after `--for` without a connection, on `bind off`, or
when the server exits. Without the server flag the request fails with
`denied`. `bind` also exists at the prompt of an accepted connection.

## From a program

The same thing with `mysh-client`:

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
    let out = inbound.client.exec(ExecRequest::argv(["uptime"])).await?;
    print!("{}", String::from_utf8_lossy(out.stdout.as_bytes()));
    inbound.client.close().await;   // the server goes back to its period
}
```

`next()` yields connections in arrival order; handshakes run concurrently
so a slow peer never blocks the others. Each `Inbound` carries a full
`Client` — sessions, files, forwards, `bind` — that cannot `reconnect`
(the server owns the schedule). Details and the `Reporter` events are in
[library](library.md) and `docs/07-embedding.md`.
