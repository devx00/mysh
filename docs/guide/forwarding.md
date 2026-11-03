# Port forwarding

mysh tunnels TCP the way ssh does, with the same three flags and the same
spec grammar.

| flag | direction | what happens |
| --- | --- | --- |
| `-L [bind:]port:host:hostport` | local → remote | your machine listens; each connection is opened to `host:hostport` from the server |
| `-R [bind:]port:host:hostport` | remote → local | the server listens; each connection is opened to `host:hostport` from your machine |
| `-D [bind:]port` | local → remote | your machine serves SOCKS5 (CONNECT only) and the server opens whatever the client asked for |

All three are repeatable, and all three work both on the command line and at
the meta prompt.

`host:hostport` is resolved **by the side that dials**, so `-L
8080:localhost:80` means port 80 on the server's own loopback, and `-R
9000:localhost:3000` means port 3000 on yours.

The default bind address is `127.0.0.1`. Pass `*`, `0.0.0.0` or `::` as the
bind to accept connections from other machines — and be sure you mean it,
because v1 honours the bind you ask for without further restriction.

## Forwards without a session

```
$ mysh forward box -L 8080:127.0.0.1:80
forward 1: -L 8080:127.0.0.1:80
```

`mysh forward` is `mysh connect -N` with forwards: no session, no stdin
touched, just the tunnels. It runs until `Ctrl-C` or the connection drops.
`mysh -N HOST -L ...` is the same thing spelled with the flag, which is why
`-N` is safe to run with `&`.

`mysh forward` needs at least one of `-L`, `-R`, `-D`.

You can of course also pass forwards to a normal connection:

```
$ mysh box -L 8080:127.0.0.1:80 -D 1080
$ mysh -s box -R 9000:127.0.0.1:3000
```

## Forwards at runtime

The meta shell adds and removes them while the connection is up:

```
mysh box> forward -L 18080:127.0.0.1:18111
forward 1: -L 18080:127.0.0.1:18111
mysh box> forward -R 18090:127.0.0.1:18111
forward 2: -R 18090:127.0.0.1:18111
mysh box> forward -D 18099
forward 3: -D 18099
mysh box> forward ls
...
mysh box> forward rm 1
```

Ids are small integers, stable for the life of the connection. `forward ls`
and an add both produce `ForwardRow`s under `--json`:

```
$ mysh forward --json box -L 18081:127.0.0.1:18111
[{"id":4,"kind":"local","bind":"127.0.0.1:18081","target":"127.0.0.1:18111","accepted":0}]
```

`accepted` counts connections that have come through.

If an interactive client for that host is already running (or a
[master](automation.md#masters) is), `mysh forward HOST -L ...` from another
terminal adds the forward to *that* connection and returns immediately,
rather than making a second one.

## Examples

**Reach a service's web UI that only listens on the server's loopback.**

```
$ mysh forward box -L 8080:127.0.0.1:80
```

Then open `http://127.0.0.1:8080/` locally. Nothing on the server has to
change, and the service keeps listening only on loopback.

**Expose a local development server to the remote host.**

```
$ mysh forward box -R 9000:127.0.0.1:3000
```

Now `curl http://127.0.0.1:9000/` *on the server* hits the app running on
your laptop's port 3000 — useful for letting a remote build or webhook talk
back to you without opening a port on your own network.

**Browse through the host.**

```
$ mysh forward box -D 1080
$ curl --socks5-hostname 127.0.0.1:1080 http://10.0.0.5/
```

Point a browser's SOCKS5 proxy at `127.0.0.1:1080` and every connection is
dialled from the server. Use `--socks5-hostname` (not `--socks5`) so names
are resolved remotely too. Only CONNECT is implemented — no UDP, no BIND.

**Reach a third machine through this one.** The dialled host does not have to
be the server itself:

```
$ mysh forward lab -L 5432:db.internal:5432
```

## When the server says no

A server can switch forwarding off:

| server flag | effect |
| --- | --- |
| `--deny forward-local` | refuses the outbound connections `-L` and `-D` need |
| `--deny forward-remote` | refuses the remote listener `-R` needs |

`--deny forward-remote` fails at setup time, with the `denied` code:

```
$ mysh forward --json box -R 18201:127.0.0.1:18111
{"error":{"code":"denied","message":"-R 127.0.0.1:18201: remote listen 127.0.0.1:18201: denied by server policy: remote forwarding is disabled by server policy"}}
```

`--deny forward-local` cannot fail at setup, because the listener is on
*your* machine. It starts fine, and each attempted connection is refused:

```
$ mysh forward box -L 18200:127.0.0.1:18111
[mysh] forward 1: 127.0.0.1:18111: denied by server policy: local forwarding is disabled by server policy
```

An individual authorized key can also carry a `no-forward` option, which
denies that key the same two things regardless of the server's flags. Check
what applies to you with `info`, whose server block lists `denied`
features. See [keys-and-trust](keys-and-trust.md) for per-key options and
[server](server.md) for the flags.

## Behaviour notes

- Errors are reported once per connection, on stderr, or in the meta shell
  if one is open. A failed connection does not disturb the forward or any
  other connection through it.
- Half-close is propagated in both directions, so protocols that shut down
  one direction and keep reading work.
- The server's quota on listeners (`max_listeners`, 32 by default) bounds how
  many `-R` forwards one connection can hold; `info` shows the limits.

Design details are in [docs/04-sessions.md](../04-sessions.md) under "Port
forwarding".
