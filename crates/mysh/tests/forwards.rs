//! Port forwarding (docs/04-sessions.md "Port forwarding", docs/06-roadmap.md
//! M3): `-L`, `-R`, `-D` through the library API against an in-process
//! server, with a loopback echo service as the target.

mod common;

use std::{net::SocketAddr, sync::Arc, time::Duration};

use common::{ServerOpts, TestServer};
use mysh::{
    cli::{ConnectOpts, Feature},
    client::{conn::Connection, console::Console, forward::Forwards},
    config::ForwardSpec,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    task::JoinHandle,
    time::timeout,
};

/// Deterministic pseudo-random bytes (xorshift64*).
fn random_bytes(len: usize, seed: u64) -> Vec<u8> {
    let mut x = seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1;
    let mut out = Vec::with_capacity(len);
    while out.len() < len {
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        let bytes = x.wrapping_mul(0x2545_F491_4F6C_DD1D).to_le_bytes();
        let take = bytes.len().min(len - out.len());
        out.extend_from_slice(&bytes[..take]);
    }
    out
}

/// Echo server on loopback: every accepted connection is copied back to
/// itself and the write half is shut down once the peer half-closes, so EOF
/// propagates.
struct Echo {
    addr: SocketAddr,
    task: JoinHandle<()>,
}

impl Echo {
    async fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind echo");
        let addr = listener.local_addr().expect("echo addr");
        let task = tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    break;
                };
                tokio::spawn(async move {
                    let (mut rd, mut wr) = stream.into_split();
                    let _ = tokio::io::copy(&mut rd, &mut wr).await;
                    let _ = wr.shutdown().await;
                });
            }
        });
        Self { addr, task }
    }

    fn port(&self) -> u16 {
        self.addr.port()
    }
}

impl Drop for Echo {
    fn drop(&mut self) {
        self.task.abort();
    }
}

struct Ctx {
    server: TestServer,
    conn: Connection,
    forwards: Forwards,
    echo: Echo,
}

async fn setup(opts: ServerOpts) -> Ctx {
    let server = common::start_server(opts).await;
    let conn = server
        .connect(ConnectOpts::default())
        .await
        .expect("connect");
    let forwards = Forwards::new(conn.clone(), Arc::new(Console::new()));
    let echo = Echo::start().await;
    Ctx {
        server,
        conn,
        forwards,
        echo,
    }
}

impl Ctx {
    fn echo_spec(&self) -> ForwardSpec {
        ForwardSpec::parse_local(&format!("127.0.0.1:0:127.0.0.1:{}", self.echo.port()))
            .expect("parse -L spec")
    }

    fn bind_of(&self, id: u32) -> SocketAddr {
        self.forwards
            .list()
            .into_iter()
            .find(|f| f.id == id)
            .unwrap_or_else(|| panic!("forward {id} listed"))
            .bind
    }

    async fn finish(self) {
        self.forwards.shutdown().await;
        self.conn.close().await;
        self.server.stop().await;
    }
}

const IO_TIMEOUT: Duration = Duration::from_secs(5);

/// Write `data`, half-close, read until EOF; the echo must return `data`
/// exactly and then EOF.
async fn echo_round_trip(stream: &mut TcpStream, data: &[u8]) {
    let (mut rd, mut wr) = stream.split();
    let write = async {
        wr.write_all(data).await.expect("write");
        wr.shutdown().await.expect("shutdown write half");
    };
    let read = async {
        let mut got = Vec::with_capacity(data.len());
        rd.read_to_end(&mut got).await.expect("read to EOF");
        got
    };
    let ((), got) = timeout(IO_TIMEOUT, async { tokio::join!(write, read) })
        .await
        .expect("echo round trip timed out");
    assert_eq!(got.len(), data.len(), "echoed length");
    assert!(got == data, "echoed content");
}

#[tokio::test]
async fn local_forward_echo_and_half_close() {
    let ctx = setup(ServerOpts::default()).await;
    let id = ctx
        .forwards
        .add_local(&ctx.echo_spec())
        .await
        .expect("add_local");
    let bind = ctx.bind_of(id);
    assert_ne!(bind.port(), 0, "port 0 resolved to the bound port");
    let listed = &ctx.forwards.list()[0];
    assert_eq!(listed.id, id);
    assert_eq!(
        listed.target,
        Some(("127.0.0.1".to_owned(), ctx.echo.port()))
    );

    let data = random_bytes(1 << 20, 1);
    let mut stream = TcpStream::connect(bind).await.expect("connect -L");
    echo_round_trip(&mut stream, &data).await;
    assert_eq!(ctx.bind_of(id), bind);
    assert_eq!(ctx.forwards.list()[0].accepted, 1);
    ctx.finish().await;
}

#[tokio::test]
async fn remote_forward_echo() {
    let ctx = setup(ServerOpts::default()).await;
    let id = ctx
        .forwards
        .add_remote(&ctx.echo_spec())
        .await
        .expect("add_remote");
    let bind = ctx.bind_of(id);
    assert_ne!(bind.port(), 0, "Bound.port filled in");

    let data = random_bytes(100 * 1024, 2);
    let mut stream = TcpStream::connect(bind).await.expect("connect -R");
    echo_round_trip(&mut stream, &data).await;
    ctx.finish().await;
}

/// `DST.ADDR` bytes for a SOCKS5 request.
enum Dst<'a> {
    Domain(&'a str),
    V4([u8; 4]),
}

async fn socks_handshake(bind: SocketAddr) -> TcpStream {
    let mut stream = TcpStream::connect(bind).await.expect("connect -D");
    stream.write_all(&[5, 1, 0]).await.expect("greeting");
    let mut reply = [0u8; 2];
    timeout(IO_TIMEOUT, stream.read_exact(&mut reply))
        .await
        .expect("greeting reply timeout")
        .expect("greeting reply");
    assert_eq!(reply, [5, 0], "no-auth method selected");
    stream
}

/// Send a request and return the reply code.
async fn socks_request(stream: &mut TcpStream, cmd: u8, dst: Dst<'_>, port: u16) -> u8 {
    let mut req = vec![5, cmd, 0];
    match dst {
        Dst::Domain(d) => {
            req.push(3);
            req.push(u8::try_from(d.len()).expect("domain length"));
            req.extend_from_slice(d.as_bytes());
        }
        Dst::V4(ip) => {
            req.push(1);
            req.extend_from_slice(&ip);
        }
    }
    req.extend_from_slice(&port.to_be_bytes());
    stream.write_all(&req).await.expect("request");
    let mut reply = [0u8; 10];
    timeout(IO_TIMEOUT, stream.read_exact(&mut reply))
        .await
        .expect("request reply timeout")
        .expect("request reply");
    assert_eq!(reply[0], 5);
    assert_eq!(reply[3], 1, "reply uses ATYP=IPv4");
    reply[1]
}

#[tokio::test]
async fn socks5_connect_domain_and_ipv4() {
    let ctx = setup(ServerOpts::default()).await;
    let id = ctx
        .forwards
        .add_dynamic(&ForwardSpec::parse_dynamic("127.0.0.1:0").expect("parse -D spec"))
        .await
        .expect("add_dynamic");
    let bind = ctx.bind_of(id);
    assert_eq!(ctx.forwards.list()[0].target, None);

    let mut stream = socks_handshake(bind).await;
    let rep = socks_request(&mut stream, 1, Dst::Domain("localhost"), ctx.echo.port()).await;
    assert_eq!(rep, 0, "CONNECT localhost succeeds");
    echo_round_trip(&mut stream, &random_bytes(70_000, 3)).await;

    let mut stream = socks_handshake(bind).await;
    let rep = socks_request(&mut stream, 1, Dst::V4([127, 0, 0, 1]), ctx.echo.port()).await;
    assert_eq!(rep, 0, "CONNECT 127.0.0.1 succeeds");
    echo_round_trip(&mut stream, &random_bytes(4096, 4)).await;

    let mut stream = socks_handshake(bind).await;
    let rep = socks_request(&mut stream, 2, Dst::V4([127, 0, 0, 1]), ctx.echo.port()).await;
    assert_eq!(rep, 0x07, "BIND is unsupported");

    // A port nobody listens on: find one by binding and releasing.
    let closed = {
        let l = TcpListener::bind("127.0.0.1:0").await.expect("bind probe");
        l.local_addr().expect("probe addr").port()
    };
    let mut stream = socks_handshake(bind).await;
    let rep = socks_request(&mut stream, 1, Dst::V4([127, 0, 0, 1]), closed).await;
    assert!(
        rep == 0x05 || rep == 0x04,
        "closed port → refused/unreachable, got {rep:#x}"
    );

    // An unknown auth method is refused with 0xFF.
    let mut stream = TcpStream::connect(bind).await.expect("connect -D");
    stream.write_all(&[5, 1, 2]).await.expect("greeting");
    let mut reply = [0u8; 2];
    timeout(IO_TIMEOUT, stream.read_exact(&mut reply))
        .await
        .expect("greeting reply timeout")
        .expect("greeting reply");
    assert_eq!(reply, [5, 0xFF]);
    ctx.finish().await;
}

#[tokio::test]
async fn remove_closes_listener() {
    let ctx = setup(ServerOpts::default()).await;
    let id = ctx
        .forwards
        .add_local(&ctx.echo_spec())
        .await
        .expect("add_local");
    let bind = ctx.bind_of(id);
    let mut stream = TcpStream::connect(bind)
        .await
        .expect("connect before remove");
    echo_round_trip(&mut stream, b"ping").await;

    assert!(ctx.forwards.remove(id).await);
    assert!(!ctx.forwards.remove(id).await, "second remove is a no-op");
    assert_eq!(ctx.forwards.list().len(), 0);
    let res = timeout(Duration::from_secs(1), TcpStream::connect(bind))
        .await
        .expect("connect did not fail within 1 s");
    match res {
        Err(e) => assert_eq!(e.kind(), std::io::ErrorKind::ConnectionRefused, "{e}"),
        Ok(_) => panic!("listener still accepting after remove"),
    }
    ctx.finish().await;
}

#[tokio::test]
async fn forward_local_denied_by_policy() {
    let ctx = setup(ServerOpts {
        deny: vec![Feature::ForwardLocal],
        ..Default::default()
    })
    .await;
    let id = ctx
        .forwards
        .add_local(&ctx.echo_spec())
        .await
        .expect("add_local binds locally regardless of policy");
    let bind = ctx.bind_of(id);
    let mut stream = TcpStream::connect(bind).await.expect("connect -L");
    stream.write_all(b"hello").await.expect("write");
    let mut buf = [0u8; 16];
    let n = timeout(Duration::from_secs(1), stream.read(&mut buf))
        .await
        .expect("denied forward must close within 1 s")
        .unwrap_or(0);
    assert_eq!(n, 0, "no echo through a denied forward");
    assert_eq!(ctx.forwards.list()[0].accepted, 0);
    ctx.finish().await;
}

#[tokio::test]
async fn forward_remote_denied() {
    let ctx = setup(ServerOpts {
        deny: vec![Feature::ForwardRemote],
        ..Default::default()
    })
    .await;
    let err = ctx
        .forwards
        .add_remote(&ctx.echo_spec())
        .await
        .expect_err("add_remote must be refused");
    let msg = format!("{err:#}").to_lowercase();
    assert!(msg.contains("denied"), "error should mention denied: {msg}");
    assert_eq!(ctx.forwards.list().len(), 0);
    ctx.finish().await;
}

#[tokio::test]
async fn many_concurrent_connections_through_one_forward() {
    let ctx = setup(ServerOpts::default()).await;
    let id = ctx
        .forwards
        .add_local(&ctx.echo_spec())
        .await
        .expect("add_local");
    let bind = ctx.bind_of(id);

    let clients: Vec<JoinHandle<()>> = (0..20u64)
        .map(|i| {
            tokio::spawn(async move {
                let data = random_bytes(64 * 1024, 100 + i);
                let mut stream = TcpStream::connect(bind).await.expect("connect -L");
                echo_round_trip(&mut stream, &data).await;
            })
        })
        .collect();
    timeout(Duration::from_secs(5), async {
        for c in clients {
            c.await.expect("client task");
        }
    })
    .await
    .expect("all 20 clients finish within 5 s");
    assert_eq!(ctx.forwards.list()[0].accepted, 20);
    ctx.finish().await;
}
