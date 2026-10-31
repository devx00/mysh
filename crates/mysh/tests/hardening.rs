//! Server hardening (docs/02-security.md "Limits and hardening" and
//! "Per-key options", docs/06-roadmap.md M4): per-key `authorized_keys`
//! options, the per-address handshake rate limit, the idle timeout, and the
//! listener/stream quotas, all against an in-process server on loopback.

mod common;

use std::{net::SocketAddr, time::Duration};

use common::{ServerOpts, TestServer};
use mysh::cli::ConnectOpts;
use mysh_net::{
    framing::read_msg,
    handshake::{HandshakeError, client_handshake},
    keys::SecretKey,
    mux::{Mode, Mux, OpenError},
};
use mysh_proto::{
    file::FileOp,
    handshake::ClientHello,
    limits,
    open::{ErrorCode, Open},
    session::{ExitStatus, PtyRequest, SessionKind, SessionOut, SessionRequest, WinSize},
};
use tokio::{net::TcpStream, time::timeout};

/// Noise handshake plus mux with `key`, without the client-side trust
/// machinery (the server key is accepted blindly: this is loopback).
async fn raw_connect(addr: SocketAddr, key: &SecretKey) -> Result<Mux, HandshakeError> {
    let tcp = TcpStream::connect(addr).await?;
    let (hs, _hello) = client_handshake(tcp, key, ClientHello { caps: 0 }, |_, _| Ok(())).await?;
    let (mux, _incoming) = Mux::new(hs.stream, Mode::Client);
    Ok(mux)
}

/// A server trusting only `key`, authorized with `options` in front of it.
async fn server_with_options(key: &SecretKey, options: &str) -> TestServer {
    common::start_server(ServerOpts {
        untrusted_client: true,
        authorized_lines: vec![format!("{options} {}", key.public().to_line(None))],
        ..ServerOpts::default()
    })
    .await
}

fn exec(argv: &[&str]) -> SessionRequest {
    SessionRequest {
        kind: SessionKind::Exec {
            argv: argv.iter().map(|s| (*s).to_owned()).collect(),
        },
        env: Vec::new(),
        pty: None,
        cwd: None,
    }
}

fn pty_shell() -> SessionRequest {
    SessionRequest {
        kind: SessionKind::Shell,
        env: Vec::new(),
        pty: Some(PtyRequest {
            term: "dumb".to_owned(),
            size: WinSize::default(),
        }),
        cwd: None,
    }
}

/// Run an exec session to completion: `(stdout, exit status)`.
async fn run_exec(mux: &Mux, req: SessionRequest) -> (Vec<u8>, ExitStatus) {
    let mut session = mux.open(&Open::Session(req)).await.expect("open session");
    let started: SessionOut = read_msg(&mut session).await.expect("Started");
    assert!(matches!(started, SessionOut::Started { .. }), "{started:?}");
    let mut out = Vec::new();
    loop {
        match read_msg::<_, SessionOut>(&mut session)
            .await
            .expect("session frame")
        {
            SessionOut::Stdout(chunk) => out.extend_from_slice(&chunk),
            SessionOut::Stderr(chunk) => panic!("unexpected stderr {chunk:?}"),
            SessionOut::Exited(status) => return (out, status),
            other => panic!("unexpected {other:?}"),
        }
    }
}

fn assert_rejected(result: Result<impl std::fmt::Debug, OpenError>, expected: ErrorCode) {
    match result {
        Err(OpenError::Rejected { code, .. }) => assert_eq!(code, expected),
        other => panic!("expected Rejected({expected:?}), got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// Per-key options

#[tokio::test]
async fn from_mismatch_is_unauthorized() {
    let key = SecretKey::generate();
    let server = server_with_options(&key, r#"from="10.0.0.0/8""#).await;
    match raw_connect(server.addr, &key).await {
        Err(HandshakeError::Denied { code, .. }) => assert_eq!(code, ErrorCode::Unauthorized),
        other => panic!("expected Denied(Unauthorized), got {other:?}"),
    }
    server.stop().await;
}

#[tokio::test]
async fn from_match_connects() {
    let key = SecretKey::generate();
    let server = server_with_options(&key, r#"from="10.0.0.0/8,127.0.0.0/8""#).await;
    let mux = raw_connect(server.addr, &key).await.expect("connect");
    let _control = mux.open(&Open::Control).await.expect("control");
    let (out, status) = run_exec(&mux, exec(&["echo", "ok"])).await;
    assert_eq!(out, b"ok\n");
    assert_eq!(status, ExitStatus::Code(0));
    mux.close().await;
    server.stop().await;
}

#[tokio::test]
async fn no_pty_rejects_pty_but_exec_works() {
    let key = SecretKey::generate();
    let server = server_with_options(&key, "no-pty").await;
    let mux = raw_connect(server.addr, &key).await.expect("connect");
    let _control = mux.open(&Open::Control).await.expect("control");
    assert_rejected(
        mux.open(&Open::Session(pty_shell())).await,
        ErrorCode::Denied,
    );
    let (out, status) = run_exec(&mux, exec(&["echo", "still"])).await;
    assert_eq!(out, b"still\n");
    assert_eq!(status, ExitStatus::Code(0));
    mux.close().await;
    server.stop().await;
}

#[tokio::test]
async fn no_files_rejects_file_open() {
    let key = SecretKey::generate();
    let server = server_with_options(&key, "no-files").await;
    let mux = raw_connect(server.addr, &key).await.expect("connect");
    let _control = mux.open(&Open::Control).await.expect("control");
    let open = Open::File {
        op: FileOp::Stat {
            path: "~".to_owned(),
        },
        cwd: None,
    };
    assert_rejected(mux.open(&open).await, ErrorCode::Denied);
    mux.close().await;
    server.stop().await;
}

#[tokio::test]
async fn no_forward_rejects_both_kinds() {
    let key = SecretKey::generate();
    let server = server_with_options(&key, "no-forward").await;
    let mux = raw_connect(server.addr, &key).await.expect("connect");
    let _control = mux.open(&Open::Control).await.expect("control");
    let direct = Open::DirectTcp {
        host: "127.0.0.1".to_owned(),
        port: 1,
    };
    assert_rejected(mux.open(&direct).await, ErrorCode::Denied);
    let listen = Open::ForwardListen {
        host: "127.0.0.1".to_owned(),
        port: 0,
    };
    assert_rejected(mux.open(&listen).await, ErrorCode::Denied);
    mux.close().await;
    server.stop().await;
}

#[tokio::test]
async fn forced_command_replaces_the_request() {
    let key = SecretKey::generate();
    let server = server_with_options(&key, r#"command="echo forced $MYSH_ORIGINAL_COMMAND""#).await;
    let mux = raw_connect(server.addr, &key).await.expect("connect");
    let _control = mux.open(&Open::Control).await.expect("control");

    let (out, status) = run_exec(&mux, exec(&["ls"])).await;
    assert_eq!(out, b"forced ls\n");
    assert_eq!(status, ExitStatus::Code(0));

    // A multi-word request is joined; a `Shell` request leaves it empty.
    let (out, _) = run_exec(&mux, exec(&["ls", "-l", "/tmp"])).await;
    assert_eq!(out, b"forced ls -l /tmp\n");
    let shell = SessionRequest {
        kind: SessionKind::Shell,
        env: Vec::new(),
        pty: None,
        cwd: None,
    };
    let (out, _) = run_exec(&mux, shell).await;
    assert_eq!(out, b"forced\n");

    mux.close().await;
    server.stop().await;
}

// ---------------------------------------------------------------------------
// Rate limit and idle timeout

#[tokio::test]
async fn handshake_rate_limit_is_per_address() {
    const RATE: u32 = 3;
    let key = SecretKey::generate();
    let server = common::start_server(ServerOpts {
        untrusted_client: true,
        authorized_lines: vec![key.public().to_line(None)],
        handshakes_per_minute: Some(RATE),
        listen_v6: true,
        ..ServerOpts::default()
    })
    .await;

    let mut muxes = Vec::new();
    for i in 0..RATE {
        let mux = raw_connect(server.addr, &key)
            .await
            .unwrap_or_else(|e| panic!("handshake {} should pass: {e}", i + 1));
        muxes.push(mux);
    }
    // N+1: TCP connects, but the server drops the socket before the Noise
    // preamble, so the client sees EOF (an I/O error, not a verdict).
    let dropped = timeout(Duration::from_secs(5), raw_connect(server.addr, &key))
        .await
        .expect("dropped connection should fail promptly");
    match dropped {
        Err(HandshakeError::Denied { .. }) => panic!("rate limit must not answer"),
        Err(_) => {}
        Ok(_) => panic!("handshake {} should be dropped", RATE + 1),
    }

    // Another address has its own bucket.
    match server.addr_v6 {
        Some(v6) => {
            let mux = raw_connect(v6, &key).await.expect("::1 is not limited");
            mux.close().await;
        }
        None => eprintln!("IPv6 loopback unavailable; skipping the ::1 half"),
    }

    for mux in muxes {
        mux.close().await;
    }
    server.stop().await;
}

#[tokio::test]
async fn idle_connection_is_closed() {
    let server = common::start_server(ServerOpts {
        idle_timeout: Some(Duration::from_millis(300)),
        ..ServerOpts::default()
    })
    .await;
    // The library client opens Control and then only pings every
    // `PING_INTERVAL` (30 s): well past a 300 ms idle timeout.
    let conn = server
        .connect(ConnectOpts::default())
        .await
        .expect("connect");
    timeout(Duration::from_secs(2), conn.closed())
        .await
        .expect("server closes an idle connection within ~1 s");
    assert!(conn.is_closed());
    server.stop().await;
}

// ---------------------------------------------------------------------------
// Quotas

#[tokio::test]
async fn listener_quota_is_enforced() {
    let server = common::start_server(ServerOpts::default()).await;
    let mux = raw_connect(server.addr, &server.client_identity.secret)
        .await
        .expect("connect");
    let _control = mux.open(&Open::Control).await.expect("control");

    let open = Open::ForwardListen {
        host: "127.0.0.1".to_owned(),
        port: 0,
    };
    let mut listeners = Vec::with_capacity(limits::MAX_LISTENERS);
    for i in 0..limits::MAX_LISTENERS {
        let stream = mux
            .open(&open)
            .await
            .unwrap_or_else(|e| panic!("listener {} should bind: {e}", i + 1));
        listeners.push(stream);
    }
    assert_rejected(mux.open(&open).await, ErrorCode::Limit);

    // Closing one frees a slot.
    drop(listeners.pop());
    let reopened = timeout(Duration::from_secs(5), async {
        loop {
            match mux.open(&open).await {
                Ok(stream) => break stream,
                Err(OpenError::Rejected {
                    code: ErrorCode::Limit,
                    ..
                }) => {
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
                Err(e) => panic!("unexpected {e:?}"),
            }
        }
    })
    .await
    .expect("slot is released when the stream closes");
    listeners.push(reopened);

    drop(listeners);
    mux.close().await;
    server.stop().await;
}

/// `MAX_STREAMS` is yamux's `max_num_streams`: it counts every open stream
/// on the connection, including Control, so `MAX_STREAMS - 1` further
/// streams succeed. The next outbound open fails locally with
/// `TooManyStreams`, and yamux 0.14 then tears the whole connection down
/// (the opener is at fault; the acceptor would do the same for an inbound
/// `SYN` past the cap). The streams must be acknowledged by the server (it
/// has answered on them): yamux also caps un-ACKed outbound streams at
/// 256, so raw opens the server never replies to stall at that lower bound
/// instead. Each stream here is a completed `Get` of a tiny file; the
/// server has half-closed it but the client still holds it open.
#[tokio::test]
async fn stream_quota_is_enforced_by_yamux() {
    let server = common::start_server(ServerOpts::default()).await;
    std::fs::write(server.home.join("quota"), b"q").expect("write quota file");
    let mux = raw_connect(server.addr, &server.client_identity.secret)
        .await
        .expect("connect");
    let _control = mux.open(&Open::Control).await.expect("control");

    let get = Open::File {
        op: FileOp::Get {
            path: "quota".to_owned(),
            offset: 0,
        },
        cwd: None,
    };
    let mut streams = Vec::with_capacity(limits::MAX_STREAMS);
    for i in 1..limits::MAX_STREAMS {
        let stream = timeout(Duration::from_secs(5), mux.open(&get))
            .await
            .expect("open stalls")
            .unwrap_or_else(|e| panic!("stream {} of {}: {e}", i + 1, limits::MAX_STREAMS));
        streams.push(stream);
    }
    let overflow = timeout(Duration::from_secs(5), mux.open_raw())
        .await
        .expect("overflow open stalls");
    assert!(
        overflow.is_err(),
        "stream {} must fail",
        limits::MAX_STREAMS + 1
    );
    timeout(Duration::from_secs(5), mux.closed())
        .await
        .expect("exceeding the stream cap closes the connection");
    assert!(matches!(mux.open_raw().await, Err(e) if e.kind() == std::io::ErrorKind::BrokenPipe));

    drop(streams);
    server.stop().await;
}
