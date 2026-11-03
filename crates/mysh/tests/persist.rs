//! Session persistence over the library API (docs/04-sessions.md "Client
//! gone", docs/03-protocol.md §10bis, docs/06-roadmap.md M5): a PTY session
//! whose stream closes is kept for the detach grace window, keeps producing
//! output into a ring, and can be listed and reattached by the same client
//! key from another connection; other keys see nothing; the grace window
//! and `--detach-grace 0` hang the session up.

mod common;

use std::{path::PathBuf, time::Duration};

use mysh::cli::ConnectOpts;
use mysh_net::{
    framing::{read_msg, write_msg},
    keys::{SecretKey, write_secret_key},
    mux::{OpenError, Stream},
};
use mysh_proto::{
    caps,
    open::{ErrorCode, Open},
    session::{
        DetachedSession, ExitStatus, PtyRequest, SessionIn, SessionKind, SessionOut,
        SessionRequest, WinSize,
    },
};

const WAIT: Duration = Duration::from_secs(5);

fn size() -> WinSize {
    WinSize {
        cols: 80,
        rows: 24,
        xpixel: 0,
        ypixel: 0,
    }
}

async fn start(grace: Option<Duration>) -> common::TestServer {
    common::start_server(common::ServerOpts {
        detach_grace: grace,
        ..common::ServerOpts::default()
    })
    .await
}

/// `sh -c SCRIPT` under a pty; returns the stream, session id and pid.
async fn open_pty(conn: &mysh::client::conn::Connection, script: &str) -> (Stream, u32, u32) {
    let req = SessionRequest {
        kind: SessionKind::Exec {
            argv: vec!["sh".into(), "-c".into(), script.into()],
        },
        env: Vec::new(),
        pty: Some(PtyRequest {
            term: "xterm".to_owned(),
            size: size(),
        }),
        cwd: None,
        persist: false,
    };
    let mut stream = conn
        .open(&Open::Session(req))
        .await
        .expect("open pty session");
    let started: SessionOut = read_msg(&mut stream).await.expect("read Started");
    let SessionOut::Started { session, pid, .. } = started else {
        panic!("expected Started, got {started:?}");
    };
    (stream, session, pid)
}

/// Read `Stdout` until the transcript contains `needle`; panics on `Exited`.
async fn read_until(stream: &mut Stream, needle: &str) -> String {
    let mut out = Vec::new();
    let fut = async {
        loop {
            match read_msg::<_, SessionOut>(stream).await.expect("read") {
                SessionOut::Stdout(chunk) => {
                    out.extend_from_slice(&chunk);
                    if String::from_utf8_lossy(&out).contains(needle) {
                        return String::from_utf8_lossy(&out).into_owned();
                    }
                }
                other => panic!(
                    "waiting for {needle:?}, got {other:?}; so far {:?}",
                    String::from_utf8_lossy(&out)
                ),
            }
        }
    };
    tokio::time::timeout(WAIT, fut)
        .await
        .unwrap_or_else(|_| panic!("timed out waiting for {needle:?}"))
}

/// Read until `Exited`; returns the transcript and the status.
async fn read_to_exit(stream: &mut Stream) -> (String, ExitStatus) {
    let mut out = Vec::new();
    let fut = async {
        loop {
            match read_msg::<_, SessionOut>(stream).await.expect("read") {
                SessionOut::Stdout(chunk) => out.extend_from_slice(&chunk),
                SessionOut::Exited(status) => {
                    return (String::from_utf8_lossy(&out).into_owned(), status);
                }
                other => panic!("unexpected {other:?}"),
            }
        }
    };
    tokio::time::timeout(WAIT, fut)
        .await
        .expect("timed out waiting for Exited")
}

async fn list(conn: &mysh::client::conn::Connection) -> Vec<DetachedSession> {
    let mut stream = conn.open(&Open::ListSessions).await.expect("ListSessions");
    read_msg(&mut stream).await.expect("session list")
}

/// Open `Attach` and consume `Attached`; returns the stream and `buffered`.
async fn attach(conn: &mysh::client::conn::Connection, id: u32) -> (Stream, u64) {
    let mut stream = conn
        .open(&Open::Attach { session: id })
        .await
        .expect("Attach");
    let first: SessionOut = read_msg(&mut stream).await.expect("Attached");
    let SessionOut::Attached {
        session, buffered, ..
    } = first
    else {
        panic!("expected Attached, got {first:?}");
    };
    assert_eq!(session, id);
    (stream, buffered)
}

/// `kill -0 PID` (true while the process exists, zombies included).
fn alive(pid: u32) -> bool {
    std::process::Command::new("kill")
        .args(["-0", &pid.to_string()])
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

async fn wait_gone(pid: u32) {
    let deadline = tokio::time::Instant::now() + WAIT;
    while alive(pid) {
        assert!(
            tokio::time::Instant::now() < deadline,
            "process {pid} still alive"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

#[tokio::test]
async fn detached_output_is_replayed_and_typing_works() {
    let server = start(Some(Duration::from_secs(30))).await;
    let conn1 = server
        .connect(ConnectOpts::default())
        .await
        .expect("connect");
    assert_ne!(
        conn1.server_hello().caps & caps::PERSIST,
        0,
        "PERSIST advertised when the grace window is open"
    );

    let (stream, id, pid) = open_pty(
        &conn1,
        "echo A; sleep 0.3; echo WHILE_DETACHED; read x; echo B_$((1+1)); read y",
    )
    .await;
    let mut stream = stream;
    read_until(&mut stream, "A").await;
    drop(stream); // detach: the stream closes, the connection stays
    tokio::time::sleep(Duration::from_millis(600)).await;
    assert!(alive(pid), "the detached process keeps running");

    // Same client identity, new connection.
    let conn2 = server
        .connect(ConnectOpts::default())
        .await
        .expect("connect");
    let rows = list(&conn2).await;
    assert_eq!(rows.len(), 1, "{rows:?}");
    assert_eq!(rows[0].id, id);
    assert_eq!(rows[0].pid, pid);
    assert!(rows[0].detached.is_some());
    assert!(
        rows[0].buffered > 0,
        "the marker printed while detached is buffered"
    );
    assert!(
        rows[0].kind.contains("WHILE_DETACHED"),
        "kind is the command line: {:?}",
        rows[0].kind
    );

    let (mut stream, buffered) = attach(&conn2, id).await;
    assert!(buffered > 0);
    let replay = read_until(&mut stream, "WHILE_DETACHED").await;
    assert!(
        !replay.contains("A\r\nA"),
        "no duplicate replay: {replay:?}"
    );

    // Now attached elsewhere: a second attach is refused, listing shows it attached.
    match conn1.open(&Open::Attach { session: id }).await {
        Err(OpenError::Rejected { code, message }) => {
            assert_eq!(code, ErrorCode::Limit, "{message}");
        }
        other => panic!("expected Limit, got {other:?}"),
    }
    let rows = list(&conn1).await;
    assert_eq!(rows.len(), 1);
    assert!(rows[0].detached.is_none());

    // Typing works after the reattach.
    write_msg(&mut stream, &SessionIn::Stdin(b"\n".to_vec()))
        .await
        .expect("stdin");
    read_until(&mut stream, "B_2").await;
    // Ids are server-wide: a fresh session on the second connection continues the sequence.
    let (_s, id2, _) = open_pty(&conn2, "read z").await;
    assert!(id2 > id, "{id2} > {id}");

    write_msg(&mut stream, &SessionIn::Stdin(b"\n".to_vec()))
        .await
        .expect("stdin");
    let (_, status) = read_to_exit(&mut stream).await;
    assert_eq!(status, ExitStatus::Code(0));
    assert!(list(&conn2).await.iter().all(|r| r.id != id));

    conn1.close().await;
    conn2.close().await;
    server.stop().await;
}

#[tokio::test]
async fn exit_while_detached_is_reported_on_attach() {
    let server = start(Some(Duration::from_secs(30))).await;
    let conn = server
        .connect(ConnectOpts::default())
        .await
        .expect("connect");
    let (mut stream, id, pid) = open_pty(&conn, "echo A; sleep 0.2; echo BYE; exit 7").await;
    read_until(&mut stream, "A").await;
    drop(stream);
    tokio::time::sleep(Duration::from_millis(700)).await;
    assert!(!alive(pid), "reaped while detached");

    let rows = list(&conn).await;
    assert_eq!(rows.len(), 1, "kept for the grace window: {rows:?}");
    let (mut stream, buffered) = attach(&conn, id).await;
    assert!(buffered > 0);
    let (out, status) = read_to_exit(&mut stream).await;
    assert!(out.contains("BYE"), "{out:?}");
    assert_eq!(status, ExitStatus::Code(7));
    assert_eq!(list(&conn).await, Vec::new());

    conn.close().await;
    server.stop().await;
}

#[tokio::test]
async fn other_client_key_cannot_see_or_attach() {
    let other = SecretKey::generate();
    let server = common::start_server(common::ServerOpts {
        detach_grace: Some(Duration::from_secs(30)),
        extra_authorized: vec![other.public()],
        ..common::ServerOpts::default()
    })
    .await;
    let other_path: PathBuf = server.client_dir.join("other_id");
    write_secret_key(&other_path, &other).expect("write other key");

    let conn = server
        .connect(ConnectOpts::default())
        .await
        .expect("connect");
    let (mut stream, id, _) = open_pty(&conn, "echo A; read x").await;
    read_until(&mut stream, "A").await;
    drop(stream);
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(list(&conn).await.len(), 1);

    let stranger = server
        .connect(ConnectOpts {
            identity: Some(other_path),
            ..ConnectOpts::default()
        })
        .await
        .expect("connect as the other key");
    assert_eq!(list(&stranger).await, Vec::new());
    match stranger.open(&Open::Attach { session: id }).await {
        Err(OpenError::Rejected { code, .. }) => assert_eq!(code, ErrorCode::NotFound),
        other => panic!("expected NotFound, got {other:?}"),
    }
    match conn.open(&Open::Attach { session: id + 100 }).await {
        Err(OpenError::Rejected { code, .. }) => assert_eq!(code, ErrorCode::NotFound),
        other => panic!("expected NotFound, got {other:?}"),
    }
    // Still there for the owner.
    let (mut stream, _) = attach(&conn, id).await;
    write_msg(&mut stream, &SessionIn::Stdin(b"\n".to_vec()))
        .await
        .expect("stdin");
    let (_, status) = read_to_exit(&mut stream).await;
    assert_eq!(status, ExitStatus::Code(0));

    stranger.close().await;
    conn.close().await;
    server.stop().await;
}

#[tokio::test]
async fn grace_expiry_hangs_the_session_up() {
    let server = start(Some(Duration::from_millis(300))).await;
    let conn = server
        .connect(ConnectOpts::default())
        .await
        .expect("connect");
    let (mut stream, _id, pid) = open_pty(&conn, "echo A; read x").await;
    read_until(&mut stream, "A").await;
    drop(stream);
    tokio::time::sleep(Duration::from_secs(1)).await;
    assert_eq!(list(&conn).await, Vec::new());
    wait_gone(pid).await;

    conn.close().await;
    server.stop().await;
}

#[tokio::test]
async fn grace_zero_keeps_the_old_behaviour() {
    let server = start(Some(Duration::ZERO)).await;
    let conn = server
        .connect(ConnectOpts::default())
        .await
        .expect("connect");
    assert_eq!(conn.server_hello().caps & caps::PERSIST, 0);
    let (mut stream, id, pid) = open_pty(&conn, "echo A; read x").await;
    read_until(&mut stream, "A").await;
    drop(stream);
    wait_gone(pid).await;
    match conn.open(&Open::ListSessions).await {
        Err(OpenError::Rejected { code, .. }) => assert_eq!(code, ErrorCode::Unsupported),
        other => panic!("expected Unsupported, got {other:?}"),
    }
    match conn.open(&Open::Attach { session: id }).await {
        Err(OpenError::Rejected { code, .. }) => assert_eq!(code, ErrorCode::Unsupported),
        other => panic!("expected Unsupported, got {other:?}"),
    }

    conn.close().await;
    server.stop().await;
}

#[tokio::test]
async fn server_shutdown_hangs_up_detached_sessions() {
    let server = start(Some(Duration::from_secs(30))).await;
    let conn = server
        .connect(ConnectOpts::default())
        .await
        .expect("connect");
    let (mut stream, _id, pid) = open_pty(&conn, "echo A; read x").await;
    read_until(&mut stream, "A").await;
    drop(stream);
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(alive(pid));
    conn.close().await;
    server.stop().await;
    wait_gone(pid).await;
}
