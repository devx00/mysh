//! PTY sessions driven directly over the session stream (docs/04-sessions.md
//! "PTY session", docs/06-roadmap.md M2 tests): window size, resize, exit
//! status mapping, cwd handling, the cwd probe, shell expansion for a single
//! argument, the `Pty` policy and the per-connection session quota.

mod common;

use std::{path::Path, time::Duration};

use mysh::cli::{ConnectOpts, Feature};
use mysh_net::{
    framing::{read_msg, write_msg},
    mux::{OpenError, Stream},
};
use mysh_proto::{
    limits,
    open::{ErrorCode, Open},
    session::{
        ExitStatus, PtyRequest, SessionIn, SessionKind, SessionOut, SessionRequest, WinSize,
    },
};

const SMALL: WinSize = WinSize {
    cols: 80,
    rows: 24,
    xpixel: 0,
    ypixel: 0,
};

fn size(cols: u16, rows: u16) -> WinSize {
    WinSize {
        cols,
        rows,
        xpixel: 0,
        ypixel: 0,
    }
}

fn argv(parts: &[&str]) -> Vec<String> {
    parts.iter().map(|s| (*s).to_owned()).collect()
}

/// Fields of `SessionOut::Started`.
#[derive(Debug, Clone, Copy)]
struct Started {
    session: u32,
    cwd_fallback: bool,
}

/// Open a pty exec session and consume its `Started` message.
async fn open_pty_session(
    conn: &mysh::client::conn::Connection,
    argv: &[&str],
    size: WinSize,
    cwd: Option<String>,
) -> (Stream, Started) {
    let req = SessionRequest {
        kind: SessionKind::Exec {
            argv: self::argv(argv),
        },
        env: Vec::new(),
        pty: Some(PtyRequest {
            term: "xterm".to_owned(),
            size,
        }),
        cwd,
    };
    let mut stream = conn
        .open(&Open::Session(req))
        .await
        .expect("open pty session");
    let started: SessionOut = read_msg(&mut stream).await.expect("read Started");
    let SessionOut::Started {
        session,
        cwd_fallback,
        ..
    } = started
    else {
        panic!("expected Started, got {started:?}");
    };
    (
        stream,
        Started {
            session,
            cwd_fallback,
        },
    )
}

/// Read `SessionOut` messages until `Exited`; returns the concatenated
/// stdout and the status.
async fn collect_until_exit(stream: &mut Stream) -> (Vec<u8>, ExitStatus) {
    let mut out = Vec::new();
    loop {
        match read_msg::<_, SessionOut>(stream)
            .await
            .expect("read SessionOut")
        {
            SessionOut::Stdout(chunk) => out.extend_from_slice(&chunk),
            SessionOut::Stderr(chunk) => panic!("pty session sent Stderr: {chunk:?}"),
            SessionOut::Exited(status) => return (out, status),
            other @ (SessionOut::Started { .. } | SessionOut::Attached { .. }) => {
                panic!("unexpected {other:?}")
            }
        }
    }
}

async fn run(
    conn: &mysh::client::conn::Connection,
    argv: &[&str],
    size: WinSize,
    cwd: Option<String>,
) -> (Started, String, ExitStatus) {
    let (mut stream, started) = open_pty_session(conn, argv, size, cwd).await;
    let (out, status) = collect_until_exit(&mut stream).await;
    (started, String::from_utf8_lossy(&out).into_owned(), status)
}

fn canon(path: &Path) -> String {
    path.canonicalize()
        .expect("canonicalize")
        .display()
        .to_string()
}

/// The last non-empty line of a pty transcript, without `\r`.
fn last_line(out: &str) -> String {
    out.lines()
        .map(|l| l.trim_end_matches('\r'))
        .rfind(|l| !l.is_empty())
        .unwrap_or_default()
        .to_owned()
}

#[tokio::test]
async fn pty_session_sees_requested_size() {
    let server = common::start_server(common::ServerOpts::default()).await;
    let conn = server
        .connect(ConnectOpts::default())
        .await
        .expect("connect");

    let (_, out, status) = run(&conn, &["sh", "-c", "stty size"], size(100, 40), None).await;
    assert!(out.contains("40 100"), "output: {out:?}");
    assert_eq!(status, ExitStatus::Code(0));

    conn.close().await;
    server.stop().await;
}

#[tokio::test]
async fn resize_mid_session_is_observed() {
    let server = common::start_server(common::ServerOpts::default()).await;
    let conn = server
        .connect(ConnectOpts::default())
        .await
        .expect("connect");

    let (mut stream, _) = open_pty_session(
        &conn,
        &["sh", "-c", "stty size; read x; stty size"],
        SMALL,
        None,
    )
    .await;
    // Wait for the first `stty size` before resizing.
    let mut out = Vec::new();
    loop {
        match read_msg::<_, SessionOut>(&mut stream).await.expect("read") {
            SessionOut::Stdout(chunk) => {
                out.extend_from_slice(&chunk);
                if String::from_utf8_lossy(&out).contains("24 80") {
                    break;
                }
            }
            other => panic!("unexpected before first size: {other:?}"),
        }
    }
    write_msg(&mut stream, &SessionIn::Resize(size(120, 50)))
        .await
        .expect("send Resize");
    write_msg(&mut stream, &SessionIn::Stdin(b"\n".to_vec()))
        .await
        .expect("send Stdin");
    let (rest, status) = collect_until_exit(&mut stream).await;
    out.extend_from_slice(&rest);
    let text = String::from_utf8_lossy(&out);
    assert!(text.contains("50 120"), "output: {text:?}");
    assert_eq!(status, ExitStatus::Code(0));

    conn.close().await;
    server.stop().await;
}

#[tokio::test]
async fn signal_exit_status() {
    let server = common::start_server(common::ServerOpts::default()).await;
    let conn = server
        .connect(ConnectOpts::default())
        .await
        .expect("connect");

    let (_, _, status) = run(&conn, &["sh", "-c", "kill -TERM $$"], SMALL, None).await;
    assert!(
        matches!(status, ExitStatus::Signal { signal: 15, .. }),
        "status: {status:?}"
    );
    assert_eq!(status.shell_code(), 143);

    let (_, _, status) = run(&conn, &["sh", "-c", "exit 5"], SMALL, None).await;
    assert_eq!(status, ExitStatus::Code(5));

    conn.close().await;
    server.stop().await;
}

#[tokio::test]
async fn cwd_is_honoured_and_fallback_reported() {
    let server = common::start_server(common::ServerOpts::default()).await;
    let conn = server
        .connect(ConnectOpts::default())
        .await
        .expect("connect");
    let work = server.home.join("work");
    std::fs::create_dir_all(&work).expect("create work dir");
    let work_canon = canon(&work);
    let home_canon = canon(&server.home);

    let (started, out, _) = run(&conn, &["pwd"], SMALL, Some("work".to_owned())).await;
    assert!(!started.cwd_fallback);
    assert_eq!(last_line(&out), work_canon);
    assert!(last_line(&out).ends_with("/work"), "pwd: {out:?}");

    let (started, out, _) = run(&conn, &["pwd"], SMALL, Some("~/work".to_owned())).await;
    assert!(!started.cwd_fallback);
    assert_eq!(last_line(&out), work_canon);

    let (started, out, _) = run(&conn, &["pwd"], SMALL, Some("does-not-exist".to_owned())).await;
    assert!(started.cwd_fallback, "missing cwd must report fallback");
    assert_eq!(last_line(&out), home_canon);

    conn.close().await;
    server.stop().await;
}

#[tokio::test]
async fn cwd_probe_returns_foreground_cwd() {
    let server = common::start_server(common::ServerOpts::default()).await;
    let conn = server
        .connect(ConnectOpts::default())
        .await
        .expect("connect");
    let work = server.home.join("work");
    std::fs::create_dir_all(&work).expect("create work dir");

    let (mut stream, started) =
        open_pty_session(&conn, &["sh", "-c", "cd work; read x"], SMALL, None).await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    let probed = conn
        .cwd_probe(started.session)
        .await
        .expect("cwd probe answered");
    assert_eq!(canon(Path::new(&probed)), canon(&work));

    write_msg(&mut stream, &SessionIn::Stdin(b"\n".to_vec()))
        .await
        .expect("send Stdin");
    let (_, status) = collect_until_exit(&mut stream).await;
    assert_eq!(status, ExitStatus::Code(0));

    // The session is gone: the probe answers `None` now.
    assert_eq!(conn.cwd_probe(started.session).await, None);

    conn.close().await;
    server.stop().await;
}

#[tokio::test]
async fn single_argument_exec_goes_through_shell() {
    let server = common::start_server(common::ServerOpts {
        shell: Some("/bin/sh".into()),
        ..common::ServerOpts::default()
    })
    .await;
    let conn = server
        .connect(ConnectOpts::default())
        .await
        .expect("connect");

    let (_, out, status) = run(&conn, &["echo $0-$((1+1))"], SMALL, None).await;
    assert!(out.contains("-2"), "output: {out:?}");
    assert!(out.contains("sh-2"), "argv[0] should be the shell: {out:?}");
    assert_eq!(status, ExitStatus::Code(0));

    conn.close().await;
    server.stop().await;
}

#[tokio::test]
async fn pty_denied_by_policy() {
    let server = common::start_server(common::ServerOpts {
        deny: vec![Feature::Pty],
        ..common::ServerOpts::default()
    })
    .await;
    let conn = server
        .connect(ConnectOpts::default())
        .await
        .expect("connect");

    let req = SessionRequest {
        kind: SessionKind::Exec {
            argv: argv(&["sh", "-c", "true"]),
        },
        env: Vec::new(),
        pty: Some(PtyRequest {
            term: "xterm".to_owned(),
            size: SMALL,
        }),
        cwd: None,
    };
    match conn.open(&Open::Session(req)).await {
        Err(OpenError::Rejected { code, message }) => {
            assert_eq!(code, ErrorCode::Denied, "message: {message}");
        }
        Ok(_) => panic!("pty session opened despite --deny pty"),
        Err(e) => panic!("unexpected error: {e}"),
    }

    // Exec without a pty is still allowed.
    let req = SessionRequest {
        kind: SessionKind::Exec {
            argv: argv(&["sh", "-c", "exit 0"]),
        },
        env: Vec::new(),
        pty: None,
        cwd: None,
    };
    let mut stream = conn
        .open(&Open::Session(req))
        .await
        .expect("exec session without pty");
    let started: SessionOut = read_msg(&mut stream).await.expect("Started");
    assert!(matches!(started, SessionOut::Started { .. }), "{started:?}");

    conn.close().await;
    server.stop().await;
}

#[tokio::test]
async fn session_quota() {
    let server = common::start_server(common::ServerOpts::default()).await;
    let conn = server
        .connect(ConnectOpts::default())
        .await
        .expect("connect");

    let mut live = Vec::with_capacity(limits::MAX_SESSIONS);
    for _ in 0..limits::MAX_SESSIONS {
        let (stream, _) = open_pty_session(&conn, &["sh", "-c", "read x"], SMALL, None).await;
        live.push(stream);
    }
    assert_eq!(live.len(), limits::MAX_SESSIONS);

    let req = SessionRequest {
        kind: SessionKind::Exec {
            argv: argv(&["sh", "-c", "read x"]),
        },
        env: Vec::new(),
        pty: Some(PtyRequest {
            term: "xterm".to_owned(),
            size: SMALL,
        }),
        cwd: None,
    };
    match conn.open(&Open::Session(req)).await {
        Err(OpenError::Rejected { code, message }) => {
            assert_eq!(code, ErrorCode::Limit, "message: {message}");
        }
        Ok(_) => panic!("session {} opened past the quota", limits::MAX_SESSIONS + 1),
        Err(e) => panic!("unexpected error: {e}"),
    }

    drop(live);
    conn.close().await;
    server.stop().await;
}
