//! Pairing through the real binary (docs/02-security.md "Pairing",
//! docs/06-roadmap.md M9): a fresh client pairs with a one-time code and
//! can then connect without `--accept-new`; a wrong code closes the window
//! and writes nothing; expired and replayed codes are refused; a normal
//! client is unaffected by an open window; a pairing-only connection cannot
//! open anything but `Pair`; `SIGUSR1` opens a new window on a running
//! `mysh serve`.

mod common;

use std::{
    io::{BufRead as _, BufReader},
    process::{Command, Output, Stdio},
    time::Duration,
};

use mysh::output::PairOut;
use mysh_net::{
    handshake::{ClientAuth, client_handshake},
    keys::{SecretKey, write_public_key, write_secret_key},
    mux::{Mode, Mux, OpenError},
};
use mysh_proto::{
    caps,
    open::{ErrorCode, Open},
};

const CODE: &str = "apple-bread-cat-dog-eagle-fish";

fn window(code: &str, duration: Duration) -> common::ServerOpts {
    common::ServerOpts {
        // The harness client key starts out unknown to the server.
        untrusted_client: true,
        pair_window: Some((code.to_owned(), duration)),
        ..common::ServerOpts::default()
    }
}

fn cmd(env: &[(String, String)]) -> Command {
    let mut cmd = Command::new(common::mysh_bin());
    cmd.env_clear()
        .envs(env.iter().map(|(k, v)| (k.as_str(), v.as_str())))
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    cmd
}

fn pair(env: &[(String, String)], host: &str, code: &str, json: bool) -> Output {
    let mut c = cmd(env);
    c.arg("pair");
    if json {
        c.arg("--json");
    }
    c.arg(host).arg(code).output().expect("run mysh pair")
}

fn connect_true(env: &[(String, String)], host: &str) -> Output {
    cmd(env)
        .arg(host)
        .arg("true")
        .output()
        .expect("run mysh HOST true")
}

fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

#[tokio::test(flavor = "multi_thread")]
async fn pair_installs_both_keys_and_later_connects_without_accept_new() {
    let server = common::start_server(window(CODE, Duration::from_secs(60))).await;
    let env = common::client_env(&server);
    let host = server.host_arg();
    assert!(!server.server_authorized_keys.exists());
    assert!(!server.client_dir.join("known_hosts").exists());

    // Typed with spaces and capitals: normalization applies.
    let out = pair(&env, &host, "Apple bread cat dog eagle fish", true);
    assert_eq!(out.status.code(), Some(0), "stderr: {}", stderr(&out));
    let doc: PairOut = serde_json::from_slice(&out.stdout).expect("PairOut");
    assert_eq!(doc.host, host);
    assert_eq!(
        doc.server_fingerprint,
        server.server_key.fingerprint().to_string()
    );
    assert_eq!(
        doc.client_fingerprint,
        server.client_identity.public.fingerprint().to_string()
    );

    let authorized = std::fs::read_to_string(&server.server_authorized_keys).expect("ak");
    assert_eq!(authorized.trim_end(), doc.authorized_line);
    assert!(authorized.contains(&server.client_identity.public.to_line(None).trim_end()[..40]));
    assert!(authorized.contains(" paired 20"));
    let known = std::fs::read_to_string(server.client_dir.join("known_hosts")).expect("kh");
    assert_eq!(known.trim_end(), doc.host_line);
    assert!(known.starts_with(&format!("{host} ")));
    assert!(known.contains(server.server_key.to_line(None).trim_end()));

    // No --accept-new: the pinned key and the installed client key suffice.
    let out = connect_true(&env, &host);
    assert_eq!(out.status.code(), Some(0), "stderr: {}", stderr(&out));

    // Replay: the window is spent.
    let out = pair(&env, &host, CODE, false);
    assert_eq!(out.status.code(), Some(2), "stderr: {}", stderr(&out));
    assert!(
        stderr(&out).contains("no pairing window"),
        "stderr: {}",
        stderr(&out)
    );
    server.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn wrong_code_closes_the_window_and_writes_nothing() {
    let server = common::start_server(window(CODE, Duration::from_secs(60))).await;
    let env = common::client_env(&server);
    let host = server.host_arg();

    let out = pair(&env, &host, "apple-bread-cat-dog-eagle-goat", false);
    assert_eq!(out.status.code(), Some(2), "stderr: {}", stderr(&out));
    assert!(
        stderr(&out).contains("did not know the code"),
        "stderr: {}",
        stderr(&out)
    );
    assert!(!server.server_authorized_keys.exists());
    assert!(!server.client_dir.join("known_hosts").exists());

    // The correct code is refused now: one failure ends the window.
    let out = pair(&env, &host, CODE, false);
    assert_eq!(out.status.code(), Some(2), "stderr: {}", stderr(&out));
    assert!(
        stderr(&out).contains("no pairing window"),
        "stderr: {}",
        stderr(&out)
    );
    assert!(!server.server_authorized_keys.exists());
    assert!(!server.client_dir.join("known_hosts").exists());
    server.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn expired_window_is_refused() {
    let server = common::start_server(window(CODE, Duration::from_millis(1))).await;
    let env = common::client_env(&server);
    tokio::time::sleep(Duration::from_millis(20)).await;
    let out = pair(&env, &server.host_arg(), CODE, false);
    assert_eq!(out.status.code(), Some(2), "stderr: {}", stderr(&out));
    assert!(
        stderr(&out).contains("no pairing window"),
        "stderr: {}",
        stderr(&out)
    );
    assert!(!server.server_authorized_keys.exists());
    server.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn normal_clients_are_unaffected_by_an_open_window() {
    // The harness client is trusted here; the window is open for others.
    let server = common::start_server(common::ServerOpts {
        pair_window: Some((CODE.to_owned(), Duration::from_secs(60))),
        ..common::ServerOpts::default()
    })
    .await;
    let env = common::client_env(&server);
    let out = cmd(&env)
        .arg("--accept-new")
        .arg(server.host_arg())
        .args(["echo", "hi"])
        .output()
        .expect("run");
    assert_eq!(out.status.code(), Some(0), "stderr: {}", stderr(&out));
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "hi");
    // A normal connection cannot use `Open::Pair`.
    let conn = server
        .connect(mysh::cli::ConnectOpts::default())
        .await
        .expect("connect");
    match conn.open(&Open::Pair).await {
        Err(OpenError::Rejected { code, .. }) => assert_eq!(code, ErrorCode::Denied),
        other => panic!("expected Denied, got {other:?}"),
    }
    conn.close().await;
    // The window is still intact for a real pairing.
    let out = pair(&env, &server.host_arg(), CODE, false);
    assert_eq!(out.status.code(), Some(0), "stderr: {}", stderr(&out));
    server.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn pairing_only_connections_get_denied_for_everything_else() {
    let server = common::start_server(window(CODE, Duration::from_secs(60))).await;
    let tcp = tokio::net::TcpStream::connect(server.addr)
        .await
        .expect("tcp");
    let key = SecretKey::generate();
    let (hs, _hello) = client_handshake(
        tcp,
        &key,
        caps::PAIR_REQUEST,
        |_, _| Ok(()),
        ClientAuth::Static,
    )
    .await
    .expect("pairing handshake");
    assert!(hs.pairing);
    let (mux, _incoming) = Mux::new(hs.stream, Mode::Client);
    let _control = mux.open(&Open::Control).await.expect("control");
    for open in [Open::Info, Open::ListSessions] {
        match mux.open(&open).await {
            Err(OpenError::Rejected { code, message }) => {
                assert_eq!(code, ErrorCode::Denied, "{message}");
                assert!(message.contains("pairing-only"), "{message}");
            }
            other => panic!("expected Denied for {open:?}, got {other:?}"),
        }
    }
    mux.close().await;
    // Nothing was consumed: the window is still open.
    assert!(server.pairing_open());
    server.stop().await;
}

/// Spawn `mysh serve --listen 127.0.0.1:0` with a throwaway config dir, send
/// it `SIGUSR1`, read the printed code from stderr, and pair with it.
#[tokio::test(flavor = "multi_thread")]
async fn sigusr1_opens_a_new_window_on_a_running_server() {
    let dir = common::TempDir::new("pair-usr1");
    let server_dir = dir.join("server");
    let client_dir = dir.join("client");
    let home = dir.join("home");
    for d in [&server_dir, &client_dir, &home] {
        std::fs::create_dir_all(d).expect("mkdir");
    }
    let client_key = SecretKey::generate();
    write_secret_key(&client_dir.join("id"), &client_key).expect("client key");
    write_public_key(&client_dir.join("id.pub"), &client_key.public(), Some("it")).expect("pub");
    // `serve` refuses to start with no trusted keys unless `--pair`; give it
    // an unrelated key so the window comes from SIGUSR1 alone.
    let dummy = SecretKey::generate().public().to_line(Some("dummy"));

    let mut serve = Command::new(common::mysh_bin())
        .env_clear()
        .env("MYSH_CONFIG_DIR", &server_dir)
        .env("HOME", &home)
        .env("PATH", std::env::var("PATH").unwrap_or_default())
        .args(["serve", "-v", "--listen", "127.0.0.1:0", "--authorized-key"])
        .arg(dummy.trim_end())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn mysh serve");
    // A reader thread feeds stderr lines through a channel so every wait is
    // bounded and the pipe never fills up.
    let (tx, rx) = std::sync::mpsc::channel::<String>();
    let stderr_pipe = serve.stderr.take().expect("stderr");
    std::thread::spawn(move || {
        for line in BufReader::new(stderr_pipe).lines().map_while(Result::ok) {
            if tx.send(line).is_err() {
                break;
            }
        }
    });
    let next_line = |rx: &std::sync::mpsc::Receiver<String>, what: &str| -> String {
        rx.recv_timeout(Duration::from_secs(20))
            .unwrap_or_else(|e| panic!("server stderr ended or stalled waiting for {what}: {e}"))
    };
    let host = loop {
        let line = next_line(&rx, "listening");
        if line.contains("listening")
            && let Some(rest) = line.split("addr=").nth(1)
        {
            break rest.split_whitespace().next().expect("addr").to_owned();
        }
    };

    let status = Command::new("kill")
        .arg("-USR1")
        .arg(serve.id().to_string())
        .status()
        .expect("kill");
    assert!(status.success());
    let code = loop {
        let line = next_line(&rx, "the pairing code");
        if let Some(rest) = line.strip_prefix("pairing code: ") {
            let c = rest.split_whitespace().next().expect("code").to_owned();
            assert!(line.contains("single use"), "{line}");
            assert_eq!(c.split('-').count(), 6, "{line}");
            break c;
        }
    };

    let env = vec![
        (
            "MYSH_CONFIG_DIR".to_owned(),
            client_dir.display().to_string(),
        ),
        ("HOME".to_owned(), home.display().to_string()),
        (
            "XDG_RUNTIME_DIR".to_owned(),
            dir.join("run").display().to_string(),
        ),
        ("PATH".to_owned(), std::env::var("PATH").unwrap_or_default()),
        ("SSH_AUTH_SOCK".to_owned(), String::new()),
    ];
    let out = pair(&env, &host, &code, true);
    assert_eq!(out.status.code(), Some(0), "stderr: {}", stderr(&out));
    let doc: PairOut = serde_json::from_slice(&out.stdout).expect("PairOut");
    assert_eq!(
        doc.client_fingerprint,
        client_key.public().fingerprint().to_string()
    );
    let authorized =
        std::fs::read_to_string(server_dir.join("authorized_keys")).expect("authorized_keys");
    assert!(authorized.contains(&doc.authorized_line));

    let out = connect_true(&env, &host);
    assert_eq!(out.status.code(), Some(0), "stderr: {}", stderr(&out));

    // Spent: the same code is refused.
    let out = pair(&env, &host, &code, false);
    assert_eq!(out.status.code(), Some(2), "stderr: {}", stderr(&out));

    let _ = serve.kill();
    let _ = serve.wait();
}
