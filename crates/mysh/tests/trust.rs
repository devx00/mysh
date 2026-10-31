//! Server trust (TOFU, pins, `known_hosts`) and client authorization, per
//! docs/02-security.md "Server trust (client)" / "Authorization" and the M1
//! test bullets in docs/06-roadmap.md.
//!
//! Skipped on purpose: an `ssh-ed25519` line in `known_hosts` matching the
//! server. The harness server key is a random X25519 key, so no ed25519 key
//! converts to it, and the `ssh-key` crate is not a dependency of `mysh`.
//! The conversion itself is unit-tested in `mysh-net`.

mod common;

use std::{
    io::Write as _,
    process::{Command, Stdio},
};

use mysh::cli::ConnectOpts;
use mysh_net::keys::SecretKey;

/// Our `known_hosts` entry for the harness server, if the file exists.
fn known_hosts_line(server: &common::TestServer) -> Option<String> {
    let text = std::fs::read_to_string(server.client_dir.join("known_hosts")).ok()?;
    let prefix = format!("{} ", server.host_arg());
    text.lines()
        .find(|l| l.starts_with(&prefix))
        .map(str::to_owned)
}

#[tokio::test]
async fn authorized_client_connects() {
    let server = common::start_server(common::ServerOpts::default()).await;
    let conn = server
        .connect(ConnectOpts::default())
        .await
        .expect("connect");
    assert_eq!(conn.remote_key(), server.server_key);
    assert_eq!(conn.trusted_via(), "accept-new");
    conn.close().await;

    let line = known_hosts_line(&server).expect("known_hosts line for the server");
    let expected = server.server_key.to_line(None);
    assert_eq!(
        line,
        format!("{} {}", server.host_arg(), expected.trim_end())
    );
    server.stop().await;
}

#[tokio::test]
async fn unauthorized_client_is_denied() {
    let server = common::start_server(common::ServerOpts {
        untrusted_client: true,
        ..common::ServerOpts::default()
    })
    .await;
    let err = match server.connect(ConnectOpts::default()).await {
        Ok(_) => panic!("unauthorized client connected"),
        Err(e) => format!("{e:#}"),
    };
    assert!(err.contains("not authorized"), "unexpected error: {err}");
    assert!(
        err.contains(server.client_identity.public.fingerprint().as_str()),
        "error should name our key: {err}"
    );
    server.stop().await;
}

#[tokio::test]
async fn wrong_pin_is_mismatch() {
    let server = common::start_server(common::ServerOpts::default()).await;
    let other = SecretKey::generate().public().fingerprint();
    let err = match server
        .connect(ConnectOpts {
            pin: Some(other.to_string()),
            ..ConnectOpts::default()
        })
        .await
    {
        Ok(_) => panic!("wrong pin accepted"),
        Err(e) => format!("{e:#}"),
    };
    assert!(err.contains("does not match"), "unexpected error: {err}");
    assert!(
        err.contains("pin"),
        "error should name the pin source: {err}"
    );
    assert!(
        err.contains(other.as_str()),
        "expected fingerprint missing: {err}"
    );
    assert!(
        err.contains(server.server_key.fingerprint().as_str()),
        "actual fingerprint missing: {err}"
    );
    // A pin never falls back to TOFU: nothing was recorded.
    assert!(known_hosts_line(&server).is_none());
    server.stop().await;
}

#[tokio::test]
async fn correct_pin_connects() {
    let server = common::start_server(common::ServerOpts::default()).await;
    let conn = server
        .connect(ConnectOpts {
            pin: Some(server.server_key.fingerprint().to_string()),
            ..ConnectOpts::default()
        })
        .await
        .expect("connect with pin");
    assert_eq!(conn.trusted_via(), "pin");
    conn.close().await;
    assert!(known_hosts_line(&server).is_none());
    server.stop().await;
}

#[tokio::test]
async fn tofu_strict_rejects_unknown() {
    let server = common::start_server(common::ServerOpts::default()).await;
    let err = match server
        .connect(ConnectOpts {
            strict: true,
            ..ConnectOpts::default()
        })
        .await
    {
        Ok(_) => panic!("strict mode accepted an unknown key"),
        Err(e) => format!("{e:#}"),
    };
    assert!(err.contains("not known"), "unexpected error: {err}");
    assert!(!server.client_dir.join("known_hosts").exists());
    server.stop().await;
}

#[tokio::test]
async fn tofu_accept_new_records_then_reconnects_without_flag() {
    let server = common::start_server(common::ServerOpts::default()).await;
    let first = server
        .connect(ConnectOpts::default())
        .await
        .expect("first connect");
    first.close().await;
    assert!(known_hosts_line(&server).is_some());

    let second = server
        .connect(ConnectOpts {
            strict: true,
            ..ConnectOpts::default()
        })
        .await
        .expect("strict reconnect");
    assert!(
        second.trusted_via().ends_with("known_hosts:1"),
        "trusted via {}",
        second.trusted_via()
    );
    second.close().await;

    let text = std::fs::read_to_string(server.client_dir.join("known_hosts")).expect("read");
    assert_eq!(text.lines().count(), 1, "reconnect must not append again");
    server.stop().await;
}

#[tokio::test]
async fn known_hosts_mismatch_is_fatal() {
    let server = common::start_server(common::ServerOpts::default()).await;
    let path = server.client_dir.join("known_hosts");
    let other = SecretKey::generate().public();
    let stale = format!("{} {}", server.host_arg(), other.to_line(Some("stale")));
    std::fs::write(&path, &stale).expect("write known_hosts");

    let err = match server.connect(ConnectOpts::default()).await {
        Ok(_) => panic!("mismatched key accepted"),
        Err(e) => format!("{e:#}"),
    };
    assert!(err.contains("does not match"), "unexpected error: {err}");
    assert!(err.contains("known_hosts, line 1"), "source missing: {err}");
    assert!(
        err.contains(other.fingerprint().as_str()),
        "expected fp: {err}"
    );
    assert!(
        err.contains(server.server_key.fingerprint().as_str()),
        "actual fp: {err}"
    );
    assert_eq!(std::fs::read_to_string(&path).expect("read"), stale);
    server.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn binary_rejects_unknown_host_when_not_a_tty() {
    let server = common::start_server(common::ServerOpts::default()).await;
    let env = common::client_env(&server);
    let run = |extra: &[&str]| {
        let mut child = Command::new(common::mysh_bin())
            .env_clear()
            .envs(env.iter().map(|(k, v)| (k.as_str(), v.as_str())))
            .args(extra)
            .arg(server.host_arg())
            .arg("true")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn mysh");
        child
            .stdin
            .take()
            .expect("stdin")
            .write_all(b"yes\n")
            .expect("write stdin");
        child.wait_with_output().expect("wait")
    };

    let out = run(&[]);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(2), "stderr: {stderr}");
    assert!(stderr.contains("not in known_hosts"), "stderr: {stderr}");
    assert!(!server.client_dir.join("known_hosts").exists());

    let out = run(&["--accept-new"]);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(0), "stderr: {stderr}");
    assert!(known_hosts_line(&server).is_some());
    server.stop().await;
}
