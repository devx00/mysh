//! `Open::Info` (docs/03-protocol.md §10quater): one `Msg<Info>` describing
//! the server and the effective policy of this connection, then close.
//! Nothing here runs a command; everything comes from the policy, the
//! process environment and `uname(2)`.

use std::{
    sync::LazyLock,
    time::{Duration, Instant},
};

use mysh_net::{
    framing::{write_msg, write_reply},
    mux::Stream,
};
use mysh_proto::{
    caps,
    info::{Info, Limits, Platform},
    limits,
    open::OpenReply,
};
use tokio::io::AsyncWriteExt as _;
use tracing::debug;

use super::{ConnCtx, Policy};
use crate::cli::Feature;

/// When the server process started (first use pins it; `Server::bind`
/// forces it early).
static STARTED: LazyLock<Instant> = LazyLock::new(Instant::now);

/// Record the server start for `Info.uptime_secs`.
pub(crate) fn mark_started() {
    LazyLock::force(&STARTED);
}

/// `uname -r` of the running kernel; empty when unavailable.
#[must_use]
pub fn kernel_release() -> String {
    rustix::system::uname()
        .release()
        .to_string_lossy()
        .into_owned()
}

/// `ServerHello.caps` for `policy`, as `handle_connection` computes it.
fn caps_for(policy: &Policy) -> u32 {
    let mut bits = 0;
    if !policy.detach_grace.is_zero() {
        bits |= caps::PERSIST;
    }
    if policy.signature_auth {
        bits |= caps::SIG_AUTH;
    }
    bits
}

/// `--deny` names as `mysh serve` spells them.
fn feature_name(feature: Feature) -> &'static str {
    match feature {
        Feature::Pty => "pty",
        Feature::Exec => "exec",
        Feature::Files => "files",
        Feature::ForwardLocal => "forward-local",
        Feature::ForwardRemote => "forward-remote",
    }
}

/// The `Info` for one connection's effective policy.
#[must_use]
pub fn build(policy: &Policy) -> Info {
    let mut denied: Vec<String> = policy
        .deny
        .iter()
        .map(|f| feature_name(*f).to_owned())
        .collect();
    denied.sort_unstable();
    Info {
        name: policy.name.clone(),
        version: env!("CARGO_PKG_VERSION").to_owned(),
        platform: Platform {
            os: std::env::consts::OS.to_owned(),
            arch: std::env::consts::ARCH.to_owned(),
            kernel: kernel_release(),
        },
        shell: mysh_pty::process::login_shell(policy.shell.as_deref())
            .display()
            .to_string(),
        home: policy.home.display().to_string(),
        user: policy.user.clone(),
        caps: caps_for(policy),
        limits: Limits {
            max_sessions: u32::try_from(limits::MAX_SESSIONS).unwrap_or(u32::MAX),
            max_listeners: u32::try_from(limits::MAX_LISTENERS).unwrap_or(u32::MAX),
            max_streams: u32::try_from(limits::MAX_STREAMS).unwrap_or(u32::MAX),
            detach_grace_secs: policy.detach_grace.as_secs(),
            idle_timeout_secs: policy.idle_timeout.as_secs(),
            handshakes_per_minute: policy.handshakes_per_minute,
            denied,
        },
        uptime_secs: uptime().as_secs(),
    }
}

fn uptime() -> Duration {
    STARTED.elapsed()
}

/// `Open::Info`: reply `Ok`, send the `Info`, close.
pub async fn handle_info(mut stream: Stream, ctx: ConnCtx) {
    if write_reply(&mut stream, &OpenReply::Ok).await.is_err() {
        return;
    }
    let info = build(&ctx.policy);
    if let Err(e) = write_msg(&mut stream, &info).await {
        debug!(peer = %ctx.peer, error = %e, "info reply failed");
    }
    let _ = stream.shutdown().await;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kernel_matches_uname() {
        let out = std::process::Command::new("uname").arg("-r").output();
        if let Ok(out) = out
            && out.status.success()
        {
            let expected = String::from_utf8_lossy(&out.stdout).trim().to_owned();
            assert_eq!(kernel_release(), expected);
        }
    }

    #[test]
    fn info_reflects_policy() {
        let mut policy = crate::server::tests::test_policy();
        policy.deny.insert(Feature::Exec);
        policy.detach_grace = Duration::ZERO;
        let info = build(&policy);
        assert_eq!(info.name, "testhost");
        assert_eq!(info.platform.os, std::env::consts::OS);
        assert_eq!(info.platform.arch, std::env::consts::ARCH);
        assert_eq!(info.shell, "/bin/sh");
        assert_eq!(info.user, "tester");
        assert_eq!(info.limits.denied, vec!["exec".to_owned()]);
        assert_eq!(info.limits.detach_grace_secs, 0);
        assert_eq!(info.caps & caps::PERSIST, 0);
        assert_eq!(info.caps & caps::SIG_AUTH, caps::SIG_AUTH);
        assert_eq!(
            info.limits.max_sessions,
            u32::try_from(limits::MAX_SESSIONS).unwrap()
        );
    }
}
