//! `mysh accept` (docs/05-meta-shell.md "Accepting connections"): listen
//! for servers started with `serve --connect-back`, print one line per
//! connection, and serve a control socket for each so the rest of the CLI
//! can address them as `@NAME`.
//!
//! The listener and the trust rules live in [`mysh_client::accept`]; this
//! module is the command around them: identity resolution, the callers
//! file, the per-connection [`CtlServer`], and the signal handling that
//! releases every connection (so each server goes back to its period)
//! before exiting.

use std::{
    net::{IpAddr, Ipv6Addr, SocketAddr},
    sync::Arc,
    time::Duration,
};

use anyhow::{Context as _, Result, anyhow, bail};
use mysh_client::{
    accept::{AcceptOpts, Acceptor, Inbound},
    identity::{Callers, client_identities},
};
use tokio::{
    net::lookup_host,
    signal::unix::{SignalKind, signal},
    sync::watch,
    task::JoinSet,
};
use tracing::info;

use super::{console::Console, console::ConsolePrompt, ctl::CtlServer, shared::Shared};
use crate::{
    cli::AcceptArgs,
    config::{DEFAULT_PORT, Paths, Target},
    identity::Baked,
    output::Mode,
};

/// How long the command waits for its connections to close on the way out.
const CLOSE_GRACE: Duration = Duration::from_secs(5);

/// Listen for connecting-back servers until a signal arrives. Returns the
/// process exit code.
pub async fn run(args: &AcceptArgs, paths: &Paths, baked: &Baked, mode: Mode) -> Result<i32> {
    let console = Console::with_mode(mode);
    let addr = listen_addr(args.addr.as_deref()).await?;
    let callers_path = args
        .callers
        .clone()
        .unwrap_or_else(|| paths.callers.clone());
    let callers = Callers::load_from(&callers_path);
    callers.include_baked(baked);
    if callers.is_empty() && !args.accept_new {
        bail!(
            "no callers in {}: add the servers' public keys (authorized_keys line format, the comment is the name) or pass --accept-new",
            callers_path.display()
        );
    }
    // Identity resolution is the same as for a dialed connection; the
    // server checks this key against its `authorized_keys`.
    let prompt = ConsolePrompt::new(console.clone());
    let identity = client_identities(&Target::accepted("accept"), paths, baked, &mut |source| {
        mysh_client::TrustPrompt::passphrase(&prompt, source)
    })
    .await?
    .into_iter()
    .next()
    .ok_or_else(|| anyhow!("no client identity found; run `mysh keygen`"))?;

    let opts = AcceptOpts {
        accept_new: args.accept_new,
        handshakes_per_minute: args.handshakes_per_minute,
    };
    let mut acceptor =
        Acceptor::bind(addr, identity, callers, Arc::new(console.clone()), opts).await?;
    console.notice(&format!(
        "accepting connections on {} (callers: {})",
        acceptor.local_addr(),
        callers_path.display()
    ));
    // Up: tell a `--daemon` parent and write the pid file (removed at exit).
    let _pid_file = crate::daemon::ready(&args.detach)?;

    // Registered and never read: a hangup must not end a detached acceptor.
    let _hangup = signal(SignalKind::hangup());
    let mut sigterm = signal(SignalKind::terminate()).context("SIGTERM handler")?;
    let mut sigint = signal(SignalKind::interrupt()).context("SIGINT handler")?;
    let (shutdown, _) = watch::channel(false);
    let mut connections = JoinSet::new();
    let reason = loop {
        tokio::select! {
            _ = sigterm.recv() => break "signal",
            _ = sigint.recv() => break "interrupt",
            inbound = acceptor.next() => match inbound {
                Some(inbound) => {
                    connections.spawn(serve(
                        inbound,
                        paths.clone(),
                        console.clone(),
                        shutdown.subscribe(),
                    ));
                }
                None => break "listener stopped",
            },
            Some(_) = connections.join_next(), if !connections.is_empty() => {}
        }
    };
    info!(reason, "accept exiting");
    acceptor.close();
    let _ = shutdown.send(true);
    // Closing every connection lets each server return to its period
    // instead of waiting for the TCP timeout.
    let _ = tokio::time::timeout(CLOSE_GRACE, async {
        while connections.join_next().await.is_some() {}
    })
    .await;
    console.flush().await;
    Ok(0)
}

/// Serve one accepted connection: its control socket at
/// `<runtime>/mysh/@NAME.sock` until the connection ends or the command
/// exits. The socket is removed either way.
async fn serve(
    inbound: Inbound,
    paths: Paths,
    console: Console,
    mut shutdown: watch::Receiver<bool>,
) {
    let Inbound { client, caller, .. } = inbound;
    let conn = client.connection().clone();
    let target = Target::accepted(&caller.label());
    let shared = Shared::new(
        conn.clone(),
        console.clone(),
        client.forwards().clone(),
        super::home_dir(),
    );
    let ctl = CtlServer::start(&paths, &target, Arc::clone(&shared)).await;
    if let Some(ctl) = &ctl {
        info!(caller = %target.display, socket = %ctl.path().display(), "serving accepted connection");
    }
    tokio::select! {
        () = conn.closed() => {}
        _ = shutdown.changed() => {}
    }
    // Removes the socket before the connection goes away, so no CLI call
    // finds a socket that cannot answer.
    drop(ctl);
    drop(shared);
    client.close().await;
}

/// `ADDR` of `mysh accept`: a bare port, `host:port`, or the default
/// `[::]:7722`.
async fn listen_addr(arg: Option<&str>) -> Result<SocketAddr> {
    let Some(arg) = arg else {
        return Ok(SocketAddr::new(
            IpAddr::V6(Ipv6Addr::UNSPECIFIED),
            DEFAULT_PORT,
        ));
    };
    if let Ok(port) = arg.parse::<u16>() {
        return Ok(SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), port));
    }
    if let Ok(addr) = arg.parse::<SocketAddr>() {
        return Ok(addr);
    }
    lookup_host(arg)
        .await
        .with_context(|| format!("resolving {arg}"))?
        .next()
        .ok_or_else(|| anyhow!("{arg} resolves to no address"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn listen_addr_forms() {
        assert_eq!(
            listen_addr(None).await.expect("default"),
            SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), DEFAULT_PORT)
        );
        assert_eq!(
            listen_addr(Some("9000")).await.expect("port"),
            SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 9000)
        );
        assert_eq!(
            listen_addr(Some("127.0.0.1:7100")).await.expect("addr"),
            "127.0.0.1:7100".parse::<SocketAddr>().expect("parse")
        );
        assert!(listen_addr(Some("not a host")).await.is_err());
    }
}
