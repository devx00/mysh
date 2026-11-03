//! Client: connect, trust, sessions, terminal driver, meta shell, files,
//! forwards. Layout per `docs/01-architecture.md`; modes and exit codes per
//! docs/05-meta-shell.md "Modes and exit" and docs/04-sessions.md "Exit
//! codes".

pub mod attach;
pub mod conn;
pub mod console;
pub mod ctl;
pub mod editor;
pub mod fileops;
pub mod files;
pub mod fleet;
pub mod forward;
pub mod jobs;
pub mod master;
pub mod meta;
pub mod pair;
pub mod session;
pub mod session_api;
pub mod shared;
pub mod sync;
pub mod terminal;

use std::{path::PathBuf, sync::Arc, time::Duration};

use anyhow::{Context as _, Result};
use mysh_proto::session::{ExitStatus, SessionKind};
use tokio::signal::unix::{SignalKind, signal};
use tracing::{debug, warn};

use crate::{
    cli::{AuthorizeArgs, FileCmd, ForwardCliArgs, GetArgs, MasterArgs, PutArgs, SessionArgs},
    config::{Paths, Target},
    identity::Baked,
    output::{self, EXIT_TIMEOUT, Mode, code_for, codes},
};

use self::{
    conn::{Connection, connect},
    console::Console,
    ctl::CtlServer,
    forward::Forwards,
    meta::{Ctx, History, Outcome},
    session::{Event, Stack},
    shared::Shared,
    terminal::{Input, Terminal},
};

/// Exit code when the connection drops or the ping timer fires.
pub const EXIT_LOST: i32 = 255;

/// What `mysh HOST …` was asked to do once connected.
#[derive(Debug, Clone)]
pub enum ClientCommand {
    /// Bare `mysh HOST [CMD]`; `-s`/`-N`/`-t` come from the [`Target`].
    Connect {
        command: Vec<String>,
    },
    Put(PutArgs),
    Get(GetArgs),
    /// `mysh HOST cat|write|tail|stat|mkdir|rm|mv|realpath|hash|sync …`.
    File(FileCmd),
    Forward(ForwardCliArgs),
    Authorize(AuthorizeArgs),
    /// `mysh HOST session …`: the remote process API.
    Session(SessionArgs),
    /// `mysh master HOST` / `mysh -M HOST`: hold the connection open.
    Master(MasterArgs),
}

/// Connect and run `cmd` with the output `mode`; returns the process exit
/// code. Errors are local usage, authentication or trust failures (the
/// caller maps them to 2).
#[allow(clippy::needless_pass_by_value)] // by-value per the crate contract; `run` is the end of their life
pub async fn run(
    target: Target,
    cmd: ClientCommand,
    paths: Paths,
    baked: Baked,
    mode: Mode,
) -> Result<i32> {
    let console = Console::with_mode(mode);
    let conn = connect(&target, &paths, &baked, &console).await?;
    let forwards = Forwards::new(conn.clone(), console.clone());
    let result = match add_cli_forwards(&forwards, &target).await {
        Ok(()) => dispatch(&conn, &console, &target, &paths, &forwards, cmd).await,
        Err(e) => Err(e),
    };
    shutdown(&conn, &forwards, &console).await;
    result
}

async fn dispatch(
    conn: &Connection,
    console: &Console,
    target: &Target,
    paths: &Paths,
    forwards: &Forwards,
    cmd: ClientCommand,
) -> Result<i32> {
    let local_cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    let code = match cmd {
        ClientCommand::Put(args) => {
            one_shot(
                console,
                target.timeout,
                files::put_with_input(
                    conn,
                    console,
                    &args,
                    None,
                    &local_cwd,
                    Some(fileops::Input::Process),
                ),
            )
            .await
        }
        ClientCommand::File(mut cmd) => {
            if let FileCmd::Tail(tail) = &mut cmd {
                // `tail -f` ends on its own deadline (clean exit, not 124).
                tail.timeout = tail.timeout.or(target.timeout);
            }
            let fut = fileops::run(
                conn,
                console,
                &cmd,
                None,
                &local_cwd,
                Some(fileops::Input::Process),
            );
            if cmd.follows() {
                until_interrupted(console, fut).await
            } else {
                one_shot(console, target.timeout, fut).await
            }
        }
        ClientCommand::Get(args) => {
            one_shot(
                console,
                target.timeout,
                files::get(conn, console, &args, None, &local_cwd),
            )
            .await
        }
        ClientCommand::Authorize(args) => {
            let line = meta::pubkey_line(conn, args.pubkey.as_deref(), &home_dir(), &local_cwd)?;
            one_shot(console, None, files::authorize(conn, console, &line)).await
        }
        ClientCommand::Session(args) => {
            // `session send --stdin` reads this process's stdin itself.
            match session_api::run(conn, console, &args, None).await {
                Ok(code) => code,
                Err(e) => {
                    console.error(&e);
                    1
                }
            }
        }
        ClientCommand::Master(args) => {
            master::serve(conn, console, target, paths, forwards.clone(), &args).await?
        }
        ClientCommand::Forward(ForwardCliArgs {}) => wait_mode(conn, console).await,
        ClientCommand::Connect { command } if !command.is_empty() => {
            exec_mode(conn, console, target, paths, forwards.clone(), command).await?
        }
        ClientCommand::Connect { .. } if target.no_session => wait_mode(conn, console).await,
        ClientCommand::Connect { .. } if target.attach.is_some() => {
            if !(mysh_pty::terminal::is_terminal(std::io::stdin()) && console.is_tty()) {
                anyhow::bail!("--attach needs a terminal");
            }
            if !attach::supported(conn) {
                anyhow::bail!(
                    "the server does not keep detached sessions (persistence is off); nothing to attach"
                );
            }
            // Nothing (or too much) to attach is an ordinary failure (1), not
            // a usage error: pick the session before entering the terminal.
            let rows = attach::list(conn).await?;
            match attach::choose(&rows, target.attach.flatten()) {
                Ok(id) => {
                    let initial = Some(Initial::Attach(id));
                    interactive(conn, console, target, paths, forwards.clone(), initial).await?
                }
                Err(e) => {
                    console.error(&e);
                    1
                }
            }
        }
        ClientCommand::Connect { .. } => {
            let initial = target.shell.then_some(Initial::Session(SessionKind::Shell));
            interactive(conn, console, target, paths, forwards.clone(), initial).await?
        }
    };
    Ok(code)
}

/// Stop the forwards, flush, and close the connection (bounded to 3 s).
pub(crate) async fn shutdown(conn: &Connection, forwards: &Forwards, console: &Console) {
    forwards.shutdown().await;
    console.flush().await;
    if tokio::time::timeout(Duration::from_secs(3), conn.close())
        .await
        .is_err()
    {
        debug!("connection close timed out");
    }
    console.flush().await;
}

async fn add_cli_forwards(forwards: &Forwards, target: &Target) -> Result<()> {
    for spec in &target.local {
        forwards
            .add_local(spec)
            .await
            .with_context(|| format!("-L {}:{}", spec.bind, spec.port))?;
    }
    for spec in &target.remote {
        forwards
            .add_remote(spec)
            .await
            .with_context(|| format!("-R {}:{}", spec.bind, spec.port))?;
    }
    for spec in &target.dynamic {
        forwards
            .add_dynamic(spec)
            .await
            .with_context(|| format!("-D {}:{}", spec.bind, spec.port))?;
    }
    Ok(())
}

/// Run one file/authorize operation within the target's `--timeout`;
/// failures print and exit 1 (124 after a timeout).
async fn one_shot(
    console: &Console,
    limit: Option<Duration>,
    fut: impl Future<Output = Result<()>>,
) -> i32 {
    match meta::bounded(limit, fut).await {
        Ok(()) => 0,
        Err(e) => {
            console.error(&e);
            if code_for(&e) == codes::TIMEOUT {
                EXIT_TIMEOUT
            } else {
                1
            }
        }
    }
}

/// Run an open-ended operation (`tail -f`, which bounds itself with its
/// own `--timeout`) until it ends or SIGINT/SIGTERM arrives; a signal is a
/// clean exit (0), not a failure. Dropping the future closes its stream.
async fn until_interrupted(console: &Console, fut: impl Future<Output = Result<()>>) -> i32 {
    let (Ok(mut sigint), Ok(mut sigterm)) = (
        signal(SignalKind::interrupt()),
        signal(SignalKind::terminate()),
    ) else {
        warn!("cannot install signal handlers; Ctrl-C will not end cleanly");
        return one_shot(console, None, fut).await;
    };
    tokio::select! {
        r = fut => match r {
            Ok(()) => 0,
            Err(e) => {
                console.error(&e);
                1
            }
        },
        _ = sigint.recv() => 0,
        _ = sigterm.recv() => 0,
    }
}

pub(crate) fn home_dir() -> PathBuf {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .or_else(dirs::home_dir)
        .unwrap_or_else(|| PathBuf::from("/"))
}

fn banner(conn: &Connection) -> String {
    format!(
        "connected to {} ({}, trusted via {}); type \"shell\" for a shell, \"help\" for commands",
        conn.target().display,
        conn.remote_key().fingerprint(),
        conn.trusted_via()
    )
}

/// `-N` / `mysh forward`: nothing to do but hold the connection.
async fn wait_mode(conn: &Connection, console: &Console) -> i32 {
    let (Ok(mut sigint), Ok(mut sigterm)) = (
        signal(SignalKind::interrupt()),
        signal(SignalKind::terminate()),
    ) else {
        warn!("cannot install signal handlers; waiting for the connection to end");
        conn.closed().await;
        return EXIT_LOST;
    };
    tokio::select! {
        _ = sigint.recv() => 0,
        _ = sigterm.recv() => 0,
        () = conn.closed() => {
            console.notice(&format!("connection closed: {}", conn.close_reason().unwrap_or_default()));
            EXIT_LOST
        }
    }
}

/// `mysh HOST CMD...`: one exec session, no prompt. A PTY only with `-t`
/// (and only when the local terminal can provide one). `--timeout` sends
/// TERM then KILL and exits 124; `--cwd` sets the working directory.
async fn exec_mode(
    conn: &Connection,
    console: &Console,
    target: &Target,
    paths: &Paths,
    forwards: Forwards,
    command: Vec<String>,
) -> Result<i32> {
    let tty = mysh_pty::terminal::is_terminal(std::io::stdin())
        && console.is_tty()
        && console.mode() == Mode::Human;
    if target.force_pty && !target.no_pty {
        if tty {
            let initial = Initial::Session(SessionKind::Exec { argv: command });
            return interactive(conn, console, target, paths, forwards, Some(initial)).await;
        }
        console.notice("pseudo-terminal will not be allocated because stdin is not a terminal");
    }
    let (mut stack, mut events) = Stack::new(console.clone());
    let label = meta::kind_label(&command);
    let req = meta::session_request(
        target,
        SessionKind::Exec { argv: command },
        None,
        target.cwd.clone(),
    );
    let started = std::time::Instant::now();
    let id = stack.open_session(conn, req, &label).await?;
    if let Some(s) = stack.get(id) {
        console.event(&output::Event::Started {
            session: id,
            pid: s.pid,
        });
    }
    stack.set_primary(id);
    stack.foreground(id, None)?;
    let mut term = Terminal::cooked(console)?;
    let mut sigint = signal(SignalKind::interrupt()).context("SIGINT handler")?;
    let mut sigterm = signal(SignalKind::terminate()).context("SIGTERM handler")?;
    let mut deadline = meta::ExecTimeout::new(target.timeout);
    loop {
        tokio::select! {
            inp = term.next() => match inp {
                Some(Input::Bytes(b)) => {
                    let _ = stack.send_stdin(id, &b);
                }
                Some(Input::Eof) | None => {
                    let _ = stack.stdin_eof(id);
                }
                Some(Input::MetaKey | Input::Winch) => {}
            },
            ev = events.recv() => {
                let Some(ev) = ev else { return Ok(EXIT_LOST) };
                stack.apply(&ev, false);
                match ev {
                    Event::Exited { status, .. } => {
                        return Ok(meta::finish_exec(console, Some(status), started, deadline.fired));
                    }
                    Event::Lost { .. } => {
                        console.notice("connection lost");
                        return Ok(EXIT_LOST);
                    }
                }
            }
            () = deadline.due() => match deadline.fire() {
                meta::TimeoutStep::Signal(sig) => {
                    let _ = stack.signal(id, sig);
                }
                meta::TimeoutStep::Abandon => {
                    return Ok(meta::finish_exec(console, None, started, true));
                }
            },
            _ = sigint.recv() => {
                let _ = stack.signal(id, mysh_proto::session::Signal::Int);
            }
            _ = sigterm.recv() => {
                let _ = stack.signal(id, mysh_proto::session::Signal::Term);
            }
            () = conn.closed() => {
                console.notice("connection lost");
                return Ok(EXIT_LOST);
            }
        }
    }
}

enum State {
    Prompt,
    Fg(u32),
}

enum FgEnd {
    /// Meta key: back to the prompt.
    Meta,
    /// The foreground session exited.
    Exited,
    /// The connection is gone.
    Lost,
}

/// What `interactive` foregrounds before showing the prompt.
#[derive(Debug, Clone)]
enum Initial {
    /// `-s` / `-t CMD`: open this session.
    Session(SessionKind),
    /// `--attach[=ID]`: reattach this detached session (already chosen).
    Attach(u32),
}

/// Prompt mode (`mysh HOST`), `-s`, `-t CMD` and `--attach`. Scripted when
/// stdin is not a terminal.
async fn interactive(
    conn: &Connection,
    console: &Console,
    target: &Target,
    paths: &Paths,
    forwards: Forwards,
    initial: Option<Initial>,
) -> Result<i32> {
    let stdin_tty = mysh_pty::terminal::is_terminal(std::io::stdin());
    let shared = Shared::new(conn.clone(), console.clone(), forwards, home_dir());
    let local_cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    let mut ctx = Ctx::new(shared, console.clone(), local_cwd, initial.is_some());
    // `--json`/`--json-stream` never run the line editor: the input is a
    // script even on a terminal.
    if !(stdin_tty && console.is_tty() && !console.mode().is_json()) {
        if initial.is_some() {
            console.notice("stdin is not a terminal; reading prompt commands from it");
            ctx.auto_exit = false;
        }
        return meta::run_script(&mut ctx).await;
    }
    ctx.history = History::load(&paths.history);
    let mut term = Terminal::new(console, target.meta_key).context("entering raw mode")?;
    if !target.quiet && console.mode() == Mode::Human {
        console.println(&banner(conn));
    }
    // The control socket lives as long as the prompt; `Drop` removes it.
    let ctl = if target.no_ctl {
        None
    } else {
        CtlServer::start(paths, target, Arc::clone(&ctx.shared)).await
    };
    // SIGTERM: end the connection so both loops unwind and the terminal is
    // restored by the `Terminal` guard.
    if let Ok(mut sigterm) = signal(SignalKind::terminate()) {
        let conn = conn.clone();
        tokio::spawn(async move {
            if sigterm.recv().await.is_some() {
                conn.close().await;
            }
        });
    }
    let state = match initial {
        Some(initial) => open_initial(&mut ctx, &term, target, initial).await?,
        None => State::Prompt,
    };
    let code = main_loop(&mut ctx, &mut term, state).await;
    drop(ctl);
    console.set_prompt_hook(None);
    if let Err(e) = ctx.history.save() {
        debug!(error = %e, path = %paths.history.display(), "history not saved");
    }
    drop(term);
    Ok(code)
}

/// `-s` / `-t CMD` / `--attach`: the primary session, foregrounded before
/// the loop. An attached session is foregrounded with the terminal size so
/// the server gets `Resize` right after `Attached`.
async fn open_initial(
    ctx: &mut Ctx,
    term: &Terminal,
    target: &Target,
    initial: Initial,
) -> Result<State> {
    let id = match initial {
        Initial::Session(kind) => {
            let label = match &kind {
                SessionKind::Shell => meta::kind_label(&[]),
                SessionKind::Exec { argv } => meta::kind_label(argv),
            };
            let req = meta::session_request(target, kind, Some(term.winsize()), None);
            let id = ctx
                .stack
                .open_session(&ctx.shared.conn, req, &label)
                .await?;
            ctx.stack.set_primary(id);
            ctx.stack.foreground(id, None)?;
            id
        }
        Initial::Attach(id) => {
            let id = attach::attach(&ctx.shared.conn, &mut ctx.stack, Some(id)).await?;
            ctx.stack.set_primary(id);
            ctx.stack.foreground(id, Some(term.winsize()))?;
            id
        }
    };
    Ok(State::Fg(id))
}

/// Alternate between the prompt and the foreground session until the
/// client should exit; returns the exit code.
async fn main_loop(ctx: &mut Ctx, term: &mut Terminal, mut state: State) -> i32 {
    loop {
        if ctx.shared.conn.is_closed() {
            return lost(ctx);
        }
        match state {
            State::Prompt => match meta::run_prompt(ctx, term).await {
                Outcome::Foreground(id) => match ctx.stack.foreground(id, Some(term.winsize())) {
                    Ok(()) => state = State::Fg(id),
                    Err(e) => ctx.console.println(&format!("error: {e:#}")),
                },
                Outcome::Exit => return exit_code(ctx),
                Outcome::Disconnect => {
                    return if ctx.shared.conn.is_closed() {
                        lost(ctx)
                    } else {
                        exit_code(ctx)
                    };
                }
            },
            State::Fg(id) => match drive_foreground(ctx, term, id).await {
                FgEnd::Meta => {
                    ctx.stack.background();
                    ctx.console.print("\r\n");
                    state = State::Prompt;
                }
                FgEnd::Exited => {
                    if ctx.auto_exit && ctx.stack.is_empty() {
                        return exit_code(ctx);
                    }
                    state = State::Prompt;
                }
                FgEnd::Lost => return lost(ctx),
            },
        }
    }
}

fn lost(ctx: &Ctx) -> i32 {
    ctx.console.notice(&format!(
        "connection closed: {}",
        ctx.shared.conn.close_reason().unwrap_or_default()
    ));
    EXIT_LOST
}

/// Exit code at a clean exit: the primary session's status in auto-exit
/// mode, else 0.
fn exit_code(ctx: &Ctx) -> i32 {
    if ctx.auto_exit {
        ctx.stack.primary_status().map_or(0, ExitStatus::shell_code)
    } else {
        0
    }
}

/// Terminal ↔ foreground session until the meta key, the session's exit,
/// or connection loss.
async fn drive_foreground(ctx: &mut Ctx, term: &mut Terminal, id: u32) -> FgEnd {
    loop {
        tokio::select! {
            inp = term.next() => match inp {
                Some(Input::Bytes(b)) => {
                    let _ = ctx.stack.send_stdin(id, &b);
                }
                Some(Input::MetaKey) => return FgEnd::Meta,
                Some(Input::Winch) => {
                    let _ = ctx.stack.resize(id, term.winsize());
                }
                Some(Input::Eof) | None => {
                    let _ = ctx.stack.stdin_eof(id);
                }
            },
            ev = ctx.events.recv() => {
                let Some(ev) = ev else { return FgEnd::Lost };
                let mine = matches!(ev, Event::Exited { id: eid, .. } | Event::Lost { id: eid } if eid == id);
                ctx.stack.apply(&ev, true);
                ctx.sync_sessions();
                if mine {
                    return FgEnd::Exited;
                }
            }
            () = ctx.shared.conn.closed() => return FgEnd::Lost,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shell_code_mapping() {
        assert_eq!(ExitStatus::Code(0).shell_code(), 0);
        assert_eq!(ExitStatus::Code(3).shell_code(), 3);
        assert_eq!(
            ExitStatus::Signal {
                signal: 9,
                core_dumped: false
            }
            .shell_code(),
            137
        );
        assert_eq!(EXIT_LOST, 255);
    }

    #[test]
    fn primary_status_maps_to_exit_code() {
        assert_eq!(None.map_or(0, ExitStatus::shell_code), 0);
        assert_eq!(
            Some(ExitStatus::Code(7)).map_or(0, ExitStatus::shell_code),
            7
        );
    }
}
