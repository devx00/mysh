//! `mysh` entry point: argument dispatch, logging, and exit codes. Everything
//! else lives in the library crate so integration tests can drive it.
//!
//! Exit codes: the client returns its own (docs/04-sessions.md "Exit codes");
//! usage, config, and identity errors are 2; server failures are 1.

use std::process::ExitCode;

use anyhow::{Context as _, Result, bail};
use mysh::cli::{Cli, Command, ConnectArgs, ConnectOpts, FileCmd};
use mysh::client::ClientCommand;
use mysh::config::{Config, Paths, Target, resolve_target};
use mysh::identity::{self, Baked};
use mysh::output::{ErrorOut, Mode, code_for, codes};
use tracing_subscriber::EnvFilter;

/// Exit code for usage, configuration, and identity errors.
const EXIT_USAGE: u8 = 2;
/// Exit code for server failures.
const EXIT_SERVE: u8 = 1;

fn main() -> ExitCode {
    let cli = match mysh::cli::try_parse_from(std::env::args_os()) {
        Ok(cli) => cli,
        Err(e) => return usage_failure(&e),
    };
    init_logging(cli.verbose);
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            return fail(
                &anyhow::Error::from(e).context("starting runtime"),
                EXIT_SERVE,
                Mode::Human,
            );
        }
    };
    let code = runtime.block_on(run(cli));
    // Dropping the runtime would wait for blocking tasks; the client's stdin
    // reader sits in a blocking `read(2)` until the next keypress. Output has
    // been flushed by the client before `run` returns.
    runtime.shutdown_background();
    code
}

/// `RUST_LOG` wins; otherwise `-v` levels apply to the mysh crates only.
/// Colours only when stderr is a terminal (logs are read by scripts and
/// tests otherwise, e.g. the pairing code after `SIGUSR1`).
fn init_logging(verbose: u8) {
    let level = match verbose {
        0 => None,
        1 => Some("info"),
        2 => Some("debug"),
        _ => Some("trace"),
    };
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| {
        let directives = level.map_or_else(
            || "warn".to_owned(),
            |l| format!("warn,mysh={l},mysh_net={l},mysh_pty={l},mysh_proto={l}"),
        );
        EnvFilter::new(directives)
    });
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .with_ansi(mysh_pty::terminal::is_terminal(std::io::stderr()))
        .with_target(verbose >= 2)
        .init();
}

/// A clap parse failure: clap's own diagnostics (and exit code 0 for
/// `--help`/`--version`), or a `usage` [`ErrorOut`] when the command line
/// asked for JSON.
fn usage_failure(err: &clap::Error) -> ExitCode {
    use clap::error::ErrorKind;
    let wants_json = std::env::args_os()
        .skip(1)
        .any(|a| a == "--json" || a == "--json-stream");
    if !wants_json
        || matches!(
            err.kind(),
            ErrorKind::DisplayHelp | ErrorKind::DisplayVersion
        )
    {
        err.exit();
    }
    let message = err.render().to_string();
    eprintln!(
        "{}",
        ErrorOut::new(codes::USAGE, message.trim_end()).to_line()
    );
    ExitCode::from(EXIT_USAGE)
}

/// Print an anyhow chain as `mysh: error: …` (an [`ErrorOut`] line in the
/// JSON modes) and return `code`. An unclassified error that exits with
/// the usage code reports `usage`.
fn fail(err: &anyhow::Error, code: u8, mode: Mode) -> ExitCode {
    if mode.is_json() {
        let mut out = ErrorOut::from_error(err);
        if out.error.code == codes::INTERNAL && code == EXIT_USAGE {
            codes::USAGE.clone_into(&mut out.error.code);
        }
        eprintln!("{}", out.to_line());
    } else {
        eprintln!("mysh: error: {err:#}");
    }
    ExitCode::from(code)
}

/// The output mode the connection options ask for.
fn mode_for(opts: &ConnectOpts) -> Mode {
    let stdout_tty = mysh_pty::terminal::is_terminal(std::io::stdout());
    Mode::select(opts.json, opts.json_stream, opts.plain, stdout_tty)
}

/// The output mode of one command line: the connection options of a host
/// command, the explicit `--json` of the others, else human.
fn output_mode(cli: &Cli) -> Mode {
    match &cli.command {
        Some(Command::Put(h)) => mode_for(&h.opts),
        Some(Command::Get(h)) => mode_for(&h.opts),
        Some(Command::Cat(h)) => mode_for(&h.opts),
        Some(Command::Write(h)) => mode_for(&h.opts),
        Some(Command::Tail(h)) => mode_for(&h.opts),
        Some(Command::Stat(h)) => mode_for(&h.opts),
        Some(Command::Mkdir(h)) => mode_for(&h.opts),
        Some(Command::Rm(h)) => mode_for(&h.opts),
        Some(Command::Mv(h)) => mode_for(&h.opts),
        Some(Command::Realpath(h)) => mode_for(&h.opts),
        Some(Command::Hash(h)) => mode_for(&h.opts),
        Some(Command::Sync(h)) => mode_for(&h.opts),
        Some(Command::Forward(h)) => mode_for(&h.opts),
        Some(Command::Authorize(h)) => mode_for(&h.opts),
        Some(Command::Connect(args)) => mode_for(&args.opts),
        Some(Command::Session(h)) => mode_for(&h.opts),
        Some(Command::Master(h)) => mode_for(&h.opts),
        Some(Command::Pair(h)) => mode_for(&h.opts),
        Some(Command::Bind(h)) => mode_for(&h.opts),
        // `accept` reports one event per connection, as NDJSON with
        // `--json`.
        Some(Command::Accept(args)) if args.json => Mode::JsonStream,
        Some(Command::Run(args)) => mode_for(&args.opts),
        None => mode_for(&cli.connect.opts),
        Some(Command::Help(args)) if args.json => Mode::Json,
        Some(Command::Assets(args)) if args.json => Mode::Json,
        Some(Command::Skill(args))
            if matches!(
                args.command,
                mysh::skill::SkillCommand::Install { json: true, .. }
                    | mysh::skill::SkillCommand::List { json: true }
            ) =>
        {
            Mode::Json
        }
        Some(_) => Mode::Human,
    }
}

async fn run(cli: Cli) -> ExitCode {
    // The connect options are parsed for every command; a subcommand that
    // takes no HOST leaves them at their defaults (human/plain).
    let mode = output_mode(&cli);
    if let Some(Command::Help(args)) = &cli.command {
        return match mysh::cli::help_text(args) {
            Ok(text) => {
                print!("{text}");
                ExitCode::SUCCESS
            }
            Err(e) => fail(&anyhow::anyhow!(e), EXIT_USAGE, mode),
        };
    }
    let paths = Paths::from_env();
    let config = match Config::load(&paths.config_file) {
        Ok(c) => c,
        Err(e) => {
            return fail(
                &anyhow::Error::from(e)
                    .context(format!("loading config {}", paths.config_file.display())),
                EXIT_USAGE,
                mode,
            );
        }
    };
    let baked = match identity::baked() {
        Ok(b) => b,
        Err(e) => return fail(&e, EXIT_USAGE, mode),
    };

    match cli.command {
        Some(Command::Serve(args)) if args.detach.daemon => {
            detach(&args.detach, &paths, "serve", mode)
        }
        Some(Command::Serve(args)) => match mysh::server::serve(args, paths).await {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => fail(&e, EXIT_SERVE, mode),
        },
        Some(Command::Keygen(args)) => match identity::keygen(&args, &paths) {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => fail(&e, EXIT_USAGE, mode),
        },
        Some(Command::Fingerprint(args)) => match identity::fingerprint(&args) {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => fail(&e, EXIT_USAGE, mode),
        },
        Some(Command::Pair(h)) => pair(&h, &config, &paths, &baked, mode).await,
        Some(Command::Accept(args)) if args.detach.daemon => {
            detach(&args.detach, &paths, "accept", mode)
        }
        Some(Command::Accept(args)) => exit_code(
            mysh::client::accept::run(&args, &paths, &baked, mode).await,
            mode,
        ),
        Some(Command::Run(args)) => exit_code(
            mysh::client::fleet::run(args, &config, paths, baked, mode).await,
            mode,
        ),
        Some(Command::Mcp(args)) => match mysh::mcp::serve(args, &config, paths, baked).await {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => fail(&e, EXIT_USAGE, mode),
        },
        Some(Command::Assets(args)) => {
            let console = mysh::client::console::Console::with_mode(mode);
            match mysh::assets::run(&args, &config, &paths, &console).await {
                Ok(code) => ExitCode::from(u8::try_from(code).unwrap_or(255)),
                Err(e) => fail(&e, 1, mode),
            }
        }
        Some(Command::Skill(args)) => {
            let console = mysh::client::console::Console::with_mode(mode);
            match mysh::skill::run(&args, &console).await {
                Ok(code) => ExitCode::from(u8::try_from(code).unwrap_or(255)),
                Err(e) => fail(&e, 1, mode),
            }
        }
        // `--hosts`/`--group`: HOST's slot holds the first PATH.
        Some(Command::Put(h)) if h.opts.fan_out() => {
            let mut args = h.args;
            args.paths.insert(0, h.host);
            exit_code(
                mysh::client::fleet::put(&h.opts, &args, &config, paths, baked, mode).await,
                mode,
            )
        }
        Some(Command::Get(h)) if h.opts.fan_out() => {
            let mut args = h.args;
            args.paths.insert(0, h.host);
            exit_code(
                mysh::client::fleet::get(&h.opts, &args, &config, paths, baked, mode).await,
                mode,
            )
        }
        other => match client_request(other, cli.connect) {
            Ok((host, opts, cmd)) => {
                Box::pin(client(&host, &opts, &config, cmd, paths, baked, mode)).await
            }
            Err(e) => fail(&e, EXIT_USAGE, mode),
        },
    }
}

/// `--daemon`: re-exec detached, wait for readiness, report the pid and
/// log path (`{"pid","log"}` in a JSON mode), exit.
fn detach(args: &mysh::daemon::DaemonArgs, paths: &Paths, command: &str, mode: Mode) -> ExitCode {
    let default_log = mysh::daemon::default_log(&paths.history, command);
    match mysh::daemon::spawn(args, &default_log) {
        Ok(started) => {
            if mode.is_json() {
                println!(
                    "{}",
                    serde_json::to_string(&started).unwrap_or_else(|_| "{}".to_owned())
                );
            } else {
                println!(
                    "mysh {command}: started, pid {}, log {}",
                    started.pid,
                    started.log.display()
                );
            }
            ExitCode::SUCCESS
        }
        Err(e) => fail(&e, EXIT_SERVE, mode),
    }
}

/// Exit code of a command that returns one: the command's, or usage (2)
/// for a failure before it could run.
fn exit_code(result: Result<i32>, mode: Mode) -> ExitCode {
    match result {
        Ok(code) => ExitCode::from(u8::try_from(code).unwrap_or(255)),
        Err(e) => fail(&e, EXIT_USAGE, mode),
    }
}

/// `mysh pair HOST CODE`: its own connection path (unverified server key,
/// pairing-only), never the control socket.
async fn pair(
    h: &mysh::cli::HostAnd<mysh::cli::PairArgs>,
    config: &Config,
    paths: &Paths,
    baked: &Baked,
    mode: Mode,
) -> ExitCode {
    let target = match resolve(&h.host, &h.opts, config) {
        Ok(t) => t,
        Err(e) => return fail(&e, EXIT_USAGE, mode),
    };
    match mysh::client::pair::run(&target, &h.args.code(), paths, baked, mode).await {
        Ok(code) => ExitCode::from(u8::try_from(code).unwrap_or(255)),
        Err(e) => fail(&e, EXIT_USAGE, mode),
    }
}

/// `(HOST, connection options, client command)`.
type ClientRequest = (String, ConnectOpts, ClientCommand);

/// Split a host-taking command into a [`ClientRequest`].
/// `Serve`/`Keygen`/`Fingerprint` are handled before this.
fn client_request(command: Option<Command>, bare: ConnectArgs) -> Result<ClientRequest> {
    let connect = |args: ConnectArgs| -> Result<ClientRequest> {
        let host = args.host.ok_or_else(|| anyhow::anyhow!("missing HOST"))?;
        let cmd = ClientCommand::Connect {
            command: args.command,
        };
        Ok((host, args.opts, cmd))
    };
    match command {
        None => connect(bare),
        Some(Command::Connect(args)) => connect(args),
        Some(Command::Put(h)) => Ok((h.host, h.opts, ClientCommand::Put(h.args))),
        Some(Command::Get(h)) => Ok((h.host, h.opts, ClientCommand::Get(h.args))),
        Some(Command::Cat(h)) => Ok((h.host, h.opts, ClientCommand::File(FileCmd::Cat(h.args)))),
        Some(Command::Write(h)) => {
            Ok((h.host, h.opts, ClientCommand::File(FileCmd::Write(h.args))))
        }
        Some(Command::Tail(h)) => Ok((h.host, h.opts, ClientCommand::File(FileCmd::Tail(h.args)))),
        Some(Command::Stat(h)) => Ok((h.host, h.opts, ClientCommand::File(FileCmd::Stat(h.args)))),
        Some(Command::Mkdir(h)) => {
            Ok((h.host, h.opts, ClientCommand::File(FileCmd::Mkdir(h.args))))
        }
        Some(Command::Rm(h)) => Ok((h.host, h.opts, ClientCommand::File(FileCmd::Rm(h.args)))),
        Some(Command::Mv(h)) => Ok((h.host, h.opts, ClientCommand::File(FileCmd::Mv(h.args)))),
        Some(Command::Realpath(h)) => Ok((
            h.host,
            h.opts,
            ClientCommand::File(FileCmd::Realpath(h.args)),
        )),
        Some(Command::Hash(h)) => Ok((h.host, h.opts, ClientCommand::File(FileCmd::Hash(h.args)))),
        Some(Command::Sync(h)) => Ok((h.host, h.opts, ClientCommand::File(FileCmd::Sync(h.args)))),
        Some(Command::Authorize(h)) => Ok((h.host, h.opts, ClientCommand::Authorize(h.args))),
        Some(Command::Bind(h)) => Ok((h.host, h.opts, ClientCommand::Bind(h.args))),
        Some(Command::Session(h)) => Ok((h.host, h.opts, ClientCommand::Session(h.args))),
        Some(Command::Master(h)) => Ok((h.host, h.opts, ClientCommand::Master(h.args))),
        Some(Command::Forward(h)) => {
            if h.opts.local.is_empty() && h.opts.remote.is_empty() && h.opts.dynamic.is_empty() {
                bail!("mysh forward needs at least one of -L, -R, or -D");
            }
            Ok((h.host, h.opts, ClientCommand::Forward(h.args)))
        }
        Some(
            Command::Serve(_)
            | Command::Keygen(_)
            | Command::Fingerprint(_)
            | Command::Help(_)
            | Command::Pair(_)
            | Command::Run(_)
            | Command::Accept(_)
            | Command::Mcp(_)
            | Command::Assets(_)
            | Command::Skill(_),
        ) => {
            bail!("internal error: non-client command reached client dispatch")
        }
    }
}

/// Resolve `host` against the config and run the client command. File,
/// forward, `session` and `exec`/`CMD` calls first try the control socket
/// of a running client or master for the same target (docs/05 "Control
/// socket", "Master mode") unless `--no-ctl`; `master = auto` starts one
/// when the socket is missing.
#[allow(clippy::too_many_arguments)] // one call site; the request is already split into its parts
async fn client(
    host: &str,
    opts: &ConnectOpts,
    config: &Config,
    cmd: ClientCommand,
    paths: Paths,
    baked: Baked,
    mode: Mode,
) -> ExitCode {
    if opts.fan_out() {
        return fail(
            &anyhow::anyhow!("--hosts/--group apply to run, put and get only"),
            EXIT_USAGE,
            mode,
        );
    }
    let mut target = match resolve(host, opts, config) {
        Ok(t) => t,
        Err(e) => return fail(&e, EXIT_USAGE, mode),
    };
    if matches!(cmd, ClientCommand::Forward(_)) {
        // `mysh forward` is `connect -N` with forwards.
        target.no_session = true;
    }
    if let ClientCommand::Master(args) = &cmd
        && args.daemon
    {
        // Re-spawn detached and return once the socket answers (an already
        // running master counts); the child runs `master` without `--daemon`.
        return match mysh::client::master::ensure(&paths, &target, args.idle).await {
            Ok(true) => ExitCode::SUCCESS,
            Ok(false) => fail(
                &anyhow::anyhow!("master for {} did not come up", target.display),
                EXIT_SERVE,
                mode,
            ),
            Err(e) => fail(&e.context("starting the master"), EXIT_SERVE, mode),
        };
    }
    if !target.no_ctl
        && !matches!(cmd, ClientCommand::Master(_))
        && let Some(argv) = ctl_argv(&cmd, opts)
    {
        let console = mysh::client::console::Console::with_mode(mode);
        if target.master.spawns()
            && let Err(e) = mysh::client::master::ensure(&paths, &target, None).await
        {
            if target.master == mysh::config::MasterMode::Always {
                return fail(&e.context("starting the master"), EXIT_SERVE, mode);
            }
            console.notice(&format!("master not started: {e:#}"));
        }
        // Stdin is only read once a socket answers: a fallback to this
        // process's own connection must still see every byte of it.
        if mysh::client::ctl::socket_ready(&paths, &target).await {
            // Only `exec`/`CMD` and `session send --stdin` consume stdin,
            // and only up to the request cap; a larger input runs on a
            // connection of this process's own.
            match ctl_stdin(&cmd).await {
                Err(TooMuchStdin) => {}
                Ok(stdin) => {
                    match mysh::client::ctl::request(&paths, &target, argv, &console, stdin).await {
                        Ok(Some(code)) => {
                            return ExitCode::from(u8::try_from(code).unwrap_or(255));
                        }
                        Ok(None) => {}
                        Err(e) => {
                            return fail(&e.context("control socket request"), EXIT_SERVE, mode);
                        }
                    }
                }
            }
        }
        if target.master == mysh::config::MasterMode::Always {
            return fail(
                &anyhow::anyhow!("no control socket for {}", target.display),
                EXIT_SERVE,
                mode,
            );
        }
    }
    Box::pin(run_client(target, cmd, paths, baked, mode)).await
}

async fn run_client(
    target: Target,
    cmd: ClientCommand,
    paths: Paths,
    baked: Baked,
    mode: Mode,
) -> ExitCode {
    match Box::pin(mysh::client::run(target, cmd, paths, baked, mode)).await {
        Ok(code) => ExitCode::from(u8::try_from(code).unwrap_or(255)),
        Err(e) => {
            let code = if code_for(&e) == codes::TIMEOUT {
                u8::try_from(mysh::output::EXIT_TIMEOUT).unwrap_or(EXIT_USAGE)
            } else {
                EXIT_USAGE
            };
            fail(&e, code, mode)
        }
    }
}

/// Stdin is larger than a control request may carry.
struct TooMuchStdin;

/// Standard input to hand to the serving client, if this command reads any.
async fn ctl_stdin(cmd: &ClientCommand) -> Result<Vec<u8>, TooMuchStdin> {
    let reads_stdin = match cmd {
        ClientCommand::Connect { command } => !command.is_empty(),
        ClientCommand::Session(args) => {
            matches!(&args.cmd, mysh::cli::SessionCmd::Send(send) if send.stdin)
        }
        ClientCommand::Put(args) => args.paths.first().is_some_and(|p| p == "-"),
        ClientCommand::File(cmd) => cmd.reads_stdin(),
        _ => false,
    };
    if !reads_stdin {
        return Ok(Vec::new());
    }
    mysh::client::ctl::read_ctl_stdin()
        .await
        .ok_or(TooMuchStdin)
}

/// The prompt words for a subcommand that can run over the control socket.
fn ctl_argv(cmd: &ClientCommand, opts: &ConnectOpts) -> Option<Vec<String>> {
    match cmd {
        ClientCommand::Put(args) => Some(args.to_argv()),
        ClientCommand::Get(args) => Some(args.to_argv()),
        ClientCommand::Authorize(args) => Some(args.to_argv()),
        ClientCommand::Bind(args) => Some(args.to_argv()),
        ClientCommand::Session(args) => Some(args.to_argv()),
        ClientCommand::File(cmd) => {
            let mut argv = cmd.to_argv();
            // `tail -f` over the socket runs on the serving client: carry
            // this call's `--timeout` along so it still ends by itself.
            if let FileCmd::Tail(tail) = cmd
                && tail.follow
                && tail.timeout.is_none()
                && let Some(limit) = opts.timeout
            {
                argv.insert(1, "--for".to_owned());
                argv.insert(2, format!("{}ms", limit.as_millis()));
            }
            Some(argv)
        }
        ClientCommand::Forward(_) => {
            let mut argv = vec!["forward".to_owned()];
            for (flag, specs) in [
                ("-L", &opts.local),
                ("-R", &opts.remote),
                ("-D", &opts.dynamic),
            ] {
                for s in specs {
                    argv.push(flag.to_owned());
                    argv.push(s.clone());
                }
            }
            Some(argv)
        }
        // `mysh HOST CMD` runs as `exec CMD` on the serving client. A
        // command that needs the local terminal (`-t`, or stdin that is a
        // tty) keeps its own connection.
        ClientCommand::Connect { command } if !command.is_empty() => {
            if opts.force_pty || mysh_pty::terminal::is_terminal(std::io::stdin()) {
                return None;
            }
            let mut argv = vec!["exec".to_owned()];
            if let Some(dir) = &opts.cwd {
                argv.push("--cwd".to_owned());
                argv.push(dir.clone());
            }
            if let Some(limit) = opts.timeout {
                argv.push("--timeout".to_owned());
                argv.push(format!("{}ms", limit.as_millis()));
            }
            argv.push("--".to_owned());
            argv.extend(command.iter().cloned());
            Some(argv)
        }
        ClientCommand::Connect { .. } | ClientCommand::Master(_) => None,
    }
}

fn resolve(host: &str, opts: &ConnectOpts, config: &Config) -> Result<Target> {
    if host.is_empty() {
        bail!("missing HOST");
    }
    resolve_target(host, opts, config)
        .map_err(anyhow::Error::msg)
        .with_context(|| format!("resolving {host}"))
}
