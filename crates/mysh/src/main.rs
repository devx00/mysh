//! `mysh` entry point: argument dispatch, logging, and exit codes. Everything
//! else lives in the library crate so integration tests can drive it.
//!
//! Exit codes: the client returns its own (docs/04-sessions.md "Exit codes");
//! usage, config, and identity errors are 2; server failures are 1.

use std::process::ExitCode;

use anyhow::{Context as _, Result, bail};
use mysh::cli::{Cli, Command, ConnectArgs, ConnectOpts};
use mysh::client::ClientCommand;
use mysh::config::{Config, Paths, Target, resolve_target};
use mysh::identity::{self, Baked};
use tracing_subscriber::EnvFilter;

/// Exit code for usage, configuration, and identity errors.
const EXIT_USAGE: u8 = 2;
/// Exit code for server failures.
const EXIT_SERVE: u8 = 1;

fn main() -> ExitCode {
    let cli = mysh::cli::parse();
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
        .with_target(verbose >= 2)
        .init();
}

/// Print an anyhow chain as `mysh: error: …` and return `code`.
fn fail(err: &anyhow::Error, code: u8) -> ExitCode {
    eprintln!("mysh: error: {err:#}");
    ExitCode::from(code)
}

async fn run(cli: Cli) -> ExitCode {
    let paths = Paths::from_env();
    let config = match Config::load(&paths.config_file) {
        Ok(c) => c,
        Err(e) => {
            return fail(
                &anyhow::Error::from(e)
                    .context(format!("loading config {}", paths.config_file.display())),
                EXIT_USAGE,
            );
        }
    };
    let baked = match identity::baked() {
        Ok(b) => b,
        Err(e) => return fail(&e, EXIT_USAGE),
    };

    match cli.command {
        Some(Command::Serve(args)) => match mysh::server::serve(args, paths).await {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => fail(&e, EXIT_SERVE),
        },
        Some(Command::Keygen(args)) => match identity::keygen(&args, &paths) {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => fail(&e, EXIT_USAGE),
        },
        Some(Command::Fingerprint(args)) => match identity::fingerprint(&args) {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => fail(&e, EXIT_USAGE),
        },
        other => match client_request(other, cli.connect) {
            Ok((host, opts, cmd)) => client(&host, &opts, &config, cmd, paths, baked).await,
            Err(e) => fail(&e, EXIT_USAGE),
        },
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
        Some(Command::Authorize(h)) => Ok((h.host, h.opts, ClientCommand::Authorize(h.args))),
        Some(Command::Forward(h)) => {
            if h.opts.local.is_empty() && h.opts.remote.is_empty() && h.opts.dynamic.is_empty() {
                bail!("mysh forward needs at least one of -L, -R, or -D");
            }
            Ok((h.host, h.opts, ClientCommand::Forward(h.args)))
        }
        Some(Command::Serve(_) | Command::Keygen(_) | Command::Fingerprint(_)) => {
            bail!("internal error: non-client command reached client dispatch")
        }
    }
}

/// Resolve `host` against the config and run the client command.
async fn client(
    host: &str,
    opts: &ConnectOpts,
    config: &Config,
    cmd: ClientCommand,
    paths: Paths,
    baked: Baked,
) -> ExitCode {
    let mut target = match resolve(host, opts, config) {
        Ok(t) => t,
        Err(e) => return fail(&e, EXIT_USAGE),
    };
    if matches!(cmd, ClientCommand::Forward(_)) {
        // `mysh forward` is `connect -N` with forwards.
        target.no_session = true;
    }
    match mysh::client::run(target, cmd, paths, baked).await {
        Ok(code) => ExitCode::from(u8::try_from(code).unwrap_or(255)),
        Err(e) => fail(&e, EXIT_USAGE),
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
