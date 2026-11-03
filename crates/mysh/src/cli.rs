//! Command-line and meta-prompt argument definitions (docs/05-meta-shell.md,
//! "CLI" and "Commands"). Pure parsing: no I/O, no networking.
//!
//! The prompt commands (`put`, `get`, `forward`, `authorize`) share their
//! argument structs with the CLI subcommands of the same name, so one clap
//! definition serves both frontends.

use std::ffi::OsString;
use std::fmt::Write as _;
use std::path::PathBuf;

use clap::{ArgAction, Args, CommandFactory, Parser, Subcommand, ValueEnum};

/// Top-level command line: `mysh [OPTIONS] HOST [-- CMD...]` or a subcommand.
#[derive(Parser, Debug)]
#[command(
    name = "mysh",
    version,
    about,
    long_about = None,
    args_conflicts_with_subcommands = true,
    subcommand_negates_reqs = true,
    arg_required_else_help = true
)]
pub struct Cli {
    /// Increase log verbosity; `-vv` includes handshake and stream events.
    #[arg(short, long, global = true, action = ArgAction::Count)]
    pub verbose: u8,

    #[command(subcommand)]
    pub command: Option<Command>,

    /// Bare `mysh [OPTIONS] HOST [-- CMD...]` form, used when no subcommand
    /// is given.
    #[command(flatten)]
    pub connect: ConnectArgs,
}

/// Subcommands. Their names are reserved words that cannot be used as a bare
/// `HOST`; `mysh connect NAME` is the escape hatch.
#[derive(Subcommand, Debug)]
pub enum Command {
    /// Connect to HOST (same as the bare form; use when HOST collides with a
    /// subcommand name).
    Connect(ConnectArgs),
    /// Run the server.
    Serve(ServeArgs),
    /// Generate a new identity key pair.
    Keygen(KeygenArgs),
    /// Print the fingerprint of a key file (private or public, either format).
    Fingerprint(FingerprintArgs),
    /// Copy local files to HOST.
    Put(HostAnd<PutArgs>),
    /// Copy files from HOST to the local machine.
    Get(HostAnd<GetArgs>),
    /// Connect with forwards only (`connect -N` with `-L/-R/-D`).
    Forward(HostAnd<ForwardCliArgs>),
    /// Append the client's public key to HOST's `authorized_keys`.
    Authorize(HostAnd<AuthorizeArgs>),
}

/// Connection options shared by every HOST-taking command.
#[allow(clippy::struct_excessive_bools)]
#[derive(Args, Clone, Debug, Default)]
pub struct ConnectOpts {
    /// Port (default 7722, or from `HOST:PORT`).
    #[arg(short = 'p', long, value_name = "PORT")]
    pub port: Option<u16>,

    /// Identity: a private key file, or a `.pub` naming an ssh-agent key
    /// (see docs/02-security.md for the resolution order).
    #[arg(short = 'i', long, value_name = "PATH")]
    pub identity: Option<PathBuf>,

    /// Expected server public key or fingerprint.
    #[arg(long, value_name = "KEY")]
    pub pin: Option<String>,

    /// Trust unknown server keys without asking (TOFU: accept new).
    #[arg(long, conflicts_with = "strict")]
    pub accept_new: bool,

    /// Fail when the server key is unknown (TOFU: strict).
    #[arg(long)]
    pub strict: bool,

    /// Run `shell` on connect; exit when the last session ends.
    #[arg(short = 's', long)]
    pub shell: bool,

    /// Force a PTY for CMD.
    #[arg(short = 't', long = "force-pty", conflicts_with = "no_pty")]
    pub force_pty: bool,

    /// Forbid a PTY for CMD.
    #[arg(short = 'T', long = "no-pty")]
    pub no_pty: bool,

    /// No session and no stdin; forwards only (safe to run with `&`).
    #[arg(short = 'N', long = "no-session")]
    pub no_session: bool,

    /// Reattach a detached session (`--attach` picks the only one,
    /// `--attach=ID` a specific one) instead of opening a new one.
    #[arg(
        long,
        value_name = "ID",
        num_args = 0..=1,
        require_equals = true,
        conflicts_with_all = ["shell", "no_session"]
    )]
    pub attach: Option<Option<u32>>,

    /// Local forward `[bind:]port:host:hostport` (repeatable).
    #[arg(short = 'L', long = "local", value_name = "SPEC")]
    pub local: Vec<String>,

    /// Remote forward `[bind:]port:host:hostport` (repeatable).
    #[arg(short = 'R', long = "remote", value_name = "SPEC")]
    pub remote: Vec<String>,

    /// Dynamic (SOCKS) forward `[bind:]port` (repeatable).
    #[arg(short = 'D', long = "dynamic", value_name = "SPEC")]
    pub dynamic: Vec<String>,

    /// Meta key: a single character, caret notation (`^]`), or `none`.
    #[arg(short = 'e', long, value_name = "KEY|none")]
    pub escape: Option<String>,

    /// No connect banner.
    #[arg(short = 'q', long)]
    pub quiet: bool,

    /// Send an environment variable (repeatable; the server must accept it).
    #[arg(long, value_name = "NAME[=VALUE]")]
    pub env: Vec<String>,

    /// Ignore key files on disk; use only the compiled-in identity and peers.
    #[arg(long)]
    pub baked_only: bool,

    /// Do not reuse a running interactive client's control socket for
    /// `put`/`get`/`forward`/`authorize`; always open a new connection.
    #[arg(long = "no-ctl")]
    pub no_ctl: bool,
}

/// `HOST [-- CMD...]` with the shared connection options.
#[derive(Args, Clone, Debug, Default)]
pub struct ConnectArgs {
    #[command(flatten)]
    pub opts: ConnectOpts,

    /// `host`, `host:port`, `[v6addr]:port`, bare `v6addr`, or a config alias.
    #[arg(value_name = "HOST")]
    pub host: Option<String>,

    /// Command to run remotely instead of landing at the prompt.
    #[arg(
        value_name = "CMD",
        trailing_var_arg = true,
        allow_hyphen_values = true,
        num_args = 0..
    )]
    pub command: Vec<String>,
}

/// Connection options plus a required HOST, followed by a command's own
/// arguments.
#[derive(Args, Clone, Debug)]
pub struct HostAnd<T: Args> {
    #[command(flatten)]
    pub opts: ConnectOpts,

    /// `host`, `host:port`, `[v6addr]:port`, bare `v6addr`, or a config alias.
    #[arg(value_name = "HOST")]
    pub host: String,

    #[command(flatten)]
    pub args: T,
}

/// Server features that can be switched off with `--deny`.
#[derive(ValueEnum, Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Feature {
    /// PTY sessions (`shell`).
    Pty,
    /// Non-PTY exec sessions.
    Exec,
    /// File transfer and listing.
    Files,
    /// Local (`-L`) and dynamic (`-D`) forwards.
    ForwardLocal,
    /// Remote (`-R`) forwards.
    ForwardRemote,
}

/// `mysh serve` options.
#[allow(clippy::struct_excessive_bools)] // independent switches, not a state machine
#[derive(Args, Clone, Debug, Default)]
pub struct ServeArgs {
    /// Listen address (repeatable; default `[::]:7722`, falling back to
    /// `0.0.0.0:7722`).
    #[arg(long, value_name = "ADDR")]
    pub listen: Vec<String>,

    /// Host identity key file.
    #[arg(long, value_name = "PATH")]
    pub key: Option<PathBuf>,

    /// Fail instead of generating a host key on first start.
    #[arg(long)]
    pub no_generate_key: bool,

    /// Additional `authorized_keys` file (repeatable).
    #[arg(long, value_name = "PATH")]
    pub authorized_keys: Vec<PathBuf>,

    /// Additional authorized public key line (repeatable).
    #[arg(long, value_name = "KEY")]
    pub authorized_key: Vec<String>,

    /// Do not read `~/.ssh/authorized_keys`.
    #[arg(long)]
    pub no_ssh_authorized_keys: bool,

    /// Override shell resolution for sessions.
    #[arg(long, value_name = "PATH")]
    pub shell: Option<PathBuf>,

    /// Extra environment variable names accepted from clients (repeatable).
    #[arg(long, value_name = "NAME")]
    pub accept_env: Vec<String>,

    /// Disable a feature (repeatable).
    #[arg(long, value_name = "FEATURE", value_enum)]
    pub deny: Vec<Feature>,

    /// Name sent in the server hello (default: hostname).
    #[arg(long, value_name = "NAME")]
    pub name: Option<String>,

    /// Ignore key files on disk; use only the compiled-in identity and peers.
    #[arg(long)]
    pub baked_only: bool,

    /// Handshakes accepted per minute from one client address (0 = no limit).
    #[arg(long, value_name = "N")]
    pub handshake_rate: Option<u32>,

    /// Close a connection with no control traffic for this many seconds.
    #[arg(long, value_name = "SECS")]
    pub idle_timeout: Option<u64>,

    /// Keep a detached PTY session alive for this many seconds.
    #[arg(long, value_name = "SECS")]
    pub detach_grace: Option<u64>,

    /// Do not accept ssh-ed25519 signature authentication.
    #[arg(long)]
    pub no_signature_auth: bool,
}

/// `mysh keygen` options.
#[derive(Args, Clone, Debug, Default)]
pub struct KeygenArgs {
    /// Output path for the private key (public key goes to `PATH.pub`).
    #[arg(short = 'o', long, value_name = "PATH")]
    pub output: Option<PathBuf>,

    /// Comment stored in the public key file.
    #[arg(short = 'C', long, value_name = "COMMENT")]
    pub comment: Option<String>,
}

/// `mysh fingerprint [FILE]`.
#[derive(Args, Clone, Debug, Default)]
pub struct FingerprintArgs {
    /// Key file, private or public, either format; `-` reads stdin.
    #[arg(value_name = "FILE")]
    pub file: Option<PathBuf>,
}

/// `mysh forward HOST` carries its forwards in the shared `-L/-R/-D`
/// connection options; this struct exists so `Command::Forward` has the same
/// `HostAnd<_>` shape as the other host commands.
#[derive(Args, Clone, Debug, Default)]
pub struct ForwardCliArgs {}

/// Parse the process command line, exiting with clap's diagnostics on error.
#[must_use]
pub fn parse() -> Cli {
    Cli::parse()
}

/// Parse an explicit argument list (including the binary name as first item).
pub fn try_parse_from<I, T>(args: I) -> clap::error::Result<Cli>
where
    I: IntoIterator<Item = T>,
    T: Into<OsString> + Clone,
{
    Cli::try_parse_from(args)
}

// ---------------------------------------------------------------------------
// Meta prompt commands
// ---------------------------------------------------------------------------

/// Root of the meta-prompt grammar; one line is one command.
#[derive(Parser, Debug)]
#[command(
    name = "",
    no_binary_name = true,
    disable_help_subcommand = true,
    disable_version_flag = true
)]
pub(crate) struct MetaCli {
    #[command(subcommand)]
    pub(crate) cmd: MetaCommand,
}

/// Commands accepted at the `mysh HOST> ` prompt.
#[derive(Subcommand, Clone, Debug, PartialEq, Eq)]
pub enum MetaCommand {
    /// List commands, or show help for one command.
    Help {
        /// Command name.
        #[arg(value_name = "CMD")]
        cmd: Option<String>,
    },
    /// Start a new interactive PTY session and bring it to the foreground.
    Shell(ShellArgs),
    /// Bring a session to the foreground (default: most recently used).
    Fg {
        /// Session id.
        #[arg(value_name = "ID")]
        id: Option<u32>,
    },
    /// List sessions (`-a`: also the server's detached ones).
    Sessions {
        /// Include sessions detached on the server, attachable with `attach`.
        #[arg(short = 'a', long = "all")]
        all: bool,
    },
    /// Reattach a session detached on the server and foreground it.
    Attach {
        /// Session id (default: the only detached session).
        #[arg(value_name = "ID")]
        id: Option<u32>,
    },
    /// Leave a session running on the server and drop it from the stack.
    Detach {
        /// Session id (default: most recently used).
        #[arg(value_name = "ID")]
        id: Option<u32>,
    },
    /// Send a signal to a session (default: TERM), or cancel a background
    /// job with `%ID`.
    Kill {
        /// Signal name or number.
        #[arg(short = 's', long = "signal", value_name = "SIG")]
        signal: Option<String>,
        /// Session id, or `%ID` for a job.
        #[arg(value_name = "ID")]
        id: String,
    },
    /// Write TEXT to the most recently used session and foreground it.
    /// Caret notation (`^]`, `^C`) and `\xNN` escapes are decoded.
    Send {
        /// Text to send; words are joined with single spaces.
        #[arg(
            value_name = "TEXT",
            required = true,
            trailing_var_arg = true,
            allow_hyphen_values = true,
            num_args = 1..
        )]
        text: Vec<String>,
    },
    /// Copy local files to the remote.
    Put(PutArgs),
    /// Copy remote files to the local machine.
    Get(GetArgs),
    /// List a remote directory.
    Ls(LsArgs),
    /// Print the remote and local working directories.
    Cwd,
    /// Change the client's working directory.
    Lcd {
        /// Directory (default: home).
        #[arg(value_name = "DIR")]
        dir: Option<String>,
    },
    /// Add, list, or remove port forwards.
    Forward(ForwardArgs),
    /// Run a non-PTY command and stream its output here.
    Exec {
        /// Command and arguments.
        #[arg(
            value_name = "CMD",
            required = true,
            trailing_var_arg = true,
            allow_hyphen_values = true,
            num_args = 1..
        )]
        command: Vec<String>,
    },
    /// Show connection information.
    Info,
    /// Measure round-trip time on the control stream.
    Ping {
        /// Number of pings (default: 4).
        #[arg(short = 'c', long = "count", value_name = "N")]
        count: Option<u32>,
    },
    /// Re-send the current terminal size to the most recently used session.
    Resize,
    /// Tee terminal output to FILE from now on; `log off` stops.
    Log {
        /// File path, or `off`.
        #[arg(value_name = "FILE|off")]
        target: String,
    },
    /// Append the client's public key to the remote `authorized_keys`.
    Authorize(AuthorizeArgs),
    /// List background jobs (`CMD &`), show one job's output, or wait for one.
    Jobs {
        /// Wait for job ID to finish.
        #[arg(short = 'w', long, requires = "id")]
        wait: bool,
        /// Job id.
        #[arg(value_name = "ID")]
        id: Option<u32>,
    },
    /// Close the connection if no session is running.
    Exit,
    /// Close the connection now; PTY sessions stay attachable while the
    /// server keeps them (`kill` ends one).
    Disconnect,
}

/// `shell [--home] [CMD...]`.
#[derive(Args, Clone, Debug, Default, PartialEq, Eq)]
pub struct ShellArgs {
    /// Start in the remote home directory instead of the MRU session's cwd.
    #[arg(long)]
    pub home: bool,

    /// Run CMD under a PTY instead of the login shell.
    #[arg(
        value_name = "CMD",
        trailing_var_arg = true,
        allow_hyphen_values = true,
        num_args = 0..
    )]
    pub command: Vec<String>,
}

/// `put [-r] [-c] [-P] [-F] LOCAL... [REMOTE]`.
///
/// Shorts differ from plain `put -p`/`-L` because the same struct is
/// flattened next to the connection options on the CLI (`-p` port, `-L`
/// forward).
#[allow(clippy::struct_excessive_bools)]
#[derive(Args, Clone, Debug, Default, PartialEq, Eq)]
pub struct PutArgs {
    /// Copy directories recursively.
    #[arg(short = 'r', long)]
    pub recursive: bool,

    /// Resume partially transferred files.
    #[arg(short = 'c', long = "continue")]
    pub continue_: bool,

    /// Preserve modification times and modes.
    #[arg(short = 'P', long)]
    pub preserve: bool,

    /// Follow symbolic links instead of copying them as links.
    #[arg(short = 'F', long)]
    pub follow_symlinks: bool,

    /// Concurrent file streams for `-r` (default 4).
    #[arg(short = 'j', long = "jobs", value_name = "N", default_value_t = DEFAULT_TRANSFER_JOBS)]
    pub jobs: usize,

    /// LOCAL... [REMOTE]; with one path REMOTE defaults to the MRU session's
    /// cwd, then `~`.
    #[arg(value_name = "PATH", required = true, num_args = 1..)]
    pub paths: Vec<String>,
}

impl PutArgs {
    /// Concurrency for recursive transfers; a zero (`Default`) means the
    /// clap default.
    #[must_use]
    pub fn concurrency(&self) -> usize {
        if self.jobs == 0 {
            DEFAULT_TRANSFER_JOBS
        } else {
            self.jobs
        }
    }

    /// The prompt words that reproduce this command (for the control socket).
    #[must_use]
    pub fn to_argv(&self) -> Vec<String> {
        let mut argv = vec!["put".to_owned()];
        if self.recursive {
            argv.push("-r".to_owned());
        }
        if self.continue_ {
            argv.push("-c".to_owned());
        }
        if self.preserve {
            argv.push("-P".to_owned());
        }
        if self.follow_symlinks {
            argv.push("-F".to_owned());
        }
        argv.push("-j".to_owned());
        argv.push(self.concurrency().to_string());
        argv.push("--".to_owned());
        argv.extend(self.paths.iter().cloned());
        argv
    }
}

/// `get [-r] [-c] [-P] REMOTE... [LOCAL]`.
#[derive(Args, Clone, Debug, Default, PartialEq, Eq)]
pub struct GetArgs {
    /// Copy directories recursively.
    #[arg(short = 'r', long)]
    pub recursive: bool,

    /// Resume partially transferred files.
    #[arg(short = 'c', long = "continue")]
    pub continue_: bool,

    /// Preserve modification times and modes.
    #[arg(short = 'P', long)]
    pub preserve: bool,

    /// Concurrent file streams for `-r` (default 4).
    #[arg(short = 'j', long = "jobs", value_name = "N", default_value_t = DEFAULT_TRANSFER_JOBS)]
    pub jobs: usize,

    /// REMOTE... [LOCAL]; with one path LOCAL defaults to the client cwd.
    #[arg(value_name = "PATH", required = true, num_args = 1..)]
    pub paths: Vec<String>,
}

impl GetArgs {
    /// Concurrency for recursive transfers; a zero (`Default`) means the
    /// clap default.
    #[must_use]
    pub fn concurrency(&self) -> usize {
        if self.jobs == 0 {
            DEFAULT_TRANSFER_JOBS
        } else {
            self.jobs
        }
    }

    /// The prompt words that reproduce this command (for the control socket).
    #[must_use]
    pub fn to_argv(&self) -> Vec<String> {
        let mut argv = vec!["get".to_owned()];
        if self.recursive {
            argv.push("-r".to_owned());
        }
        if self.continue_ {
            argv.push("-c".to_owned());
        }
        if self.preserve {
            argv.push("-P".to_owned());
        }
        argv.push("-j".to_owned());
        argv.push(self.concurrency().to_string());
        argv.push("--".to_owned());
        argv.extend(self.paths.iter().cloned());
        argv
    }
}

/// `ls [-l] [-a] [REMOTE]`.
#[derive(Args, Clone, Debug, Default, PartialEq, Eq)]
pub struct LsArgs {
    /// Long listing.
    #[arg(short = 'l', long)]
    pub long: bool,

    /// Include dot files.
    #[arg(short = 'a', long)]
    pub all: bool,

    /// Remote path (default: MRU session's cwd, then `~`).
    #[arg(value_name = "REMOTE")]
    pub path: Option<String>,
}

/// `forward -L SPEC | -R SPEC | -D SPEC | ls | rm ID`.
#[derive(Args, Clone, Debug, Default, PartialEq, Eq)]
pub struct ForwardArgs {
    /// Local forward `[bind:]port:host:hostport` (repeatable).
    #[arg(short = 'L', long = "local", value_name = "SPEC")]
    pub local: Vec<String>,

    /// Remote forward `[bind:]port:host:hostport` (repeatable).
    #[arg(short = 'R', long = "remote", value_name = "SPEC")]
    pub remote: Vec<String>,

    /// Dynamic (SOCKS) forward `[bind:]port` (repeatable).
    #[arg(short = 'D', long = "dynamic", value_name = "SPEC")]
    pub dynamic: Vec<String>,

    /// `ls` to list active forwards, or `rm ID` to remove one.
    #[arg(value_name = "ls | rm ID", num_args = 0..=2)]
    pub action: Vec<String>,
}

/// What a `forward` command line asks for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ForwardAction {
    /// Add the forwards given with `-L/-R/-D`.
    Add,
    /// List active forwards.
    List,
    /// Remove the forward with this id.
    Remove(u32),
}

impl ForwardArgs {
    /// Validate the positional sub-action against the flags.
    pub fn action(&self) -> Result<ForwardAction, String> {
        let has_specs =
            !(self.local.is_empty() && self.remote.is_empty() && self.dynamic.is_empty());
        match self.action.as_slice() {
            [] if has_specs => Ok(ForwardAction::Add),
            [] => Err("forward: give -L/-R/-D SPEC, `ls`, or `rm ID`".to_owned()),
            [_, ..] if has_specs => {
                Err("forward: `ls`/`rm` cannot be combined with -L/-R/-D".to_owned())
            }
            [word] if word == "ls" => Ok(ForwardAction::List),
            [word] if word == "rm" => Err("forward rm: missing ID".to_owned()),
            [word, id] if word == "rm" => id
                .parse::<u32>()
                .map(ForwardAction::Remove)
                .map_err(|_| format!("forward rm: invalid id {id:?}")),
            [word, ..] => Err(format!(
                "forward: unknown action {word:?} (expected `ls` or `rm ID`)"
            )),
        }
    }
}

/// `authorize [PUBKEY_FILE]`.
#[derive(Args, Clone, Debug, Default, PartialEq, Eq)]
pub struct AuthorizeArgs {
    /// Public key file to install (default: the identity in use).
    #[arg(value_name = "PUBKEY_FILE")]
    pub pubkey: Option<PathBuf>,
}

impl AuthorizeArgs {
    /// The prompt words that reproduce this command (for the control socket).
    #[must_use]
    pub fn to_argv(&self) -> Vec<String> {
        let mut argv = vec!["authorize".to_owned()];
        if let Some(p) = &self.pubkey {
            argv.push("--".to_owned());
            argv.push(p.to_string_lossy().into_owned());
        }
        argv
    }
}

/// Default `-j` for recursive transfers.
pub const DEFAULT_TRANSFER_JOBS: usize = 4;

/// Parse one prompt line. `Ok(None)` for a blank line; `Err` carries the
/// rendered clap diagnostic (which is the help text for `-h`). The boolean
/// is `true` when the line ended with a lone `&` token (run in the
/// background); an `&` glued to a word (`put a&`) is part of that word.
pub fn parse_meta_line(line: &str) -> Result<Option<(MetaCommand, bool)>, String> {
    let words = shlex::split(line).ok_or_else(|| "unbalanced quotes".to_owned())?;
    parse_meta_argv(words)
}

/// [`parse_meta_line`] for an already tokenized line.
pub fn parse_meta_argv(mut words: Vec<String>) -> Result<Option<(MetaCommand, bool)>, String> {
    if words.is_empty() {
        return Ok(None);
    }
    let background = words.last().is_some_and(|w| w == "&");
    if background {
        words.pop();
        if words.is_empty() {
            return Err("nothing to run in the background before `&`\n".to_owned());
        }
    }
    match MetaCli::try_parse_from(words) {
        Ok(cli) => Ok(Some((cli.cmd, background))),
        Err(e) => Err(e.render().to_string()),
    }
}

/// Help text for the prompt: the long help of one command, or the command
/// list with one-line summaries.
#[must_use]
pub fn meta_help(cmd: Option<&str>) -> String {
    let mut root = MetaCli::command();
    root.build();
    if let Some(name) = cmd {
        return match root.find_subcommand_mut(name) {
            Some(sub) => sub.render_long_help().to_string(),
            None => format!("unknown command {name:?}; type `help` for the list\n"),
        };
    }
    let width = root
        .get_subcommands()
        .map(|c| c.get_name().len())
        .max()
        .unwrap_or(0);
    let mut out = String::from("Commands (each accepts -h):\n");
    for sub in root.get_subcommands() {
        let about = sub.get_about().map(ToString::to_string).unwrap_or_default();
        let _ = writeln!(out, "  {:<width$}  {about}", sub.get_name());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cli(args: &[&str]) -> Cli {
        try_parse_from(std::iter::once("mysh").chain(args.iter().copied()))
            .unwrap_or_else(|e| panic!("parse {args:?}: {e}"))
    }

    fn meta(line: &str) -> MetaCommand {
        let (cmd, background) = parse_meta_line(line)
            .unwrap_or_else(|e| panic!("parse {line:?}: {e}"))
            .unwrap_or_else(|| panic!("empty parse for {line:?}"));
        assert!(!background, "{line:?} parsed as background");
        cmd
    }

    #[test]
    fn clap_definitions_are_consistent() {
        Cli::command().debug_assert();
        MetaCli::command().debug_assert();
    }

    #[test]
    fn bare_host() {
        let c = cli(&["host"]);
        assert!(c.command.is_none());
        assert_eq!(c.connect.host.as_deref(), Some("host"));
        assert_eq!(c.connect.command, [] as [std::string::String; 0]);
        assert_eq!(c.verbose, 0);
    }

    #[test]
    fn host_with_dashdash_command() {
        let c = cli(&["host", "--", "ls", "-la"]);
        assert_eq!(c.connect.host.as_deref(), Some("host"));
        assert_eq!(c.connect.command, ["ls", "-la"]);
    }

    #[test]
    fn host_with_command_without_dashdash() {
        let c = cli(&["host", "ls", "-la"]);
        assert_eq!(c.connect.host.as_deref(), Some("host"));
        assert_eq!(c.connect.command, ["ls", "-la"]);
    }

    #[test]
    fn shell_flag_before_host() {
        let c = cli(&["-s", "host"]);
        assert!(c.connect.opts.shell);
        assert_eq!(c.connect.host.as_deref(), Some("host"));
    }

    #[test]
    fn repeated_local_forwards() {
        let c = cli(&["-L", "8080:localhost:80", "-L", "1:2:3", "host"]);
        assert_eq!(c.connect.opts.local, ["8080:localhost:80", "1:2:3"]);
        assert_eq!(c.connect.host.as_deref(), Some("host"));
    }

    #[test]
    fn verbose_is_global_and_counted() {
        let c = cli(&["serve", "-vv"]);
        assert_eq!(c.verbose, 2);
        let c = cli(&["host", "-v"]);
        assert_eq!(c.verbose, 1);
    }

    #[test]
    fn serve_with_deny_and_listen() {
        let c = cli(&[
            "serve",
            "--deny",
            "pty",
            "--deny",
            "files",
            "--listen",
            "127.0.0.1:0",
        ]);
        match c.command {
            Some(Command::Serve(s)) => {
                assert_eq!(s.deny, [Feature::Pty, Feature::Files]);
                assert_eq!(s.listen, ["127.0.0.1:0"]);
                assert!(!s.no_generate_key);
            }
            other => panic!("expected serve, got {other:?}"),
        }
    }

    #[test]
    fn put_with_port_and_paths() {
        let c = cli(&["put", "-p", "7000", "host", "a", "b", "dest"]);
        match c.command {
            Some(Command::Put(p)) => {
                assert_eq!(p.opts.port, Some(7000));
                assert_eq!(p.host, "host");
                assert_eq!(p.args.paths, ["a", "b", "dest"]);
                assert!(!p.args.preserve);
            }
            other => panic!("expected put, got {other:?}"),
        }
    }

    #[test]
    fn connect_subcommand_allows_reserved_host() {
        let c = cli(&["connect", "serve"]);
        match c.command {
            Some(Command::Connect(a)) => assert_eq!(a.host.as_deref(), Some("serve")),
            other => panic!("expected connect, got {other:?}"),
        }
    }

    #[test]
    fn keygen_and_fingerprint() {
        match cli(&["keygen", "-o", "x", "-C", "c"]).command {
            Some(Command::Keygen(k)) => {
                assert_eq!(k.output, Some(PathBuf::from("x")));
                assert_eq!(k.comment.as_deref(), Some("c"));
            }
            other => panic!("expected keygen, got {other:?}"),
        }
        match cli(&["fingerprint", "-"]).command {
            Some(Command::Fingerprint(f)) => assert_eq!(f.file, Some(PathBuf::from("-"))),
            other => panic!("expected fingerprint, got {other:?}"),
        }
    }

    #[test]
    fn forward_subcommand_uses_shared_specs() {
        match cli(&["forward", "host", "-L", "1:2:3", "-D", "1080"]).command {
            Some(Command::Forward(f)) => {
                assert_eq!(f.host, "host");
                assert_eq!(f.opts.local, ["1:2:3"]);
                assert_eq!(f.opts.dynamic, ["1080"]);
            }
            other => panic!("expected forward, got {other:?}"),
        }
    }

    #[test]
    fn conflicting_flags_error() {
        assert!(try_parse_from(["mysh", "-t", "-T", "host"]).is_err());
        assert!(try_parse_from(["mysh", "--accept-new", "--strict", "host"]).is_err());
    }

    #[test]
    fn meta_blank_line() {
        assert_eq!(parse_meta_line("").expect("blank ok"), None);
        assert_eq!(parse_meta_line("   ").expect("blank ok"), None);
    }

    #[test]
    fn meta_unbalanced_quotes() {
        assert!(parse_meta_line("put \"oops").is_err());
    }

    #[test]
    fn meta_put_quoted_path() {
        match meta("put \"my file\" dest") {
            MetaCommand::Put(p) => assert_eq!(p.paths, ["my file", "dest"]),
            other => panic!("expected put, got {other:?}"),
        }
    }

    #[test]
    fn meta_forward_variants() {
        match meta("forward -L 1:2:3") {
            MetaCommand::Forward(f) => {
                assert_eq!(f.local, ["1:2:3"]);
                assert_eq!(f.action(), Ok(ForwardAction::Add));
            }
            other => panic!("expected forward, got {other:?}"),
        }
        match meta("forward ls") {
            MetaCommand::Forward(f) => assert_eq!(f.action(), Ok(ForwardAction::List)),
            other => panic!("expected forward, got {other:?}"),
        }
        match meta("forward rm 2") {
            MetaCommand::Forward(f) => assert_eq!(f.action(), Ok(ForwardAction::Remove(2))),
            other => panic!("expected forward, got {other:?}"),
        }
        match meta("forward") {
            MetaCommand::Forward(f) => assert!(f.action().is_err()),
            other => panic!("expected forward, got {other:?}"),
        }
        match meta("forward rm") {
            MetaCommand::Forward(f) => assert!(f.action().is_err()),
            other => panic!("expected forward, got {other:?}"),
        }
        match meta("forward ls -L 1:2:3") {
            MetaCommand::Forward(f) => assert!(f.action().is_err()),
            other => panic!("expected forward, got {other:?}"),
        }
    }

    #[test]
    fn meta_kill_with_signal() {
        assert_eq!(
            meta("kill -s INT 3"),
            MetaCommand::Kill {
                signal: Some("INT".to_owned()),
                id: "3".to_owned()
            }
        );
        assert_eq!(
            meta("kill 1"),
            MetaCommand::Kill {
                signal: None,
                id: "1".to_owned()
            }
        );
    }

    #[test]
    fn meta_send_text() {
        assert_eq!(
            meta("send ^] foo"),
            MetaCommand::Send {
                text: vec!["^]".to_owned(), "foo".to_owned()]
            }
        );
        assert!(parse_meta_line("send").is_err());
    }

    #[test]
    fn meta_shell_and_exec_swallow_hyphen_args() {
        match meta("shell htop --tree") {
            MetaCommand::Shell(s) => {
                assert!(!s.home);
                assert_eq!(s.command, ["htop", "--tree"]);
            }
            other => panic!("expected shell, got {other:?}"),
        }
        match meta("shell --home") {
            MetaCommand::Shell(s) => {
                assert!(s.home);
                assert_eq!(s.command, [] as [std::string::String; 0]);
            }
            other => panic!("expected shell, got {other:?}"),
        }
        assert_eq!(
            meta("exec ls -la"),
            MetaCommand::Exec {
                command: vec!["ls".to_owned(), "-la".to_owned()]
            }
        );
    }

    #[test]
    fn meta_simple_commands() {
        assert_eq!(meta("exit"), MetaCommand::Exit);
        assert_eq!(meta("disconnect"), MetaCommand::Disconnect);
        assert_eq!(meta("sessions"), MetaCommand::Sessions { all: false });
        assert_eq!(meta("sessions -a"), MetaCommand::Sessions { all: true });
        assert_eq!(meta("attach"), MetaCommand::Attach { id: None });
        assert_eq!(meta("attach 4"), MetaCommand::Attach { id: Some(4) });
        assert_eq!(meta("detach 2"), MetaCommand::Detach { id: Some(2) });
        assert_eq!(meta("fg 2"), MetaCommand::Fg { id: Some(2) });
        assert_eq!(meta("ping -c 3"), MetaCommand::Ping { count: Some(3) });
        assert_eq!(
            meta("log off"),
            MetaCommand::Log {
                target: "off".to_owned()
            }
        );
        assert_eq!(
            meta("help put"),
            MetaCommand::Help {
                cmd: Some("put".to_owned())
            }
        );
        match meta("ls -la /tmp") {
            MetaCommand::Ls(l) => {
                assert!(l.long && l.all);
                assert_eq!(l.path.as_deref(), Some("/tmp"));
            }
            other => panic!("expected ls, got {other:?}"),
        }
    }

    #[test]
    fn meta_errors_render_text() {
        let err = parse_meta_line("bogus").expect_err("unknown command");
        assert!(err.contains("bogus"), "{err}");
        let err = parse_meta_line("put -h").expect_err("help is an error");
        assert!(err.contains("Usage"), "{err}");
    }

    #[test]
    fn meta_help_lists_every_command() {
        let all = meta_help(None);
        for name in [
            "help",
            "shell",
            "fg",
            "sessions",
            "kill",
            "send",
            "put",
            "get",
            "ls",
            "cwd",
            "lcd",
            "forward",
            "exec",
            "info",
            "ping",
            "resize",
            "log",
            "authorize",
            "jobs",
            "exit",
            "disconnect",
        ] {
            assert!(
                all.contains(&format!("  {name}")),
                "missing {name} in:\n{all}"
            );
        }
        let put = meta_help(Some("put"));
        assert!(put.contains("Usage"), "{put}");
        assert!(put.contains("--recursive"), "{put}");
        assert!(meta_help(Some("nope")).contains("unknown command"));
    }

    #[test]
    fn meta_background_suffix() {
        let (cmd, background) = parse_meta_line("put a b &")
            .expect("parse")
            .expect("non-empty");
        assert!(background);
        assert_eq!(
            cmd,
            MetaCommand::Put(PutArgs {
                paths: vec!["a".into(), "b".into()],
                jobs: DEFAULT_TRANSFER_JOBS,
                ..PutArgs::default()
            })
        );
        let err = parse_meta_line("&").expect_err("lone & is an error");
        assert!(err.contains("nothing to run"), "{err}");
        // Glued `&` belongs to the word.
        let (cmd, background) = parse_meta_line("put a&")
            .expect("parse")
            .expect("non-empty");
        assert!(!background);
        assert_eq!(
            cmd,
            MetaCommand::Put(PutArgs {
                paths: vec!["a&".into()],
                jobs: DEFAULT_TRANSFER_JOBS,
                ..PutArgs::default()
            })
        );
    }

    #[test]
    fn meta_jobs_and_kill_job() {
        assert_eq!(
            meta("jobs"),
            MetaCommand::Jobs {
                wait: false,
                id: None
            }
        );
        assert_eq!(
            meta("jobs -w 2"),
            MetaCommand::Jobs {
                wait: true,
                id: Some(2)
            }
        );
        assert!(parse_meta_line("jobs -w").is_err());
        assert_eq!(
            meta("kill %2"),
            MetaCommand::Kill {
                signal: None,
                id: "%2".to_owned()
            }
        );
    }

    #[test]
    fn transfer_jobs_flag_and_argv_round_trip() {
        let put = PutArgs {
            recursive: true,
            preserve: true,
            jobs: 0,
            paths: vec!["a b".into(), "-x".into(), "dest".into()],
            ..PutArgs::default()
        };
        assert_eq!(put.concurrency(), DEFAULT_TRANSFER_JOBS);
        let argv = put.to_argv();
        let (cmd, background) = parse_meta_argv(argv).expect("parse").expect("non-empty");
        assert!(!background);
        assert_eq!(
            cmd,
            MetaCommand::Put(PutArgs {
                jobs: DEFAULT_TRANSFER_JOBS,
                ..put
            })
        );

        let get = GetArgs {
            continue_: true,
            jobs: 2,
            paths: vec!["r".into()],
            ..GetArgs::default()
        };
        let (cmd, _) = parse_meta_argv(get.to_argv())
            .expect("parse")
            .expect("non-empty");
        assert_eq!(cmd, MetaCommand::Get(get));
        assert_eq!(
            meta("get -j 8 r"),
            MetaCommand::Get(GetArgs {
                jobs: 8,
                paths: vec!["r".into()],
                ..GetArgs::default()
            })
        );

        let auth = AuthorizeArgs {
            pubkey: Some(PathBuf::from("k.pub")),
        };
        let (cmd, _) = parse_meta_argv(auth.to_argv())
            .expect("parse")
            .expect("non-empty");
        assert_eq!(cmd, MetaCommand::Authorize(auth));
        let (cmd, _) = parse_meta_argv(AuthorizeArgs::default().to_argv())
            .expect("parse")
            .expect("non-empty");
        assert_eq!(cmd, MetaCommand::Authorize(AuthorizeArgs::default()));
    }

    #[test]
    fn no_ctl_flag() {
        let c = cli(&["put", "--no-ctl", "host", "a"]);
        match c.command {
            Some(Command::Put(p)) => assert!(p.opts.no_ctl),
            other => panic!("expected put, got {other:?}"),
        }
    }
}
