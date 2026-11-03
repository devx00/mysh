//! Request shapes shared by the library, the `mysh` command line and the
//! control socket. They derive clap's `Args` so one definition serves
//! every frontend; a library caller fills them in like plain structs
//! (`PutArgs { recursive: true, paths: vec![..], ..Default::default() }`).

use std::path::PathBuf;
use std::time::Duration;

use clap::{Args, Subcommand};

use crate::config::{MasterMode, parse_duration};

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

    /// One JSON document per command on stdout; errors as JSON on stderr
    /// (docs/05-meta-shell.md "Agent interface").
    #[arg(long, conflicts_with = "json_stream")]
    pub json: bool,

    /// Newline-delimited JSON events on stdout as they happen.
    #[arg(long = "json-stream")]
    pub json_stream: bool,

    /// No ANSI sequences, progress lines, banner or prompt redraws (implied
    /// by `--json`, `--json-stream`, and when stdout is not a terminal).
    #[arg(long)]
    pub plain: bool,

    /// Give up after DURATION (`10s`, `2m`, `500ms`): a command gets TERM,
    /// then KILL after 2 s; exit code 124.
    #[arg(long, value_name = "DURATION", value_parser = parse_duration)]
    pub timeout: Option<Duration>,

    /// Working directory for CMD (`~`-relative paths are expanded by the
    /// server).
    #[arg(long, value_name = "DIR")]
    pub cwd: Option<String>,

    /// Run as a background master for HOST: serve the control socket, no
    /// prompt, no stdin (same as `mysh master HOST`).
    #[arg(short = 'M')]
    pub as_master: bool,

    /// Start a background master when no control socket is there
    /// (`never` by default; `[defaults] master` in the config file).
    #[arg(long, value_name = "never|auto|always")]
    pub master: Option<MasterMode>,

    /// Fan out to these hosts (comma-separated, repeatable; `run`, `put`
    /// and `get` only).
    #[arg(long, value_name = "HOST,...")]
    pub hosts: Vec<String>,

    /// Fan out to a `[groups.NAME]` of the config file (repeatable; `run`,
    /// `put` and `get` only).
    #[arg(long, value_name = "NAME")]
    pub group: Vec<String>,
}

impl ConnectOpts {
    /// `--hosts`/`--group` were given: the command fans out
    /// (docs/05-meta-shell.md "Fleet").
    #[must_use]
    pub fn fan_out(&self) -> bool {
        !self.hosts.is_empty() || !self.group.is_empty()
    }
}

/// `put [-r] [-c] [-P] [-F] [--checksum] LOCAL... [REMOTE]`, or
/// `put [--mode M] [--mtime T] - REMOTE` from stdin.
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

    /// Skip files whose size and BLAKE2s digest already match the remote.
    #[arg(long)]
    pub checksum: bool,

    /// Mode of the file written from stdin (`put - REMOTE`; octal,
    /// default 0644).
    #[arg(long, value_name = "MODE", value_parser = parse_mode)]
    pub mode: Option<u32>,

    /// Modification time of the file written from stdin, seconds since the
    /// epoch.
    #[arg(long, value_name = "SECS", allow_negative_numbers = true)]
    pub mtime: Option<i64>,

    /// `LOCAL... [REMOTE]`; with one path REMOTE defaults to the MRU session's
    /// cwd, then `~`. `-` reads standard input (REMOTE required).
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
        if self.checksum {
            argv.push("--checksum".to_owned());
        }
        if let Some(mode) = self.mode {
            argv.push("--mode".to_owned());
            argv.push(format!("{mode:o}"));
        }
        if let Some(mtime) = self.mtime {
            argv.push("--mtime".to_owned());
            argv.push(mtime.to_string());
        }
        argv.push("-j".to_owned());
        argv.push(self.concurrency().to_string());
        argv.push("--".to_owned());
        argv.extend(self.paths.iter().cloned());
        argv
    }
}

/// `get [-r] [-c] [-P] [--checksum] REMOTE... [LOCAL]`; LOCAL `-` prints.
#[allow(clippy::struct_excessive_bools)] // independent switches, like `PutArgs`
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

    /// Skip files whose size and BLAKE2s digest already match the local
    /// copy.
    #[arg(long)]
    pub checksum: bool,

    /// `REMOTE... [LOCAL]`; with one path LOCAL defaults to the client cwd.
    /// `-` writes the files to standard output.
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
        if self.checksum {
            argv.push("--checksum".to_owned());
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

/// `cat REMOTE…`.
#[derive(Args, Clone, Debug, Default, PartialEq, Eq)]
pub struct CatArgs {
    /// Remote files, printed in order.
    #[arg(value_name = "REMOTE", required = true, num_args = 1..)]
    pub paths: Vec<String>,
}

/// `write [--mode M] [--append] REMOTE`.
#[derive(Args, Clone, Debug, Default, PartialEq, Eq)]
pub struct WriteArgs {
    /// Mode of a new file (octal, default 0644; an appended file keeps
    /// its own).
    #[arg(long, value_name = "MODE", value_parser = parse_mode)]
    pub mode: Option<u32>,

    /// Append to the file instead of replacing it atomically.
    #[arg(long)]
    pub append: bool,

    /// Remote file.
    #[arg(value_name = "REMOTE")]
    pub path: String,
}

/// `tail [-n N] [-f] [--for D] REMOTE`.
///
/// The deadline is `--for`, not `--timeout`, because the struct is also
/// flattened next to the connection options on the CLI, where `--timeout`
/// is the global bound (which `tail -f` honours as well).
#[derive(Args, Clone, Debug, PartialEq, Eq)]
pub struct TailArgs {
    /// Lines to print (default 10).
    #[arg(short = 'n', long = "lines", value_name = "N", default_value_t = DEFAULT_TAIL_LINES)]
    pub lines: usize,

    /// Keep printing as the file grows, until Ctrl-C, `--for` or the
    /// connection's `--timeout`.
    #[arg(short = 'f', long)]
    pub follow: bool,

    /// With `-f`: stop after DURATION (`10s`, `2m`) and exit 0.
    #[arg(id = "for", long = "for", value_name = "DURATION", value_parser = parse_duration)]
    pub timeout: Option<Duration>,

    /// Remote file.
    #[arg(value_name = "REMOTE")]
    pub path: String,
}

impl Default for TailArgs {
    fn default() -> Self {
        Self {
            lines: DEFAULT_TAIL_LINES,
            follow: false,
            timeout: None,
            path: String::new(),
        }
    }
}

/// `stat REMOTE…`.
#[derive(Args, Clone, Debug, Default, PartialEq, Eq)]
pub struct StatArgs {
    /// Remote paths.
    #[arg(value_name = "REMOTE", required = true, num_args = 1..)]
    pub paths: Vec<String>,
}

/// `mkdir [-P] [-m MODE] REMOTE…` (`-p` is the shared CLI port option).
#[derive(Args, Clone, Debug, Default, PartialEq, Eq)]
pub struct MkdirArgs {
    /// Create missing parents too; no error when the directory exists.
    #[arg(short = 'P', long)]
    pub parents: bool,

    /// Mode of the created directories (octal, default 0755).
    #[arg(short = 'm', long, value_name = "MODE", value_parser = parse_mode)]
    pub mode: Option<u32>,

    /// Remote directories.
    #[arg(value_name = "REMOTE", required = true, num_args = 1..)]
    pub paths: Vec<String>,
}

/// `rm [-r] REMOTE…`.
#[derive(Args, Clone, Debug, Default, PartialEq, Eq)]
pub struct RmArgs {
    /// Remove directories and their contents.
    #[arg(short = 'r', long)]
    pub recursive: bool,

    /// Remote paths.
    #[arg(value_name = "REMOTE", required = true, num_args = 1..)]
    pub paths: Vec<String>,
}

/// `mv FROM TO`.
#[derive(Args, Clone, Debug, Default, PartialEq, Eq)]
pub struct MvArgs {
    /// Remote path to rename.
    #[arg(value_name = "FROM")]
    pub from: String,

    /// New remote path (replaced if it exists).
    #[arg(value_name = "TO")]
    pub to: String,
}

/// `realpath REMOTE`.
#[derive(Args, Clone, Debug, Default, PartialEq, Eq)]
pub struct RealpathArgs {
    /// Remote path.
    #[arg(value_name = "REMOTE")]
    pub path: String,
}

/// `hash REMOTE…`.
#[derive(Args, Clone, Debug, Default, PartialEq, Eq)]
pub struct HashArgs {
    /// Remote regular files.
    #[arg(value_name = "REMOTE", required = true, num_args = 1..)]
    pub paths: Vec<String>,
}

/// `sync [--pull] [--delete] [--dry-run] [--checksum] [-j N] SRC DST`.
#[allow(clippy::struct_excessive_bools)]
#[derive(Args, Clone, Debug, Default, PartialEq, Eq)]
pub struct SyncArgs {
    /// SRC is remote and DST local (default: local SRC → remote DST).
    #[arg(long)]
    pub pull: bool,

    /// Remove files and directories on DST that SRC does not have.
    #[arg(long)]
    pub delete: bool,

    /// Print the plan and change nothing.
    #[arg(long)]
    pub dry_run: bool,

    /// Compare same-size files by BLAKE2s digest instead of mtime.
    #[arg(long)]
    pub checksum: bool,

    /// Concurrent file streams (default 4).
    #[arg(short = 'j', long = "jobs", value_name = "N", default_value_t = DEFAULT_TRANSFER_JOBS)]
    pub jobs: usize,

    /// Source tree.
    #[arg(value_name = "SRC")]
    pub src: String,

    /// Destination tree (created if missing).
    #[arg(value_name = "DST")]
    pub dst: String,
}

impl SyncArgs {
    /// Concurrency; a zero (`Default`) means the clap default.
    #[must_use]
    pub fn concurrency(&self) -> usize {
        if self.jobs == 0 {
            DEFAULT_TRANSFER_JOBS
        } else {
            self.jobs
        }
    }
}

/// A file primitive run once (`mysh HOST cat …`), at the prompt, or over
/// the control socket; the args structs are shared with the prompt's `MetaCommand`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FileCmd {
    /// `cat` command.
    Cat(CatArgs),
    /// `write` command.
    Write(WriteArgs),
    /// `tail` command.
    Tail(TailArgs),
    /// `stat` command.
    Stat(StatArgs),
    /// `mkdir` command.
    Mkdir(MkdirArgs),
    /// `rm` command.
    Rm(RmArgs),
    /// `mv` command.
    Mv(MvArgs),
    /// `realpath` command.
    Realpath(RealpathArgs),
    /// `hash` command.
    Hash(HashArgs),
    /// `sync` command.
    Sync(SyncArgs),
}

impl FileCmd {
    /// The command's name as typed.
    #[must_use]
    pub fn name(&self) -> &'static str {
        match self {
            Self::Cat(_) => "cat",
            Self::Write(_) => "write",
            Self::Tail(_) => "tail",
            Self::Stat(_) => "stat",
            Self::Mkdir(_) => "mkdir",
            Self::Rm(_) => "rm",
            Self::Mv(_) => "mv",
            Self::Realpath(_) => "realpath",
            Self::Hash(_) => "hash",
            Self::Sync(_) => "sync",
        }
    }

    /// Whether the command consumes standard input (`write`).
    #[must_use]
    pub fn reads_stdin(&self) -> bool {
        matches!(self, Self::Write(_))
    }

    /// `tail -f`: runs until interrupted.
    #[must_use]
    pub fn follows(&self) -> bool {
        matches!(self, Self::Tail(TailArgs { follow: true, .. }))
    }

    /// The prompt words that reproduce this command (for the control socket).
    #[must_use]
    pub fn to_argv(&self) -> Vec<String> {
        let mut argv = vec![self.name().to_owned()];
        let flag = |argv: &mut Vec<String>, on: bool, word: &str| {
            if on {
                argv.push(word.to_owned());
            }
        };
        match self {
            Self::Cat(a) => {
                argv.push("--".to_owned());
                argv.extend(a.paths.iter().cloned());
            }
            Self::Write(a) => {
                if let Some(mode) = a.mode {
                    argv.push("--mode".to_owned());
                    argv.push(format!("{mode:o}"));
                }
                flag(&mut argv, a.append, "--append");
                argv.push("--".to_owned());
                argv.push(a.path.clone());
            }
            Self::Tail(a) => {
                argv.push("-n".to_owned());
                argv.push(a.lines.to_string());
                flag(&mut argv, a.follow, "-f");
                if let Some(d) = a.timeout {
                    argv.push("--for".to_owned());
                    argv.push(format_duration(d));
                }
                argv.push("--".to_owned());
                argv.push(a.path.clone());
            }
            Self::Stat(a) => {
                argv.push("--".to_owned());
                argv.extend(a.paths.iter().cloned());
            }
            Self::Mkdir(a) => {
                flag(&mut argv, a.parents, "-P");
                if let Some(mode) = a.mode {
                    argv.push("-m".to_owned());
                    argv.push(format!("{mode:o}"));
                }
                argv.push("--".to_owned());
                argv.extend(a.paths.iter().cloned());
            }
            Self::Rm(a) => {
                flag(&mut argv, a.recursive, "-r");
                argv.push("--".to_owned());
                argv.extend(a.paths.iter().cloned());
            }
            Self::Mv(a) => {
                argv.push("--".to_owned());
                argv.push(a.from.clone());
                argv.push(a.to.clone());
            }
            Self::Realpath(a) => {
                argv.push("--".to_owned());
                argv.push(a.path.clone());
            }
            Self::Hash(a) => {
                argv.push("--".to_owned());
                argv.extend(a.paths.iter().cloned());
            }
            Self::Sync(a) => {
                flag(&mut argv, a.pull, "--pull");
                flag(&mut argv, a.delete, "--delete");
                flag(&mut argv, a.dry_run, "--dry-run");
                flag(&mut argv, a.checksum, "--checksum");
                argv.push("-j".to_owned());
                argv.push(a.concurrency().to_string());
                argv.push("--".to_owned());
                argv.push(a.src.clone());
                argv.push(a.dst.clone());
            }
        }
        argv
    }
}

/// Default `-n` for `tail`.
pub const DEFAULT_TAIL_LINES: usize = 10;

/// An octal permission mode (`644`, `0755`, `u+x` is not accepted).
fn parse_mode(s: &str) -> Result<u32, String> {
    let digits = s.strip_prefix("0o").unwrap_or(s);
    u32::from_str_radix(digits, 8)
        .ok()
        .filter(|m| *m <= 0o7777)
        .ok_or_else(|| format!("`{s}` is not an octal mode (e.g. 644, 0755)"))
}

/// `session new|send|read|list|kill|wait …` (docs/05-meta-shell.md,
/// "Session command family"). The same struct serves the CLI subcommand,
/// the prompt command and the control socket.
#[derive(Args, Clone, Debug, PartialEq, Eq)]
pub struct SessionArgs {
    #[command(subcommand)]
    /// Subcommand to execute.
    pub cmd: SessionCmd,
}

/// What a `session` command line asks for.
#[derive(Subcommand, Clone, Debug, PartialEq, Eq)]
pub enum SessionCmd {
    /// Start a session that outlives this command; prints `{id, pid}`.
    New(SessionNewArgs),
    /// Write to a session's stdin.
    Send(SessionSendArgs),
    /// Read a session's output from an absolute byte offset.
    Read(SessionReadArgs),
    /// List the sessions this key owns on the server.
    List,
    /// Signal a session (default: TERM).
    Kill {
        /// Signal name or number.
        #[arg(short = 's', long = "signal", value_name = "SIG")]
        signal: Option<String>,
        /// Session id.
        #[arg(value_name = "ID")]
        id: u32,
    },
    /// Wait for a session to exit and print its status.
    Wait {
        /// Give up after DURATION (`10s`, `2m`, `500ms`); exit code 124.
        #[arg(long, value_name = "DURATION", value_parser = parse_duration)]
        timeout: Option<Duration>,
        /// Session id.
        #[arg(value_name = "ID")]
        id: u32,
    },
}

/// `session new [--cwd DIR] [--pty] [--env K=V] -- CMD…`.
#[derive(Args, Clone, Debug, Default, PartialEq, Eq)]
pub struct SessionNewArgs {
    /// Working directory (default: the remote home).
    #[arg(long, value_name = "DIR")]
    pub cwd: Option<String>,

    /// Run under a pty (stdout and stderr are then merged).
    #[arg(long)]
    pub pty: bool,

    /// Environment variable `NAME[=VALUE]` (repeatable; the server must
    /// accept it).
    #[arg(long, value_name = "NAME[=VALUE]")]
    pub env: Vec<String>,

    /// Command and arguments (a single word runs through the shell).
    #[arg(
        value_name = "CMD",
        required = true,
        trailing_var_arg = true,
        allow_hyphen_values = true,
        num_args = 1..
    )]
    pub command: Vec<String>,
}

/// `session send ID [TEXT…] [--stdin] [--eof]`.
#[derive(Args, Clone, Debug, Default, PartialEq, Eq)]
pub struct SessionSendArgs {
    /// Session id.
    #[arg(value_name = "ID")]
    pub id: u32,

    /// Read the bytes from this command's stdin instead of TEXT.
    #[arg(long)]
    pub stdin: bool,

    /// Close the session's stdin afterwards (non-PTY sessions).
    #[arg(long)]
    pub eof: bool,

    /// Text to send; words are joined with single spaces and a newline is
    /// appended. Caret notation (`^C`) and `\xNN` escapes are decoded.
    #[arg(
        value_name = "TEXT",
        trailing_var_arg = true,
        allow_hyphen_values = true,
        num_args = 0..
    )]
    pub text: Vec<String>,
}

/// `session read ID [--since N] [--wait D] [--max BYTES] [--follow]`.
#[derive(Args, Clone, Debug, Default, PartialEq, Eq)]
pub struct SessionReadArgs {
    /// Session id.
    #[arg(value_name = "ID")]
    pub id: u32,

    /// Absolute byte offset to read from (default: 0).
    #[arg(long, value_name = "OFFSET")]
    pub since: Option<u64>,

    /// Block up to DURATION for new output (default: no wait).
    #[arg(long, value_name = "DURATION", value_parser = parse_duration)]
    pub wait: Option<Duration>,

    /// Largest reply, in bytes (default and cap: 1 MiB).
    #[arg(long, value_name = "BYTES")]
    pub max: Option<u32>,

    /// Keep reading until the session exits.
    #[arg(short = 'f', long)]
    pub follow: bool,
}

/// `mysh master HOST [--idle D] [--daemon]`.
#[derive(Args, Clone, Debug, Default, PartialEq, Eq)]
pub struct MasterArgs {
    /// Exit after DURATION without a control-socket client (default 10m).
    #[arg(long, value_name = "DURATION", value_parser = parse_duration)]
    pub idle: Option<Duration>,

    /// Start the master in the background and return once its socket is up.
    #[arg(long)]
    pub daemon: bool,
}

impl SessionArgs {
    /// The prompt words that reproduce this command (for the control
    /// socket); `--stdin` input travels with the request, not in the words.
    #[must_use]
    pub fn to_argv(&self) -> Vec<String> {
        let mut argv = vec!["session".to_owned()];
        let push_opt = |argv: &mut Vec<String>, flag: &str, value: Option<String>| {
            if let Some(v) = value {
                argv.push(flag.to_owned());
                argv.push(v);
            }
        };
        match &self.cmd {
            SessionCmd::New(new) => {
                argv.push("new".to_owned());
                push_opt(&mut argv, "--cwd", new.cwd.clone());
                if new.pty {
                    argv.push("--pty".to_owned());
                }
                for e in &new.env {
                    argv.push("--env".to_owned());
                    argv.push(e.clone());
                }
                argv.push("--".to_owned());
                argv.extend(new.command.iter().cloned());
            }
            SessionCmd::Send(send) => {
                argv.push("send".to_owned());
                if send.stdin {
                    argv.push("--stdin".to_owned());
                }
                if send.eof {
                    argv.push("--eof".to_owned());
                }
                argv.push(send.id.to_string());
                if !send.text.is_empty() {
                    argv.push("--".to_owned());
                    argv.extend(send.text.iter().cloned());
                }
            }
            SessionCmd::Read(read) => {
                argv.push("read".to_owned());
                push_opt(&mut argv, "--since", read.since.map(|v| v.to_string()));
                push_opt(&mut argv, "--wait", read.wait.map(format_duration));
                push_opt(&mut argv, "--max", read.max.map(|v| v.to_string()));
                if read.follow {
                    argv.push("--follow".to_owned());
                }
                argv.push(read.id.to_string());
            }
            SessionCmd::List => argv.push("list".to_owned()),
            SessionCmd::Kill { signal, id } => {
                argv.push("kill".to_owned());
                push_opt(&mut argv, "-s", signal.clone());
                argv.push(id.to_string());
            }
            SessionCmd::Wait { timeout, id } => {
                argv.push("wait".to_owned());
                push_opt(&mut argv, "--timeout", timeout.map(format_duration));
                argv.push(id.to_string());
            }
        }
        argv
    }
}

/// A duration as `parse_duration` reads it back.
fn format_duration(d: Duration) -> String {
    format!("{}ms", d.as_millis())
}

/// Default `-j` for recursive transfers.
pub const DEFAULT_TRANSFER_JOBS: usize = 4;
