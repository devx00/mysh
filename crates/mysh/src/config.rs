//! Paths, the TOML config file, HOST/forward spec grammars, and target
//! resolution (docs/05-meta-shell.md "Config file", docs/02-security.md
//! "Identity resolution"). Pure parsing and path logic: the only I/O is
//! reading the config file in [`Config::load`].

use std::collections::BTreeMap;
use std::fmt;
use std::io;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::time::Duration;

use serde::Deserialize;

use crate::cli::ConnectOpts;

/// Built-in default port.
pub const DEFAULT_PORT: u16 = 7722;
/// Built-in default meta key (`^]`).
pub const DEFAULT_META_KEY: &str = "^]";

/// Environment lookup used by the `_with` constructors so tests do not mutate
/// the process environment.
type EnvFn<'a> = &'a dyn Fn(&str) -> Option<String>;

fn process_env(key: &str) -> Option<String> {
    std::env::var(key).ok()
}

/// Read a variable, treating empty values as unset (XDG semantics).
fn env_path(env: EnvFn<'_>, key: &str) -> Option<PathBuf> {
    env(key).filter(|v| !v.is_empty()).map(PathBuf::from)
}

fn home_dir(env: EnvFn<'_>) -> Option<PathBuf> {
    env_path(env, "HOME").or_else(dirs::home_dir)
}

/// Well-known client and server file locations.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Paths {
    /// `$MYSH_CONFIG_DIR` → `$XDG_CONFIG_HOME/mysh` → `~/.config/mysh`.
    pub config_dir: PathBuf,
    /// Client identity: `config_dir/id`.
    pub identity: PathBuf,
    /// Server identity: `config_dir/host_key`.
    pub host_key: PathBuf,
    /// `config_dir/authorized_keys`.
    pub authorized_keys: PathBuf,
    /// `config_dir/known_hosts`.
    pub known_hosts: PathBuf,
    /// `config_dir/config.toml`.
    pub config_file: PathBuf,
    /// Prompt history: `$XDG_STATE_HOME/mysh/history` → `~/.local/state/mysh/history`.
    pub history: PathBuf,
    /// Control sockets (docs/05 "Control socket"): `$XDG_RUNTIME_DIR/mysh`
    /// → `$XDG_CACHE_HOME/mysh` → `~/.cache/mysh`.
    pub runtime_dir: PathBuf,
    /// `~/.ssh` when the home directory is known.
    pub ssh_dir: Option<PathBuf>,
    /// `$SSH_AUTH_SOCK` (empty = unset): the `ssh-agent` whose ed25519 keys
    /// the client may authenticate with (02-security.md, "Signature
    /// authentication").
    pub agent_socket: Option<PathBuf>,
}

impl Paths {
    /// Resolve from the process environment.
    #[must_use]
    pub fn from_env() -> Self {
        Self::from_env_with(&process_env)
    }

    /// Resolve from an explicit environment lookup.
    pub(crate) fn from_env_with(env: EnvFn<'_>) -> Self {
        let home = home_dir(env);
        let config_dir = env_path(env, "MYSH_CONFIG_DIR")
            .or_else(|| env_path(env, "XDG_CONFIG_HOME").map(|d| d.join("mysh")))
            .or_else(|| home.as_ref().map(|h| h.join(".config").join("mysh")))
            .unwrap_or_else(|| PathBuf::from(".mysh"));
        let history = env_path(env, "XDG_STATE_HOME")
            .or_else(|| home.as_ref().map(|h| h.join(".local").join("state")))
            .map_or_else(
                || config_dir.join("history"),
                |d| d.join("mysh").join("history"),
            );
        let runtime_dir = env_path(env, "XDG_RUNTIME_DIR")
            .or_else(|| env_path(env, "XDG_CACHE_HOME"))
            .or_else(|| home.as_ref().map(|h| h.join(".cache")))
            .map_or_else(|| config_dir.join("run"), |d| d.join("mysh"));
        let ssh_dir = home.map(|h| h.join(".ssh"));
        let agent_socket = env_path(env, "SSH_AUTH_SOCK");
        Self::build(config_dir, history, runtime_dir, ssh_dir, agent_socket)
    }

    /// Use an explicit config directory; history, the runtime dir, `~/.ssh`
    /// and the agent socket still come from the environment.
    #[must_use]
    pub fn with_config_dir(dir: PathBuf) -> Self {
        let env_paths = Self::from_env();
        Self::build(
            dir,
            env_paths.history,
            env_paths.runtime_dir,
            env_paths.ssh_dir,
            env_paths.agent_socket,
        )
    }

    fn build(
        config_dir: PathBuf,
        history: PathBuf,
        runtime_dir: PathBuf,
        ssh_dir: Option<PathBuf>,
        agent_socket: Option<PathBuf>,
    ) -> Self {
        Self {
            identity: config_dir.join("id"),
            host_key: config_dir.join("host_key"),
            authorized_keys: config_dir.join("authorized_keys"),
            known_hosts: config_dir.join("known_hosts"),
            config_file: config_dir.join("config.toml"),
            config_dir,
            history,
            runtime_dir,
            ssh_dir,
            agent_socket,
        }
    }
}

/// `HOST` as typed: `host`, `host:port`, `[v6]:port`, or a bare IPv6 address.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HostSpec {
    /// Host name or address, without brackets.
    pub host: String,
    /// Explicit port, if any.
    pub port: Option<u16>,
}

fn parse_port(s: &str) -> Result<u16, String> {
    s.parse::<u16>().map_err(|_| format!("invalid port {s:?}"))
}

impl FromStr for HostSpec {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.is_empty() {
            return Err("empty host".to_owned());
        }
        if let Some(rest) = s.strip_prefix('[') {
            let (host, after) = rest
                .split_once(']')
                .ok_or_else(|| format!("unterminated '[' in {s:?}"))?;
            if host.is_empty() {
                return Err(format!("empty host in {s:?}"));
            }
            let port = match after {
                "" => None,
                p => {
                    Some(parse_port(p.strip_prefix(':').ok_or_else(|| {
                        format!("expected ':' after ']' in {s:?}")
                    })?)?)
                }
            };
            return Ok(Self {
                host: host.to_owned(),
                port,
            });
        }
        if s.matches(':').count() >= 2 {
            // Bare IPv6 address: no way to carry a port, the whole thing is the host.
            return Ok(Self {
                host: s.to_owned(),
                port: None,
            });
        }
        match s.split_once(':') {
            None => Ok(Self {
                host: s.to_owned(),
                port: None,
            }),
            Some(("", _)) => Err(format!("empty host in {s:?}")),
            Some((host, port)) => Ok(Self {
                host: host.to_owned(),
                port: Some(parse_port(port)?),
            }),
        }
    }
}

/// A port forward: local (`-L`), remote (`-R`), or dynamic (`-D`, no target).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ForwardSpec {
    /// Bind address; default `127.0.0.1`, `*` (or empty) → `0.0.0.0`.
    pub bind: String,
    /// Port to listen on.
    pub port: u16,
    /// Destination for `-L`/`-R`; `None` for `-D`.
    pub target: Option<(String, u16)>,
}

/// Split on `:` while keeping `[...]` groups (IPv6 literals) intact; the
/// brackets are stripped from the returned tokens.
fn split_spec(s: &str) -> Result<Vec<String>, String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut in_bracket = false;
    for c in s.chars() {
        match c {
            '[' if !in_bracket && cur.is_empty() => in_bracket = true,
            ']' if in_bracket => in_bracket = false,
            ':' if !in_bracket => out.push(std::mem::take(&mut cur)),
            _ => cur.push(c),
        }
    }
    if in_bracket {
        return Err(format!("unterminated '[' in {s:?}"));
    }
    out.push(cur);
    Ok(out)
}

fn normalize_bind(bind: &str) -> String {
    match bind {
        "" | "*" => "0.0.0.0".to_owned(),
        b => b.to_owned(),
    }
}

impl ForwardSpec {
    /// `[bind:]port:host:hostport`, IPv6 literals in brackets.
    pub fn parse_local(s: &str) -> Result<Self, String> {
        let parts = split_spec(s)?;
        let (bind, port, host, hostport) = match parts.as_slice() {
            [port, host, hostport] => ("127.0.0.1".to_owned(), port, host, hostport),
            [bind, port, host, hostport] => (normalize_bind(bind), port, host, hostport),
            _ => {
                return Err(format!(
                    "invalid forward spec {s:?}: expected [bind:]port:host:hostport"
                ));
            }
        };
        if host.is_empty() {
            return Err(format!("invalid forward spec {s:?}: empty target host"));
        }
        let hostport = parse_port(hostport)?;
        if hostport == 0 {
            return Err(format!(
                "invalid forward spec {s:?}: target port must be non-zero"
            ));
        }
        Ok(Self {
            bind,
            port: parse_port(port)?,
            target: Some((host.clone(), hostport)),
        })
    }

    /// `[bind:]port` for a dynamic (SOCKS) forward.
    pub fn parse_dynamic(s: &str) -> Result<Self, String> {
        let parts = split_spec(s)?;
        let (bind, port) = match parts.as_slice() {
            [port] => ("127.0.0.1".to_owned(), port),
            [bind, port] => (normalize_bind(bind), port),
            _ => {
                return Err(format!(
                    "invalid dynamic forward spec {s:?}: expected [bind:]port"
                ));
            }
        };
        Ok(Self {
            bind,
            port: parse_port(port)?,
            target: None,
        })
    }
}

/// Byte for a caret-notation character (`^X` → `X`'s control code).
fn caret_byte(c: char) -> Option<u8> {
    let b = u8::try_from(c).ok()?;
    match b {
        b'?' => Some(0x7f),
        b'@'..=b'_' => Some(b - 0x40),
        b'a'..=b'z' => Some(b.to_ascii_uppercase() - 0x40),
        _ => None,
    }
}

/// Parse a meta-key setting: `none` → `None`; caret notation (`^]`, `^x`);
/// a single ASCII character; or a number (`0x1d`, `29`).
pub fn parse_meta_key(s: &str) -> Result<Option<u8>, String> {
    if s.eq_ignore_ascii_case("none") {
        return Ok(None);
    }
    let mut chars = s.chars();
    match (chars.next(), chars.next(), chars.next()) {
        (None, ..) => Err("empty meta key".to_owned()),
        (Some(c), None, _) => u8::try_from(c)
            .ok()
            .filter(u8::is_ascii)
            .map(Some)
            .ok_or_else(|| format!("meta key must be a single ASCII character, got {s:?}")),
        (Some('^'), Some(c), None) => caret_byte(c)
            .map(Some)
            .ok_or_else(|| format!("invalid caret notation {s:?}")),
        _ => {
            let value = match s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
                Some(hex) => u32::from_str_radix(hex, 16).ok(),
                None => s.parse::<u32>().ok(),
            };
            match value {
                Some(v) if v <= 0xff => Ok(Some(u8::try_from(v).expect("checked range"))),
                Some(_) => Err(format!("meta key {s:?} out of range (0..=255)")),
                None => Err(format!(
                    "invalid meta key {s:?}: use a character, ^X, 0xNN, a number, or none"
                )),
            }
        }
    }
}

/// Decode `send` text: `^X` caret sequences (`^^` is a literal caret), `\xNN`,
/// and `\n \r \t \e \\`. Anything unrecognized is passed through verbatim.
#[must_use]
pub fn decode_send_text(s: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '^' => match chars.peek().copied() {
                Some('^') => {
                    chars.next();
                    out.push(b'^');
                }
                Some(n) if caret_byte(n).is_some() => {
                    chars.next();
                    out.push(caret_byte(n).expect("checked above"));
                }
                _ => out.push(b'^'),
            },
            '\\' => match chars.peek().copied() {
                Some('n') => {
                    chars.next();
                    out.push(b'\n');
                }
                Some('r') => {
                    chars.next();
                    out.push(b'\r');
                }
                Some('t') => {
                    chars.next();
                    out.push(b'\t');
                }
                Some('e') => {
                    chars.next();
                    out.push(0x1b);
                }
                Some('\\') => {
                    chars.next();
                    out.push(b'\\');
                }
                Some('x') => {
                    let mut look = chars.clone();
                    look.next();
                    let hex: String = look.by_ref().take(2).collect();
                    let byte = if hex.len() == 2 {
                        u8::from_str_radix(&hex, 16).ok()
                    } else {
                        None
                    };
                    if let Some(b) = byte {
                        chars = look;
                        out.push(b);
                    } else {
                        out.push(b'\\');
                    }
                }
                _ => out.push(b'\\'),
            },
            other => {
                let mut buf = [0u8; 4];
                out.extend_from_slice(other.encode_utf8(&mut buf).as_bytes());
            }
        }
    }
    out
}

/// `master = …`: whether a socket-less CLI call starts a background master
/// first (docs/05-meta-shell.md, "Master mode").
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, clap::ValueEnum)]
pub enum MasterMode {
    /// Never spawn one (the default): each call connects for itself.
    #[default]
    Never,
    /// Spawn one when no socket is there, and fall back to a direct
    /// connection when that fails.
    Auto,
    /// Spawn one and fail when it does not come up.
    Always,
}

impl MasterMode {
    /// `never`/`off`/`false`, `auto`/`true`/`on`, `always`.
    pub fn parse(s: &str) -> Result<Self, String> {
        match s.trim().to_ascii_lowercase().as_str() {
            "never" | "off" | "false" | "no" => Ok(Self::Never),
            "auto" | "true" | "on" | "yes" => Ok(Self::Auto),
            "always" => Ok(Self::Always),
            other => Err(format!(
                "unknown master mode {other:?} (never, auto, always)"
            )),
        }
    }

    /// Whether a missing control socket should start a master.
    #[must_use]
    pub fn spawns(self) -> bool {
        matches!(self, Self::Auto | Self::Always)
    }
}

impl<'de> Deserialize<'de> for MasterMode {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Raw {
            Bool(bool),
            Text(String),
        }
        match Raw::deserialize(d)? {
            Raw::Bool(true) => Ok(Self::Auto),
            Raw::Bool(false) => Ok(Self::Never),
            Raw::Text(s) => Self::parse(&s).map_err(serde::de::Error::custom),
        }
    }
}

/// `~/.config/mysh/config.toml`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    /// `[defaults]`.
    pub defaults: Defaults,
    /// `[hosts.NAME]` aliases.
    pub hosts: BTreeMap<String, HostAlias>,
    /// `[groups.NAME]` host lists for `--group` (docs/05-meta-shell.md
    /// "Fleet").
    pub groups: BTreeMap<String, Group>,
}

/// `[groups.NAME]` table.
#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Group {
    /// Aliases or `HOST` forms, in fan-out order.
    pub hosts: Vec<String>,
}

/// `[defaults]` table.
#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Defaults {
    /// Meta key (`^]` built-in).
    pub escape: Option<String>,
    /// `true` behaves like `-s` everywhere.
    pub shell: Option<bool>,
    /// `true` behaves like `--accept-new` everywhere.
    pub accept_new: Option<bool>,
    /// `auto` (or `true`) starts a background master for socket-less calls.
    pub master: Option<MasterMode>,
}

/// `[hosts.NAME]` table.
#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct HostAlias {
    /// Real host (any `HOST` form); default: the alias name.
    pub host: Option<String>,
    /// Port.
    pub port: Option<u16>,
    /// Identity file (`~` is expanded by the caller).
    pub identity: Option<PathBuf>,
    /// Expected server key or fingerprint.
    pub pin: Option<String>,
    /// Forwards as `"-L spec"`, `"-R spec"`, `"-D spec"` strings.
    pub forward: Vec<String>,
    /// Environment variables: `NAME` or `NAME=VALUE`.
    pub env: Vec<String>,
    /// Go straight to a shell.
    pub shell: Option<bool>,
    /// Meta key for this host.
    pub escape: Option<String>,
    /// Master mode for this host.
    pub master: Option<MasterMode>,
}

/// Config file errors.
#[derive(Debug)]
pub enum ConfigError {
    /// Reading the file failed (other than "not found").
    Io {
        /// File that failed to read.
        path: PathBuf,
        /// Underlying error.
        source: io::Error,
    },
    /// The file is not valid TOML or has unknown keys.
    Parse(toml::de::Error),
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io { path, source } => write!(f, "reading {}: {source}", path.display()),
            Self::Parse(e) => write!(f, "config: {e}"),
        }
    }
}

impl std::error::Error for ConfigError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            Self::Parse(e) => Some(e),
        }
    }
}

impl Config {
    /// Load `path`; a missing file yields the default configuration.
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        match std::fs::read_to_string(path) {
            Ok(text) => Self::parse(&text),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(Self::default()),
            Err(source) => Err(ConfigError::Io {
                path: path.to_path_buf(),
                source,
            }),
        }
    }

    /// Parse TOML text.
    pub fn parse(text: &str) -> Result<Self, ConfigError> {
        toml::from_str(text).map_err(ConfigError::Parse)
    }
}

/// Everything needed to open a connection, after flags, alias, defaults and
/// built-ins have been merged.
#[allow(clippy::struct_excessive_bools)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Target {
    /// HOST as typed (alias name or address), for the prompt and banner.
    pub display: String,
    /// Host to connect to.
    pub host: String,
    /// Port to connect to.
    pub port: u16,
    /// `-i` or alias identity (not tilde-expanded).
    pub identity: Option<PathBuf>,
    /// `--pin` or alias pin.
    pub pin: Option<String>,
    /// `-L` forwards.
    pub local: Vec<ForwardSpec>,
    /// `-R` forwards.
    pub remote: Vec<ForwardSpec>,
    /// `-D` forwards.
    pub dynamic: Vec<ForwardSpec>,
    /// Environment to send; `None` value = read from the client environment.
    pub env: Vec<(String, Option<String>)>,
    /// Run `shell` immediately and auto-exit.
    pub shell: bool,
    /// Meta key byte; `None` disables interception.
    pub meta_key: Option<u8>,
    /// Accept unknown server keys silently.
    pub accept_new: bool,
    /// Fail on unknown server keys.
    pub strict: bool,
    /// Suppress the connect banner.
    pub quiet: bool,
    /// Ignore key files on disk.
    pub baked_only: bool,
    /// `-t`.
    pub force_pty: bool,
    /// `-T`.
    pub no_pty: bool,
    /// `-N`.
    pub no_session: bool,
    /// `--attach[=ID]`: reattach a detached session instead of opening one.
    pub attach: Option<Option<u32>>,
    /// `--no-ctl`: do not serve or use the control socket.
    pub no_ctl: bool,
    /// `--timeout`: bound on `CMD`, `put`, `get`.
    pub timeout: Option<Duration>,
    /// `--cwd`: working directory for `CMD`.
    pub cwd: Option<String>,
    /// `--master` / `master = …`: background master policy.
    pub master: MasterMode,
}

fn parse_env_item(s: &str) -> (String, Option<String>) {
    match s.split_once('=') {
        Some((name, value)) => (name.to_owned(), Some(value.to_owned())),
        None => (s.to_owned(), None),
    }
}

/// Parse an alias forward string: `"-L spec"`, `"-R spec"`, `"-D spec"`
/// (also `-Lspec`), returning the flag letter and the spec.
fn parse_alias_forward(s: &str) -> Result<(char, ForwardSpec), String> {
    let s = s.trim();
    let rest = s
        .strip_prefix('-')
        .ok_or_else(|| format!("alias forward {s:?} must start with -L, -R or -D"))?;
    let mut chars = rest.chars();
    let flag = chars
        .next()
        .ok_or_else(|| format!("alias forward {s:?} must start with -L, -R or -D"))?;
    let spec = chars.as_str().trim_start();
    if spec.is_empty() {
        return Err(format!("alias forward {s:?} is missing its spec"));
    }
    let parsed = match flag {
        'L' | 'R' => ForwardSpec::parse_local(spec)?,
        'D' => ForwardSpec::parse_dynamic(spec)?,
        other => return Err(format!("alias forward {s:?}: unknown flag -{other}")),
    };
    Ok((flag, parsed))
}

/// Merge flags, alias, `[defaults]` and built-ins into a [`Target`].
///
/// Precedence: flags > alias > defaults > built-ins. Port: `-p` >
/// `HOST:PORT` as typed > alias host port > alias `port` > 7722.
pub fn resolve_target(
    host_arg: &str,
    opts: &ConnectOpts,
    config: &Config,
) -> Result<Target, String> {
    let empty = HostAlias::default();
    let (alias, typed) = if let Some(alias) = config.hosts.get(host_arg) {
        (
            alias,
            HostSpec {
                host: host_arg.to_owned(),
                port: None,
            },
        )
    } else {
        // `pi:7100` where `pi` is an alias: the typed port overrides the alias.
        let typed: HostSpec = host_arg.parse()?;
        let alias = typed
            .port
            .and_then(|_| config.hosts.get(&typed.host))
            .unwrap_or(&empty);
        (alias, typed)
    };
    let real = match &alias.host {
        Some(h) => h.parse::<HostSpec>()?,
        None => HostSpec {
            host: typed.host.clone(),
            port: None,
        },
    };
    let port = opts
        .port
        .or(typed.port)
        .or(real.port)
        .or(alias.port)
        .unwrap_or(DEFAULT_PORT);

    let mut local = opts
        .local
        .iter()
        .map(|s| ForwardSpec::parse_local(s))
        .collect::<Result<Vec<_>, _>>()?;
    let mut remote = opts
        .remote
        .iter()
        .map(|s| ForwardSpec::parse_local(s))
        .collect::<Result<Vec<_>, _>>()?;
    let mut dynamic = opts
        .dynamic
        .iter()
        .map(|s| ForwardSpec::parse_dynamic(s))
        .collect::<Result<Vec<_>, _>>()?;
    for entry in &alias.forward {
        let (flag, spec) = parse_alias_forward(entry)?;
        match flag {
            'L' => local.push(spec),
            'R' => remote.push(spec),
            _ => dynamic.push(spec),
        }
    }

    let env = opts
        .env
        .iter()
        .chain(&alias.env)
        .map(|s| parse_env_item(s))
        .collect();

    let meta_key_text = opts
        .escape
        .as_deref()
        .or(alias.escape.as_deref())
        .or(config.defaults.escape.as_deref())
        .unwrap_or(DEFAULT_META_KEY);
    let meta_key = parse_meta_key(meta_key_text)?;

    Ok(Target {
        display: host_arg.to_owned(),
        host: real.host,
        port,
        identity: opts.identity.clone().or_else(|| alias.identity.clone()),
        pin: opts.pin.clone().or_else(|| alias.pin.clone()),
        local,
        remote,
        dynamic,
        env,
        shell: opts.shell || alias.shell.or(config.defaults.shell).unwrap_or(false),
        meta_key,
        accept_new: opts.accept_new || config.defaults.accept_new.unwrap_or(false),
        strict: opts.strict,
        quiet: opts.quiet,
        baked_only: opts.baked_only,
        force_pty: opts.force_pty,
        no_pty: opts.no_pty,
        no_session: opts.no_session,
        attach: opts.attach,
        no_ctl: opts.no_ctl,
        timeout: opts.timeout,
        cwd: opts.cwd.clone(),
        master: opts
            .master
            .or(alias.master)
            .or(config.defaults.master)
            .unwrap_or_default(),
    })
}

/// Where an identity may come from, in resolution order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum IdentitySource {
    /// `-i PATH` / `--key PATH`.
    Flag(PathBuf),
    /// `$MYSH_IDENTITY` / `$MYSH_HOST_KEY`.
    Env(PathBuf),
    /// Compiled-in identity.
    Baked,
    /// A well-known file on disk.
    File(PathBuf),
}

/// Client identity candidates, first match wins:
/// `-i` → `$MYSH_IDENTITY` → baked → `config_dir/id` → `~/.ssh/id_ed25519`
/// (the files are skipped with `baked_only`).
#[must_use]
pub fn client_identity_candidates(
    flag: Option<&Path>,
    paths: &Paths,
    baked_available: bool,
    baked_only: bool,
) -> Vec<IdentitySource> {
    client_identity_candidates_with(flag, paths, baked_available, baked_only, &process_env)
}

pub(crate) fn client_identity_candidates_with(
    flag: Option<&Path>,
    paths: &Paths,
    baked_available: bool,
    baked_only: bool,
    env: EnvFn<'_>,
) -> Vec<IdentitySource> {
    let mut out = Vec::new();
    if let Some(p) = flag {
        out.push(IdentitySource::Flag(p.to_path_buf()));
    }
    if let Some(p) = env_path(env, "MYSH_IDENTITY") {
        out.push(IdentitySource::Env(p));
    }
    if baked_available {
        out.push(IdentitySource::Baked);
    }
    if !baked_only {
        out.push(IdentitySource::File(paths.identity.clone()));
        if let Some(ssh) = &paths.ssh_dir {
            out.push(IdentitySource::File(ssh.join("id_ed25519")));
        }
    }
    out
}

/// Server identity candidates, first match wins:
/// `--key` → `$MYSH_HOST_KEY` → baked → `config_dir/host_key` (skipped with
/// `baked_only`).
#[must_use]
pub fn server_identity_candidates(
    flag: Option<&Path>,
    paths: &Paths,
    baked_available: bool,
    baked_only: bool,
) -> Vec<IdentitySource> {
    server_identity_candidates_with(flag, paths, baked_available, baked_only, &process_env)
}

pub(crate) fn server_identity_candidates_with(
    flag: Option<&Path>,
    paths: &Paths,
    baked_available: bool,
    baked_only: bool,
    env: EnvFn<'_>,
) -> Vec<IdentitySource> {
    let mut out = Vec::new();
    if let Some(p) = flag {
        out.push(IdentitySource::Flag(p.to_path_buf()));
    }
    if let Some(p) = env_path(env, "MYSH_HOST_KEY") {
        out.push(IdentitySource::Env(p));
    }
    if baked_available {
        out.push(IdentitySource::Baked);
    }
    if !baked_only {
        out.push(IdentitySource::File(paths.host_key.clone()));
    }
    out
}

/// Expand a leading `~` or `~/` to `home`; `~user` and everything else are
/// returned unchanged.
#[must_use]
pub fn expand_tilde(path: &str, home: &Path) -> PathBuf {
    if path == "~" {
        return home.to_path_buf();
    }
    match path.strip_prefix("~/") {
        Some(rest) => home.join(rest),
        None => PathBuf::from(path),
    }
}

/// Parse a duration: a bare number of seconds, or a number with a unit
/// (`ms`, `s`, `m`, `h`), e.g. `500ms`, `10s`, `2m`, `1h`. Fractions are
/// accepted (`1.5s`); the result is rounded to milliseconds.
pub fn parse_duration(s: &str) -> Result<Duration, String> {
    let text = s.trim();
    if text.is_empty() {
        return Err("empty duration".to_owned());
    }
    let digits = text
        .trim_end_matches(|c: char| c.is_ascii_alphabetic())
        .trim_end();
    let unit = text[digits.len()..].trim();
    let value: f64 = digits
        .parse()
        .map_err(|_| format!("invalid duration {s:?}"))?;
    if !value.is_finite() || value < 0.0 {
        return Err(format!("invalid duration {s:?}"));
    }
    let millis = match unit {
        "" | "s" | "sec" | "secs" => value * 1000.0,
        "ms" => value,
        "m" | "min" | "mins" => value * 60_000.0,
        "h" | "hr" | "hrs" => value * 3_600_000.0,
        other => return Err(format!("unknown duration unit {other:?} in {s:?}")),
    };
    // `2^63` as an f64 is exact and far past any sane duration.
    if millis >= 9_223_372_036_854_775_808.0 {
        return Err(format!("duration {s:?} is out of range"));
    }
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    // bounded above, non-negative
    Ok(Duration::from_millis(millis.round() as u64))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env_from<'a>(pairs: &'a [(&'a str, &'a str)]) -> impl Fn(&str) -> Option<String> + 'a {
        move |k| {
            pairs
                .iter()
                .find(|(n, _)| *n == k)
                .map(|(_, v)| (*v).to_owned())
        }
    }

    #[test]
    fn paths_honour_mysh_config_dir() {
        let env = env_from(&[("MYSH_CONFIG_DIR", "/tmp/mysh-cfg"), ("HOME", "/home/u")]);
        let p = Paths::from_env_with(&env);
        assert_eq!(p.config_dir, PathBuf::from("/tmp/mysh-cfg"));
        assert_eq!(p.identity, PathBuf::from("/tmp/mysh-cfg/id"));
        assert_eq!(p.host_key, PathBuf::from("/tmp/mysh-cfg/host_key"));
        assert_eq!(
            p.authorized_keys,
            PathBuf::from("/tmp/mysh-cfg/authorized_keys")
        );
        assert_eq!(p.known_hosts, PathBuf::from("/tmp/mysh-cfg/known_hosts"));
        assert_eq!(p.config_file, PathBuf::from("/tmp/mysh-cfg/config.toml"));
        assert_eq!(
            p.history,
            PathBuf::from("/home/u/.local/state/mysh/history")
        );
        assert_eq!(p.runtime_dir, PathBuf::from("/home/u/.cache/mysh"));
        assert_eq!(p.ssh_dir, Some(PathBuf::from("/home/u/.ssh")));
        assert_eq!(p.agent_socket, None);
    }

    #[test]
    fn paths_take_agent_socket_from_env_ignoring_empty() {
        let env = env_from(&[("HOME", "/home/u"), ("SSH_AUTH_SOCK", "/tmp/agent.sock")]);
        assert_eq!(
            Paths::from_env_with(&env).agent_socket,
            Some(PathBuf::from("/tmp/agent.sock"))
        );
        let env = env_from(&[("HOME", "/home/u"), ("SSH_AUTH_SOCK", "")]);
        assert_eq!(Paths::from_env_with(&env).agent_socket, None);
    }

    #[test]
    fn paths_fall_back_to_xdg_then_home() {
        let env = env_from(&[
            ("XDG_CONFIG_HOME", "/xdg/cfg"),
            ("XDG_STATE_HOME", "/xdg/state"),
            ("XDG_RUNTIME_DIR", "/run/user/1"),
            ("HOME", "/home/u"),
        ]);
        let p = Paths::from_env_with(&env);
        assert_eq!(p.config_dir, PathBuf::from("/xdg/cfg/mysh"));
        assert_eq!(p.history, PathBuf::from("/xdg/state/mysh/history"));
        assert_eq!(p.runtime_dir, PathBuf::from("/run/user/1/mysh"));

        let env = env_from(&[("HOME", "/home/u"), ("XDG_CONFIG_HOME", "")]);
        let p = Paths::from_env_with(&env);
        assert_eq!(p.config_dir, PathBuf::from("/home/u/.config/mysh"));
    }

    #[test]
    fn host_spec_forms() {
        let s: HostSpec = "pi.lan".parse().expect("host");
        assert_eq!(
            s,
            HostSpec {
                host: "pi.lan".into(),
                port: None
            }
        );
        let s: HostSpec = "pi.lan:7000".parse().expect("host:port");
        assert_eq!(
            s,
            HostSpec {
                host: "pi.lan".into(),
                port: Some(7000)
            }
        );
        let s: HostSpec = "[fe80::1]:7000".parse().expect("[v6]:port");
        assert_eq!(
            s,
            HostSpec {
                host: "fe80::1".into(),
                port: Some(7000)
            }
        );
        let s: HostSpec = "[fe80::1]".parse().expect("[v6]");
        assert_eq!(
            s,
            HostSpec {
                host: "fe80::1".into(),
                port: None
            }
        );
        let s: HostSpec = "fe80::1".parse().expect("bare v6");
        assert_eq!(
            s,
            HostSpec {
                host: "fe80::1".into(),
                port: None
            }
        );
        assert!("".parse::<HostSpec>().is_err());
        assert!(":22".parse::<HostSpec>().is_err());
        assert!("host:notaport".parse::<HostSpec>().is_err());
        assert!("[fe80::1".parse::<HostSpec>().is_err());
        assert!("[fe80::1]x".parse::<HostSpec>().is_err());
    }

    #[test]
    fn forward_spec_local() {
        assert_eq!(
            ForwardSpec::parse_local("8080:localhost:80").expect("spec"),
            ForwardSpec {
                bind: "127.0.0.1".into(),
                port: 8080,
                target: Some(("localhost".into(), 80)),
            }
        );
        assert_eq!(
            ForwardSpec::parse_local("[::1]:8080:[::1]:80").expect("v6 spec"),
            ForwardSpec {
                bind: "::1".into(),
                port: 8080,
                target: Some(("::1".into(), 80))
            }
        );
        assert_eq!(
            ForwardSpec::parse_local("0.0.0.0:8080:host:80")
                .expect("bind spec")
                .bind,
            "0.0.0.0"
        );
        assert_eq!(
            ForwardSpec::parse_local("*:8080:host:80")
                .expect("star")
                .bind,
            "0.0.0.0"
        );
        assert!(ForwardSpec::parse_local("8080").is_err());
        assert!(ForwardSpec::parse_local("8080:host").is_err());
        assert!(ForwardSpec::parse_local("a:b:c:d:e").is_err());
        assert!(ForwardSpec::parse_local("x:host:80").is_err());
        assert!(ForwardSpec::parse_local("8080::80").is_err());
        assert!(ForwardSpec::parse_local("8080:host:0").is_err());
        assert!(ForwardSpec::parse_local("[::1:8080:host:80").is_err());
    }

    #[test]
    fn forward_spec_dynamic() {
        assert_eq!(
            ForwardSpec::parse_dynamic("1080").expect("port"),
            ForwardSpec {
                bind: "127.0.0.1".into(),
                port: 1080,
                target: None
            }
        );
        assert_eq!(
            ForwardSpec::parse_dynamic("127.0.0.1:1080").expect("bind:port"),
            ForwardSpec {
                bind: "127.0.0.1".into(),
                port: 1080,
                target: None
            }
        );
        assert_eq!(
            ForwardSpec::parse_dynamic("[::1]:1080").expect("[v6]:port"),
            ForwardSpec {
                bind: "::1".into(),
                port: 1080,
                target: None
            }
        );
        assert!(ForwardSpec::parse_dynamic("a:b:c").is_err());
        assert!(ForwardSpec::parse_dynamic("nope").is_err());
    }

    #[test]
    fn meta_key_table() {
        assert_eq!(parse_meta_key("none"), Ok(None));
        assert_eq!(parse_meta_key("NONE"), Ok(None));
        assert_eq!(parse_meta_key("^]"), Ok(Some(0x1d)));
        assert_eq!(parse_meta_key("^?"), Ok(Some(0x7f)));
        assert_eq!(parse_meta_key("^@"), Ok(Some(0)));
        assert_eq!(parse_meta_key("^A"), Ok(Some(1)));
        assert_eq!(parse_meta_key("^a"), Ok(Some(1)));
        assert_eq!(parse_meta_key("^Z"), Ok(Some(26)));
        assert_eq!(parse_meta_key("^^"), Ok(Some(0x1e)));
        assert_eq!(parse_meta_key("^\\"), Ok(Some(0x1c)));
        assert_eq!(parse_meta_key("~"), Ok(Some(b'~')));
        assert_eq!(parse_meta_key("7"), Ok(Some(b'7')));
        assert_eq!(parse_meta_key("0x1d"), Ok(Some(0x1d)));
        assert_eq!(parse_meta_key("0x1D"), Ok(Some(0x1d)));
        assert_eq!(parse_meta_key("29"), Ok(Some(29)));
        assert!(parse_meta_key("").is_err());
        assert!(parse_meta_key("é").is_err());
        assert!(parse_meta_key("^1").is_err());
        assert!(parse_meta_key("300").is_err());
        assert!(parse_meta_key("ctrl-x").is_err());
    }

    #[test]
    fn send_text_decoding() {
        assert_eq!(decode_send_text("^]"), vec![0x1d]);
        assert_eq!(decode_send_text("^C"), vec![3]);
        assert_eq!(decode_send_text("^c"), vec![3]);
        assert_eq!(decode_send_text("^^"), b"^".to_vec());
        assert_eq!(decode_send_text("a^"), b"a^".to_vec());
        assert_eq!(decode_send_text("^1"), b"^1".to_vec());
        assert_eq!(decode_send_text("\\x1b[A"), vec![0x1b, b'[', b'A']);
        assert_eq!(
            decode_send_text("\\n\\r\\t\\e\\\\"),
            vec![b'\n', b'\r', b'\t', 0x1b, b'\\']
        );
        assert_eq!(decode_send_text("\\xZZ"), b"\\xZZ".to_vec());
        assert_eq!(decode_send_text("\\x1"), b"\\x1".to_vec());
        assert_eq!(decode_send_text("\\q"), b"\\q".to_vec());
        assert_eq!(decode_send_text("trailing\\"), b"trailing\\".to_vec());
        assert_eq!(decode_send_text("ls -la\\n"), b"ls -la\n".to_vec());
        assert_eq!(decode_send_text("é"), "é".as_bytes().to_vec());
    }

    const DOCS_EXAMPLE: &str = r#"
[defaults]
escape = "^]"          # meta key
shell = false          # true = behave like `-s` everywhere

[hosts.pi]
host = "pi.lan"
port = 7722
identity = "~/.ssh/id_ed25519"
pin = "SHA256:abc"
forward = ["-L 8080:localhost:80"]
env = ["LANG"]
shell = true           # `mysh pi` goes straight to a shell
"#;

    #[test]
    fn config_parses_docs_example() {
        let c = Config::parse(DOCS_EXAMPLE).expect("docs example parses");
        assert_eq!(c.defaults.escape.as_deref(), Some("^]"));
        assert_eq!(c.defaults.shell, Some(false));
        assert_eq!(c.defaults.accept_new, None);
        let pi = c.hosts.get("pi").expect("pi alias");
        assert_eq!(pi.host.as_deref(), Some("pi.lan"));
        assert_eq!(pi.port, Some(7722));
        assert_eq!(pi.identity, Some(PathBuf::from("~/.ssh/id_ed25519")));
        assert_eq!(pi.pin.as_deref(), Some("SHA256:abc"));
        assert_eq!(pi.forward, ["-L 8080:localhost:80"]);
        assert_eq!(pi.env, ["LANG"]);
        assert_eq!(pi.shell, Some(true));
        assert_eq!(Config::parse("").expect("empty ok"), Config::default());
    }

    #[test]
    fn config_rejects_unknown_fields() {
        assert!(Config::parse("[defaults]\nescpae = \"^]\"\n").is_err());
        assert!(Config::parse("[hosts.pi]\nhots = \"pi.lan\"\n").is_err());
        assert!(Config::parse("[bogus]\nx = 1\n").is_err());
        assert!(Config::parse("not toml at all [[[").is_err());
    }

    #[test]
    fn config_load_missing_file_is_default() {
        let dir = std::env::temp_dir().join(format!("mysh-config-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("temp dir");
        let missing = dir.join("nope.toml");
        assert_eq!(
            Config::load(&missing).expect("missing is default"),
            Config::default()
        );
        let present = dir.join("config.toml");
        std::fs::write(&present, DOCS_EXAMPLE).expect("write");
        assert!(
            Config::load(&present)
                .expect("loads")
                .hosts
                .contains_key("pi")
        );
        std::fs::remove_dir_all(&dir).expect("cleanup");
    }

    fn fixture() -> Config {
        let mut hosts = BTreeMap::new();
        hosts.insert(
            "pi".to_owned(),
            HostAlias {
                host: Some("pi.lan".to_owned()),
                port: Some(7000),
                identity: Some(PathBuf::from("~/.ssh/id_ed25519")),
                pin: Some("SHA256:alias".to_owned()),
                forward: vec![
                    "-L 8080:localhost:80".to_owned(),
                    "-R 2222:localhost:22".to_owned(),
                    "-D 1080".to_owned(),
                ],
                env: vec!["LANG".to_owned(), "FOO=bar".to_owned()],
                shell: Some(true),
                escape: Some("^\\".to_owned()),
                master: None,
            },
        );
        hosts.insert(
            "plain".to_owned(),
            HostAlias {
                host: Some("plain.lan:9000".to_owned()),
                ..HostAlias::default()
            },
        );
        Config {
            defaults: Defaults {
                escape: Some("^@".to_owned()),
                shell: Some(false),
                accept_new: Some(true),
                master: Some(MasterMode::Auto),
            },
            hosts,
            groups: BTreeMap::new(),
        }
    }

    #[test]
    fn resolve_builtins_when_nothing_configured() {
        let t = resolve_target("example.org", &ConnectOpts::default(), &Config::default())
            .expect("resolves");
        assert_eq!(t.display, "example.org");
        assert_eq!(t.host, "example.org");
        assert_eq!(t.port, DEFAULT_PORT);
        assert_eq!(t.meta_key, Some(0x1d));
        assert!(!t.shell && !t.accept_new && !t.strict);
        assert!(t.identity.is_none() && t.pin.is_none());
        assert!(t.local.is_empty() && t.remote.is_empty() && t.dynamic.is_empty());
        assert_eq!(
            t.env,
            [] as [(
                std::string::String,
                std::option::Option<std::string::String>
            ); 0]
        );
    }

    #[test]
    fn resolve_alias_over_defaults() {
        let t = resolve_target("pi", &ConnectOpts::default(), &fixture()).expect("resolves");
        assert_eq!(t.display, "pi");
        assert_eq!(t.host, "pi.lan");
        assert_eq!(t.port, 7000);
        assert_eq!(t.identity, Some(PathBuf::from("~/.ssh/id_ed25519")));
        assert_eq!(t.pin.as_deref(), Some("SHA256:alias"));
        assert_eq!(t.local.len(), 1);
        assert_eq!(t.local[0].port, 8080);
        assert_eq!(t.remote.len(), 1);
        assert_eq!(t.remote[0].target, Some(("localhost".to_owned(), 22)));
        assert_eq!(t.dynamic.len(), 1);
        assert_eq!(t.dynamic[0].port, 1080);
        assert_eq!(
            t.env,
            vec![
                ("LANG".to_owned(), None),
                ("FOO".to_owned(), Some("bar".to_owned()))
            ]
        );
        assert!(t.shell, "alias shell beats defaults.shell=false");
        assert_eq!(t.meta_key, Some(0x1c), "alias escape beats defaults");
        assert!(t.accept_new, "defaults.accept_new applies");
    }

    #[test]
    fn resolve_defaults_over_builtins() {
        let t = resolve_target("other.lan", &ConnectOpts::default(), &fixture()).expect("resolves");
        assert_eq!(t.host, "other.lan");
        assert_eq!(t.port, DEFAULT_PORT);
        assert_eq!(t.meta_key, Some(0), "defaults.escape beats built-in");
        assert!(!t.shell);
        assert!(t.accept_new);
    }

    #[test]
    fn resolve_flags_over_alias() {
        let opts = ConnectOpts {
            port: Some(1),
            identity: Some(PathBuf::from("/k")),
            pin: Some("SHA256:flag".to_owned()),
            escape: Some("none".to_owned()),
            local: vec!["1:2:3".to_owned()],
            env: vec!["TERM=xterm".to_owned()],
            strict: true,
            quiet: true,
            no_pty: true,
            ..ConnectOpts::default()
        };
        let t = resolve_target("pi", &opts, &fixture()).expect("resolves");
        assert_eq!(t.port, 1);
        assert_eq!(t.identity, Some(PathBuf::from("/k")));
        assert_eq!(t.pin.as_deref(), Some("SHA256:flag"));
        assert_eq!(t.meta_key, None);
        assert_eq!(t.local.len(), 2, "flag forwards come first, then alias");
        assert_eq!(t.local[0].port, 1);
        assert_eq!(t.local[1].port, 8080);
        assert_eq!(t.env[0], ("TERM".to_owned(), Some("xterm".to_owned())));
        assert!(t.strict && t.quiet && t.no_pty);
        assert!(!t.force_pty && !t.no_session && !t.baked_only);
    }

    #[test]
    fn resolve_port_precedence() {
        // HOST:PORT as typed beats the alias port, -p beats both.
        let t = resolve_target("pi:7100", &ConnectOpts::default(), &fixture()).expect("resolves");
        assert_eq!(t.host, "pi.lan");
        assert_eq!(t.port, 7100);
        let opts = ConnectOpts {
            port: Some(7200),
            ..ConnectOpts::default()
        };
        let t = resolve_target("pi:7100", &opts, &fixture()).expect("resolves");
        assert_eq!(t.port, 7200);
        // A port inside the alias host string counts as the alias port.
        let t = resolve_target("plain", &ConnectOpts::default(), &fixture()).expect("resolves");
        assert_eq!(t.host, "plain.lan");
        assert_eq!(t.port, 9000);
        // Typed host:port without an alias.
        let t = resolve_target("[::1]:7300", &ConnectOpts::default(), &Config::default())
            .expect("resolves");
        assert_eq!(t.host, "::1");
        assert_eq!(t.port, 7300);
    }

    #[test]
    fn resolve_reports_bad_specs() {
        let opts = ConnectOpts {
            local: vec!["nope".to_owned()],
            ..ConnectOpts::default()
        };
        assert!(resolve_target("h", &opts, &Config::default()).is_err());
        let opts = ConnectOpts {
            escape: Some("ctrl-x".to_owned()),
            ..ConnectOpts::default()
        };
        assert!(resolve_target("h", &opts, &Config::default()).is_err());
        let mut cfg = Config::default();
        cfg.hosts.insert(
            "bad".to_owned(),
            HostAlias {
                forward: vec!["-X 1:2:3".to_owned()],
                ..HostAlias::default()
            },
        );
        assert!(resolve_target("bad", &ConnectOpts::default(), &cfg).is_err());
        cfg.hosts.insert(
            "bad".to_owned(),
            HostAlias {
                forward: vec!["8080:host:80".to_owned()],
                ..HostAlias::default()
            },
        );
        assert!(resolve_target("bad", &ConnectOpts::default(), &cfg).is_err());
    }

    #[test]
    fn client_identity_order() {
        let mut paths = Paths::build(
            PathBuf::from("/cfg"),
            PathBuf::from("/h"),
            PathBuf::from("/run"),
            Some(PathBuf::from("/home/u/.ssh")),
            None,
        );
        let none = env_from(&[]);
        let got = client_identity_candidates_with(None, &paths, false, false, &none);
        assert_eq!(
            got,
            vec![
                IdentitySource::File(PathBuf::from("/cfg/id")),
                IdentitySource::File(PathBuf::from("/home/u/.ssh/id_ed25519")),
            ]
        );
        let env = env_from(&[("MYSH_IDENTITY", "/env/key")]);
        let got =
            client_identity_candidates_with(Some(Path::new("/flag")), &paths, true, false, &env);
        assert_eq!(
            got,
            vec![
                IdentitySource::Flag(PathBuf::from("/flag")),
                IdentitySource::Env(PathBuf::from("/env/key")),
                IdentitySource::Baked,
                IdentitySource::File(PathBuf::from("/cfg/id")),
                IdentitySource::File(PathBuf::from("/home/u/.ssh/id_ed25519")),
            ]
        );
        let got = client_identity_candidates_with(None, &paths, true, true, &none);
        assert_eq!(got, vec![IdentitySource::Baked]);
        paths.ssh_dir = None;
        let got = client_identity_candidates_with(None, &paths, false, false, &none);
        assert_eq!(got, vec![IdentitySource::File(PathBuf::from("/cfg/id"))]);
    }

    #[test]
    fn server_identity_order() {
        let paths = Paths::build(
            PathBuf::from("/cfg"),
            PathBuf::from("/h"),
            PathBuf::from("/run"),
            None,
            None,
        );
        let none = env_from(&[]);
        assert_eq!(
            server_identity_candidates_with(None, &paths, false, false, &none),
            vec![IdentitySource::File(PathBuf::from("/cfg/host_key"))]
        );
        let env = env_from(&[("MYSH_HOST_KEY", "/etc/ssh/ssh_host_ed25519_key")]);
        assert_eq!(
            server_identity_candidates_with(Some(Path::new("/k")), &paths, true, false, &env),
            vec![
                IdentitySource::Flag(PathBuf::from("/k")),
                IdentitySource::Env(PathBuf::from("/etc/ssh/ssh_host_ed25519_key")),
                IdentitySource::Baked,
                IdentitySource::File(PathBuf::from("/cfg/host_key")),
            ]
        );
        assert_eq!(
            server_identity_candidates_with(None, &paths, true, true, &none),
            vec![IdentitySource::Baked]
        );
    }

    #[test]
    fn tilde_expansion() {
        let home = Path::new("/home/u");
        assert_eq!(expand_tilde("~", home), PathBuf::from("/home/u"));
        assert_eq!(
            expand_tilde("~/.ssh/id", home),
            PathBuf::from("/home/u/.ssh/id")
        );
        assert_eq!(expand_tilde("~other/x", home), PathBuf::from("~other/x"));
        assert_eq!(expand_tilde("/abs", home), PathBuf::from("/abs"));
        assert_eq!(expand_tilde("rel", home), PathBuf::from("rel"));
    }
}
