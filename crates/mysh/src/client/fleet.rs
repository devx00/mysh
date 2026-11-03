//! Fleet fan-out (docs/05-meta-shell.md "Fleet"): `mysh run`, `put --hosts`
//! and `get --hosts` run the same command on several hosts at once.
//!
//! Every host is resolved like a normal target (aliases apply), then its
//! command runs through the control socket of a running master or client
//! when there is one (`master = auto` starts one), else on a fresh
//! connection of this process. Each host gets a capture console in a JSON
//! mode, so the per-host results are the same documents the single-host
//! commands print; this module only attributes and collects them.

use std::{fmt::Write as _, path::PathBuf, sync::Arc};

use anyhow::{Context as _, Result, anyhow, bail};
use tokio::{sync::Semaphore, task::JoinSet};
use tracing::debug;

use super::{
    conn::connect,
    console::{CaptureEvent, Console},
    ctl,
    forward::Forwards,
    master,
    meta::Ctx,
    shared::Shared,
};
use crate::{
    cli::{ConnectOpts, DEFAULT_FLEET_JOBS, GetArgs, PutArgs, RunArgs, parse_meta_argv},
    config::{Config, MasterMode, Paths, Target, resolve_target},
    identity::Baked,
    output::{
        Bytes, ErrorBody, ErrorOut, Event, Mode, RunResult, TransferOut, TransferResult, code_for,
        coded, codes,
    },
};

/// Split a `--hosts` value on commas; surrounding whitespace is dropped
/// and empty items are skipped.
#[must_use]
pub fn parse_hosts(list: &str) -> Vec<String> {
    list.split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
        .collect()
}

/// The hosts of `--hosts` (each split by [`parse_hosts`]) followed by those
/// of every `--group`, in order, duplicates removed. `Err` names an unknown
/// group, or says that nothing was selected.
pub fn expand_hosts(
    hosts: &[String],
    groups: &[String],
    config: &Config,
) -> Result<Vec<String>, String> {
    let mut out: Vec<String> = Vec::new();
    let mut push = |host: &str| {
        if !out.iter().any(|h| h == host) {
            out.push(host.to_owned());
        }
    };
    for list in hosts {
        for host in parse_hosts(list) {
            push(&host);
        }
    }
    for name in groups {
        let group = config
            .groups
            .get(name)
            .ok_or_else(|| format!("no [groups.{name}] in the config file"))?;
        for host in &group.hosts {
            for host in parse_hosts(host) {
                push(&host);
            }
        }
    }
    if out.is_empty() {
        return Err("no hosts: give --hosts a,b,… or --group NAME".to_owned());
    }
    Ok(out)
}

/// What the fan-out runs on each host and how its output is read back.
#[derive(Clone)]
struct Plan {
    paths: Arc<Paths>,
    baked: Arc<Baked>,
    /// Prompt words of the command (also the control-socket request).
    argv: Vec<String>,
    /// Mode of each host's capture console.
    capture: Mode,
    /// Per-host argv adjustment (`get` picks the destination directory).
    adjust: Option<Arc<Adjust>>,
}

type Adjust = dyn Fn(&str, &mut Vec<String>) -> Result<()> + Send + Sync;

/// A host of the fan-out, resolved up front.
struct Member {
    host: String,
    target: Result<Target>,
}

/// Resolve every host; a bad one becomes an error result, not a usage
/// error for the whole run.
fn members(opts: &ConnectOpts, config: &Config) -> Result<Vec<Member>> {
    let hosts = expand_hosts(&opts.hosts, &opts.group, config)
        .map_err(|e| coded(codes::USAGE, anyhow!(e)))?;
    Ok(hosts
        .into_iter()
        .map(|host| {
            let target = resolve_target(&host, opts, config)
                .map_err(|e| coded(codes::USAGE, anyhow!(e)))
                .with_context(|| format!("resolving {host}"));
            Member { host, target }
        })
        .collect())
}

/// `mysh run`: one exec per host, `-j` at a time. Returns 0 when every
/// host exited 0, else 1.
pub async fn run(
    args: RunArgs,
    config: &Config,
    paths: Paths,
    baked: Baked,
    mode: Mode,
) -> Result<i32> {
    let members = members(&args.opts, config)?;
    let mut words = vec!["exec".to_owned()];
    if let Some(dir) = &args.opts.cwd {
        words.push("--cwd".to_owned());
        words.push(dir.clone());
    }
    if let Some(limit) = args.opts.timeout {
        words.push("--timeout".to_owned());
        words.push(format!("{}ms", limit.as_millis()));
    }
    words.push("--".to_owned());
    words.extend(args.command.iter().cloned());
    let plan = Plan {
        paths: Arc::new(paths),
        baked: Arc::new(baked),
        argv: words,
        capture: Mode::JsonStream,
        adjust: None,
    };
    let console = Console::with_mode(mode);
    let results = fan_out(
        members,
        plan,
        args.concurrency(),
        &console,
        RunCollector::new,
    )
    .await;
    match mode {
        Mode::Human => print_summary(&console, &results, true),
        Mode::Plain => print_summary(&console, &results, false),
        Mode::Json | Mode::JsonStream => {}
    }
    finish(&console, &results).await
}

/// `mysh put --hosts … LOCAL… REMOTE`: the same transfer to every host.
pub async fn put(
    opts: &ConnectOpts,
    args: &PutArgs,
    config: &Config,
    paths: Paths,
    baked: Baked,
    mode: Mode,
) -> Result<i32> {
    let members = members(opts, config)?;
    let plan = Plan {
        paths: Arc::new(paths),
        baked: Arc::new(baked),
        argv: args.to_argv(),
        capture: Mode::Json,
        adjust: None,
    };
    let console = Console::with_mode(mode);
    let results = fan_out(
        members,
        plan,
        DEFAULT_FLEET_JOBS,
        &console,
        TransferCollector::new,
    )
    .await;
    finish(&console, &results).await
}

/// `mysh get --hosts … REMOTE… LOCALDIR`: every host's files land in
/// `LOCALDIR/<host>/` (created on demand).
pub async fn get(
    opts: &ConnectOpts,
    args: &GetArgs,
    config: &Config,
    paths: Paths,
    baked: Baked,
    mode: Mode,
) -> Result<i32> {
    let members = members(opts, config)?;
    let local_cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    let (remotes, local) = match args.paths.split_last() {
        Some((local, remotes)) if !remotes.is_empty() => (remotes.to_vec(), local_cwd.join(local)),
        _ => (args.paths.clone(), local_cwd),
    };
    let paths_given = args.paths.len();
    let adjust = move |host: &str, argv: &mut Vec<String>| -> Result<()> {
        let dir = local.join(host.replace('/', "_"));
        std::fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;
        // `to_argv` ends with `-- PATH…`: replace the paths.
        argv.truncate(argv.len() - paths_given);
        argv.extend(remotes.iter().cloned());
        argv.push(dir.display().to_string());
        Ok(())
    };
    let plan = Plan {
        paths: Arc::new(paths),
        baked: Arc::new(baked),
        argv: args.to_argv(),
        capture: Mode::Json,
        adjust: Some(Arc::new(adjust)),
    };
    let console = Console::with_mode(mode);
    let results = fan_out(
        members,
        plan,
        DEFAULT_FLEET_JOBS,
        &console,
        TransferCollector::new,
    )
    .await;
    finish(&console, &results).await
}

/// The final document (the array in `Json` mode, a `result` event in
/// `JsonStream` mode; text modes streamed their lines) and the exit code.
async fn finish<R: HostResult>(console: &Console, results: &[R]) -> Result<i32> {
    match console.mode() {
        Mode::Json => console.emit(&results),
        Mode::JsonStream => console.event(&Event::Result {
            value: serde_json::to_value(results).unwrap_or_default(),
        }),
        Mode::Human | Mode::Plain => {}
    }
    console.flush().await;
    Ok(i32::from(!results.iter().all(HostResult::ok)))
}

/// A result of one host, whatever the command.
trait HostResult: serde::Serialize + Send + 'static {
    fn ok(&self) -> bool;
}

impl HostResult for RunResult {
    fn ok(&self) -> bool {
        self.ok
    }
}

impl HostResult for TransferResult {
    fn ok(&self) -> bool {
        self.ok
    }
}

/// Folds one host's capture events (and the command's outcome) into its
/// result; also prints the host's attributed lines on the main console.
trait Collector: Send + 'static {
    type Out: HostResult;
    fn event(&mut self, ev: CaptureEvent);
    /// `outcome` is what the command returned: its exit code, or the error
    /// that kept it from running (connect, trust, control socket).
    fn finish(self, outcome: Result<i32>) -> Self::Out;
}

/// Run `plan` on every member, `jobs` at a time; results in member order.
#[allow(clippy::needless_pass_by_value)] // `plan` is cloned into every task
async fn fan_out<C: Collector>(
    members: Vec<Member>,
    plan: Plan,
    jobs: usize,
    console: &Console,
    collector: fn(String, Console) -> C,
) -> Vec<C::Out> {
    let limit = Arc::new(Semaphore::new(jobs.max(1)));
    let mut tasks = JoinSet::new();
    let mut results: Vec<Option<C::Out>> = Vec::with_capacity(members.len());
    for (index, member) in members.into_iter().enumerate() {
        results.push(None);
        let mut plan = plan.clone();
        let target = member.target.and_then(|target| match &plan.adjust {
            Some(adjust) => adjust(&member.host, &mut plan.argv).map(|()| target),
            None => Ok(target),
        });
        let target = match target {
            Ok(target) => target,
            Err(e) => {
                // Nothing to run: the collector only sees the outcome.
                results[index] = Some(collector(member.host, console.clone()).finish(Err(e)));
                continue;
            }
        };
        let limit = Arc::clone(&limit);
        let mut collect = collector(member.host.clone(), console.clone());
        tasks.spawn(async move {
            let _permit = limit.acquire_owned().await;
            let (capture, mut rx) = Console::capture_with_mode(plan.capture);
            let mut worker = tokio::spawn({
                let capture = capture.clone();
                async move {
                    let outcome = run_host(&target, &plan, &capture).await;
                    drop(capture);
                    outcome
                }
            });
            drop(capture);
            // Session reader tasks keep console clones briefly after the
            // command returns, so the worker's end (not `Done`) ends the
            // loop; whatever is still queued is drained first.
            let outcome = loop {
                tokio::select! {
                    ev = rx.recv() => match ev {
                        Some(CaptureEvent::Done) | None => break worker.await,
                        Some(ev) => collect.event(ev),
                    },
                    joined = &mut worker => {
                        while let Some(ev) = rx.try_recv() {
                            if !matches!(ev, CaptureEvent::Done) {
                                collect.event(ev);
                            }
                        }
                        break joined;
                    }
                }
            };
            let outcome = outcome.unwrap_or_else(|e| Err(anyhow!("fleet task failed: {e}")));
            (index, collect.finish(outcome))
        });
    }
    while let Some(joined) = tasks.join_next().await {
        match joined {
            Ok((index, result)) => results[index] = Some(result),
            Err(e) => debug!(error = %e, "fleet task failed"),
        }
    }
    results.into_iter().flatten().collect()
}

/// Run the plan's command on one host: through its control socket when
/// one answers, else on a connection of this process. The exit code is the
/// command's; `Err` is a failure before it could run (connect, trust,
/// socket) or a lost connection.
async fn run_host(target: &Target, plan: &Plan, console: &Console) -> Result<i32> {
    if !target.no_ctl {
        if target.master.spawns()
            && let Err(e) = master::ensure(&plan.paths, target, None).await
        {
            if target.master == MasterMode::Always {
                return Err(e.context("starting the master"));
            }
            debug!(host = %target.display, error = %e, "master not started");
        }
        if ctl::socket_ready(&plan.paths, target).await
            && let Some(code) =
                ctl::request(&plan.paths, target, plan.argv.clone(), console, Vec::new())
                    .await
                    .context("control socket request")?
        {
            return Ok(code);
        }
        if target.master == MasterMode::Always {
            bail!("no control socket for {}", target.display);
        }
    }
    let (cmd, background) = parse_meta_argv(plan.argv.clone())
        .map_err(|e| anyhow!(e))?
        .ok_or_else(|| anyhow!("empty command"))?;
    if background {
        bail!("`&` is not accepted here");
    }
    let conn = connect(target, &plan.paths, &plan.baked, console).await?;
    let forwards = Forwards::new(conn.clone(), console.clone());
    let shared = Shared::new(
        conn.clone(),
        console.clone(),
        forwards.clone(),
        super::home_dir(),
    );
    let local_cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    let mut ctx = Ctx::detached(&shared, console.clone(), local_cwd);
    let result = ctl::run_command(&mut ctx, cmd, Vec::new()).await;
    drop(ctx);
    drop(shared);
    super::shutdown(&conn, &forwards, console).await;
    result
}

/// Per-stream line buffers for the `host: line` / `host! line` output.
#[derive(Default)]
struct Lines {
    out: Vec<u8>,
    err: Vec<u8>,
}

impl Lines {
    /// Append `data` and print every complete line it finishes.
    fn feed(&mut self, console: &Console, host: &str, stderr: bool, data: &[u8]) {
        let buf = if stderr { &mut self.err } else { &mut self.out };
        buf.extend_from_slice(data);
        while let Some(pos) = buf.iter().position(|&b| b == b'\n') {
            let line: Vec<u8> = buf.drain(..=pos).collect();
            Self::print(console, host, stderr, &line);
        }
    }

    /// Print what is left as a final (newline-terminated) line.
    fn finish(&mut self, console: &Console, host: &str) {
        for (stderr, buf) in [(false, &mut self.out), (true, &mut self.err)] {
            if !buf.is_empty() {
                buf.push(b'\n');
                Self::print(console, host, stderr, buf);
                buf.clear();
            }
        }
    }

    fn print(console: &Console, host: &str, stderr: bool, line: &[u8]) {
        let mut bytes = Vec::with_capacity(host.len() + 2 + line.len());
        bytes.extend_from_slice(host.as_bytes());
        bytes.extend_from_slice(if stderr { b"! " } else { b": " });
        bytes.extend_from_slice(line);
        if stderr {
            console.write_raw_err(&bytes);
        } else {
            console.write_raw(&bytes);
        }
    }
}

/// Splits capture output into text lines, carrying a partial line between
/// calls.
#[derive(Default)]
struct LineSplitter(Vec<u8>);

impl LineSplitter {
    fn push(&mut self, data: &[u8]) -> Vec<String> {
        self.0.extend_from_slice(data);
        let mut lines = Vec::new();
        while let Some(pos) = self.0.iter().position(|&b| b == b'\n') {
            let line: Vec<u8> = self.0.drain(..=pos).collect();
            lines.push(String::from_utf8_lossy(&line).trim_end().to_owned());
        }
        lines
    }

    fn rest(&mut self) -> Option<String> {
        if self.0.is_empty() {
            return None;
        }
        Some(
            String::from_utf8_lossy(&std::mem::take(&mut self.0))
                .trim_end()
                .to_owned(),
        )
    }
}

/// `run`: the host's console is in `JsonStream` mode, so its stdout is
/// `Event` lines; text on its stderr is the host's own stderr (or a relayed
/// `ErrorOut` line).
struct RunCollector {
    host: String,
    console: Console,
    human: bool,
    started: std::time::Instant,
    result: RunResult,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    lines: Lines,
    split: LineSplitter,
}

impl RunCollector {
    fn new(host: String, console: Console) -> Self {
        Self {
            human: matches!(console.mode(), Mode::Human | Mode::Plain),
            console,
            started: std::time::Instant::now(),
            result: RunResult {
                host: host.clone(),
                ok: false,
                exit: None,
                signal: None,
                stdout: Bytes::new(Vec::new()),
                stderr: Bytes::new(Vec::new()),
                duration_ms: 0,
                error: None,
            },
            host,
            stdout: Vec::new(),
            stderr: Vec::new(),
            lines: Lines::default(),
            split: LineSplitter::default(),
        }
    }

    fn apply(&mut self, ev: Event) {
        if self.console.mode() == Mode::JsonStream {
            self.console.event(&Event::Host {
                host: self.host.clone(),
                data: Box::new(ev.clone()),
            });
        }
        match ev {
            Event::Stdout { data } => {
                let data = data.into_bytes();
                if self.human {
                    self.lines.feed(&self.console, &self.host, false, &data);
                }
                self.stdout.extend_from_slice(&data);
            }
            Event::Stderr { data } => {
                let data = data.into_bytes();
                if self.human {
                    self.lines.feed(&self.console, &self.host, true, &data);
                }
                self.stderr.extend_from_slice(&data);
            }
            Event::Exit {
                exit,
                signal,
                duration_ms,
                timed_out,
            } => {
                self.result.exit = exit;
                self.result.signal = signal;
                self.result.duration_ms = duration_ms;
                if timed_out && self.result.error.is_none() {
                    self.result.error = Some(ErrorBody {
                        code: codes::TIMEOUT.to_owned(),
                        message: "timed out".to_owned(),
                    });
                }
            }
            Event::Error { code, message } => {
                if self.human {
                    let text = format!("error: {message}\n");
                    self.lines
                        .feed(&self.console, &self.host, true, text.as_bytes());
                }
                self.result.error = Some(ErrorBody { code, message });
            }
            Event::Notice { text } => {
                if self.human {
                    let text = format!("[mysh] {text}\n");
                    self.lines
                        .feed(&self.console, &self.host, true, text.as_bytes());
                }
            }
            Event::Started { .. }
            | Event::Progress { .. }
            | Event::Result { .. }
            | Event::Host { .. } => {}
        }
    }

    fn text_line(&mut self, line: &str) {
        self.apply(Event::Stdout {
            data: Bytes::new(format!("{line}\n").into_bytes()),
        });
    }
}

impl Collector for RunCollector {
    type Out = RunResult;

    fn event(&mut self, ev: CaptureEvent) {
        match ev {
            CaptureEvent::Out(bytes) => {
                for line in self.split.push(&bytes) {
                    match serde_json::from_str::<Event>(&line) {
                        Ok(ev) => self.apply(ev),
                        Err(_) => self.text_line(&line),
                    }
                }
            }
            CaptureEvent::Err(bytes) => {
                let text = String::from_utf8_lossy(&bytes).into_owned();
                match serde_json::from_str::<ErrorOut>(text.trim()) {
                    Ok(out) => self.apply(Event::Error {
                        code: out.error.code,
                        message: out.error.message,
                    }),
                    Err(_) => self.apply(Event::Stderr {
                        data: Bytes::new(bytes),
                    }),
                }
            }
            CaptureEvent::Progress { .. } | CaptureEvent::Done => {}
        }
    }

    fn finish(mut self, outcome: Result<i32>) -> RunResult {
        if let Some(rest) = self.split.rest() {
            self.text_line(&rest);
        }
        match outcome {
            Err(e) => {
                if self.result.error.is_none() {
                    self.apply(Event::Error {
                        code: code_for(&e).to_owned(),
                        message: format!("{e:#}"),
                    });
                }
            }
            Ok(code) => {
                if self.result.exit.is_none() && self.result.signal.is_none() {
                    self.result.exit = Some(code);
                }
            }
        }
        self.lines.finish(&self.console, &self.host);
        if self.result.duration_ms == 0 {
            self.result.duration_ms =
                u64::try_from(self.started.elapsed().as_millis()).unwrap_or(u64::MAX);
        }
        let mut result = self.result;
        result.stdout = Bytes::new(self.stdout);
        result.stderr = Bytes::new(self.stderr);
        result.ok = result.error.is_none() && result.exit == Some(0);
        result
    }
}

/// `put`/`get`: the host's console is in `Json` mode, so a successful
/// transfer prints one [`TransferOut`] document and a failure one
/// [`ErrorOut`] line (or a relayed `error: …` text line).
struct TransferCollector {
    host: String,
    console: Console,
    result: TransferResult,
    out: LineSplitter,
    err: LineSplitter,
}

impl TransferCollector {
    fn new(host: String, console: Console) -> Self {
        Self {
            result: TransferResult {
                host: host.clone(),
                ok: false,
                transfer: None,
                error: None,
            },
            host,
            console,
            out: LineSplitter::default(),
            err: LineSplitter::default(),
        }
    }

    fn note(&mut self, line: &str) {
        if line.is_empty() {
            return;
        }
        if let Ok(t) = serde_json::from_str::<TransferOut>(line) {
            self.result.transfer = Some(t);
        } else if let Ok(e) = serde_json::from_str::<ErrorOut>(line) {
            self.result.error = Some(e.error);
        } else if self.result.error.is_none() {
            self.result.error = Some(ErrorBody {
                code: codes::INTERNAL.to_owned(),
                message: line.trim_start_matches("error: ").to_owned(),
            });
        }
    }

    /// `host: 3 files, 1.2 MiB, 0.4 s` or `host! error: …`.
    fn human_line(&self) -> String {
        match (&self.result.transfer, &self.result.error) {
            (Some(t), None) => {
                let skipped = if t.skipped > 0 {
                    format!(", {} skipped", t.skipped)
                } else {
                    String::new()
                };
                format!(
                    "{}: {} file{}{skipped}, {}, {:.1} s\n",
                    self.host,
                    t.files,
                    if t.files == 1 { "" } else { "s" },
                    super::console::human(t.bytes),
                    crate::output::millis(std::time::Duration::from_millis(t.duration_ms)) / 1000.0
                )
            }
            (_, Some(e)) => format!("{}! error: {}\n", self.host, e.message),
            (None, None) => format!("{}! error: no transfer summary\n", self.host),
        }
    }
}

impl Collector for TransferCollector {
    type Out = TransferResult;

    fn event(&mut self, ev: CaptureEvent) {
        match ev {
            CaptureEvent::Out(bytes) => {
                for line in self.out.push(&bytes) {
                    self.note(&line);
                }
            }
            CaptureEvent::Err(bytes) => {
                for line in self.err.push(&bytes) {
                    self.note(&line);
                }
            }
            CaptureEvent::Progress { .. } | CaptureEvent::Done => {}
        }
    }

    fn finish(mut self, outcome: Result<i32>) -> TransferResult {
        for rest in [self.out.rest(), self.err.rest()].into_iter().flatten() {
            self.note(&rest);
        }
        match outcome {
            Err(e) if self.result.error.is_none() => {
                self.result.error = Some(ErrorOut::from_error(&e).error);
            }
            Ok(code) if code != 0 && self.result.error.is_none() => {
                self.result.error = Some(ErrorBody {
                    code: codes::INTERNAL.to_owned(),
                    message: format!("exit {code}"),
                });
            }
            _ => {}
        }
        if self.result.transfer.is_none() && self.result.error.is_none() {
            self.result.error = Some(ErrorBody {
                code: codes::INTERNAL.to_owned(),
                message: "no transfer summary".to_owned(),
            });
        }
        self.result.ok = self.result.error.is_none();
        match self.console.mode() {
            Mode::Human | Mode::Plain => {
                let line = self.human_line();
                if self.result.ok {
                    self.console.write_raw(line.as_bytes());
                } else {
                    self.console.write_raw_err(line.as_bytes());
                }
            }
            Mode::JsonStream => {
                let data = match (&self.result.transfer, &self.result.error) {
                    (Some(t), None) => Event::Result {
                        value: serde_json::to_value(t).unwrap_or_default(),
                    },
                    (_, Some(e)) => Event::Error {
                        code: e.code.clone(),
                        message: e.message.clone(),
                    },
                    (None, None) => Event::Notice {
                        text: "no transfer summary".to_owned(),
                    },
                };
                self.console.event(&Event::Host {
                    host: self.host.clone(),
                    data: Box::new(data),
                });
            }
            Mode::Json => {}
        }
        self.result
    }
}

/// `run`'s closing table: host, exit, duration (stdout on a terminal,
/// stderr otherwise so piped output stays attributed lines only).
fn print_summary(console: &Console, results: &[RunResult], to_stdout: bool) {
    let width = results
        .iter()
        .map(|r| r.host.len())
        .max()
        .unwrap_or(0)
        .max(4);
    let mut text = format!("{:<width$}  exit  duration\n", "host");
    for r in results {
        let exit = match (r.exit, r.signal, &r.error) {
            (Some(code), _, _) => code.to_string(),
            (None, Some(sig), _) => format!("sig{sig}"),
            (None, None, Some(e)) => e.code.clone(),
            (None, None, None) => "-".to_owned(),
        };
        let note = match &r.error {
            Some(e) if r.exit.is_some() || r.signal.is_some() => format!("  ({})", e.code),
            _ => String::new(),
        };
        let _ = writeln!(
            text,
            "{:<width$}  {exit:<4}  {} ms{note}",
            r.host, r.duration_ms
        );
    }
    if to_stdout {
        console.write_raw(text.as_bytes());
    } else {
        console.write_raw_err(text.as_bytes());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_hosts_splits_trims_and_drops_empties() {
        assert_eq!(parse_hosts("a, b ,,c,"), vec!["a", "b", "c"]);
        assert_eq!(parse_hosts(" , "), Vec::<String>::new());
    }

    #[test]
    fn expand_hosts_merges_lists_and_groups_in_order_without_duplicates() {
        let config = Config::parse(
            r#"
[groups.lab]
hosts = ["pi", "nuc", "10.0.0.5:7722"]
[groups.web]
hosts = ["nuc", "www"]
"#,
        )
        .expect("config");
        let hosts = expand_hosts(
            &["nuc,extra".to_owned()],
            &["lab".to_owned(), "web".to_owned()],
            &config,
        )
        .expect("hosts");
        assert_eq!(hosts, vec!["nuc", "extra", "pi", "10.0.0.5:7722", "www"]);
    }

    #[test]
    fn expand_hosts_rejects_unknown_group_and_empty_selection() {
        let config = Config::default();
        assert!(
            expand_hosts(&[], &["nope".to_owned()], &config)
                .unwrap_err()
                .contains("groups.nope")
        );
        assert!(expand_hosts(&[], &[], &config).is_err());
        assert!(expand_hosts(&[" , ".to_owned()], &[], &config).is_err());
    }

    #[test]
    fn lines_prefix_each_complete_line_and_flush_the_rest() {
        let (console, mut rx) = Console::capture();
        let mut lines = Lines::default();
        lines.feed(&console, "a", false, b"one\ntw");
        lines.feed(&console, "a", false, b"o\n");
        lines.feed(&console, "a", true, b"oops");
        lines.finish(&console, "a");
        drop(console);
        let mut out = Vec::new();
        let mut err = Vec::new();
        while let Some(ev) = rx.try_recv() {
            match ev {
                CaptureEvent::Out(b) => out.extend(b),
                CaptureEvent::Err(b) => err.extend(b),
                _ => {}
            }
        }
        assert_eq!(out, b"a: one\na: two\n");
        assert_eq!(err, b"a! oops\n");
    }

    #[tokio::test]
    async fn run_collector_folds_stream_events_and_outcome() {
        let (console, _rx) = Console::capture_with_mode(Mode::Json);
        let mut c = RunCollector::new("a".into(), console.clone());
        let lines = [
            serde_json::to_string(&Event::Started { session: 1, pid: 2 }).unwrap(),
            serde_json::to_string(&Event::Stdout {
                data: Bytes::new(b"HI\n".to_vec()),
            })
            .unwrap(),
            serde_json::to_string(&Event::Exit {
                exit: Some(0),
                signal: None,
                duration_ms: 7,
                timed_out: false,
            })
            .unwrap(),
        ];
        c.event(CaptureEvent::Out(
            format!("{}\n", lines.join("\n")).into_bytes(),
        ));
        let r = c.finish(Ok(0));
        assert!(r.ok);
        assert_eq!(r.exit, Some(0));
        assert_eq!(r.stdout, Bytes::new(b"HI\n".to_vec()));
        assert_eq!(r.duration_ms, 7);

        let c = RunCollector::new("b".into(), console);
        let err = coded(codes::CONNECT_FAILED, anyhow!("connection refused"));
        let r = c.finish(Err(err));
        assert!(!r.ok);
        assert_eq!(
            r.error.as_ref().map(|e| e.code.as_str()),
            Some("connect_failed")
        );
        let text = serde_json::to_string(&r).unwrap();
        let back: RunResult = serde_json::from_str(&text).unwrap();
        assert_eq!(back, r);
    }

    #[test]
    fn transfer_collector_reads_summary_or_error() {
        let (console, _rx) = Console::capture_with_mode(Mode::Json);
        let mut c = TransferCollector::new("a".into(), console.clone());
        c.event(CaptureEvent::Out(
            b"{\"files\":1,\"skipped\":0,\"bytes\":5,\"duration_ms\":3}\n".to_vec(),
        ));
        let r = c.finish(Ok(0));
        assert!(r.ok);
        assert_eq!(r.transfer.as_ref().map(|t| t.bytes), Some(5));

        let mut c = TransferCollector::new("b".into(), console);
        c.event(CaptureEvent::Err(
            ErrorOut::new(codes::NOT_FOUND, "nope")
                .to_line()
                .into_bytes(),
        ));
        let r = c.finish(Ok(1));
        assert!(!r.ok);
        assert_eq!(r.error.as_ref().map(|e| e.code.as_str()), Some("not_found"));
    }
}
