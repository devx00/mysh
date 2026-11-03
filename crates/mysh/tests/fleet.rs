//! Fleet fan-out through the real binary (docs/05-meta-shell.md "Fleet",
//! docs/06-roadmap.md M9): three loopback servers behind aliases `a`, `b`,
//! `c` and a group; `run` attributes every line, honours `-j`, isolates a
//! dead host as `connect_failed`, prints a typed `--json` array, and
//! `put --hosts` lands a file on every server.

mod common;

use std::{
    io::Write as _,
    process::{Command, Output, Stdio},
    time::{Duration, Instant},
};

use mysh::output::{RunResult, TransferResult};

/// Three servers trusting the first one's client identity, plus a config
/// file with aliases `a`, `b`, `c`, a dead alias `d`, and groups `all`
/// (a, b, c) and `mixed` (a, b, d).
struct Fleet {
    a: common::TestServer,
    b: common::TestServer,
    c: common::TestServer,
}

impl Fleet {
    async fn start() -> Self {
        Self::start_with(common::ServerOpts::default()).await
    }

    /// `a` gets `opts`; `b` and `c` the defaults.
    async fn start_with(opts: common::ServerOpts) -> Self {
        let a = common::start_server(opts).await;
        let key = a.client_identity.public;
        let b = common::start_server(common::ServerOpts {
            extra_authorized: vec![key],
            ..Default::default()
        })
        .await;
        let c = common::start_server(common::ServerOpts {
            extra_authorized: vec![key],
            ..Default::default()
        })
        .await;
        // A port nothing listens on.
        let dead = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let dead_port = dead.local_addr().expect("addr").port();
        drop(dead);
        let config = format!(
            "[hosts.a]\nhost = \"127.0.0.1\"\nport = {}\n\
             [hosts.b]\nhost = \"127.0.0.1\"\nport = {}\n\
             [hosts.c]\nhost = \"127.0.0.1\"\nport = {}\n\
             [hosts.d]\nhost = \"127.0.0.1\"\nport = {dead_port}\n\
             [groups.all]\nhosts = [\"a\", \"b\", \"c\"]\n\
             [groups.mixed]\nhosts = [\"a\", \"b\", \"d\"]\n",
            a.port(),
            b.port(),
            c.port()
        );
        std::fs::write(a.client_dir.join("config.toml"), config).expect("write config");
        Self { a, b, c }
    }

    /// `mysh SUB --accept-new …` with the first server's client environment.
    fn cmd(&self, sub: &str) -> Command {
        let mut cmd = Command::new(common::mysh_bin());
        cmd.env_clear()
            .envs(common::client_env(&self.a))
            .arg(sub)
            .arg("--accept-new")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        cmd
    }

    async fn stop(self) {
        self.a.stop().await;
        self.b.stop().await;
        self.c.stop().await;
    }
}

fn run(cmd: &mut Command) -> Output {
    let mut child = cmd.spawn().expect("spawn mysh");
    child
        .stdin
        .take()
        .expect("stdin")
        .write_all(b"")
        .expect("write stdin");
    child.wait_with_output().expect("wait")
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

fn results<T: serde::de::DeserializeOwned>(out: &Output) -> Vec<T> {
    let stdout = text(&out.stdout);
    let line = stdout
        .lines()
        .find(|l| !l.trim().is_empty())
        .unwrap_or_else(|| panic!("no JSON on stdout; stderr: {}", text(&out.stderr)));
    serde_json::from_str(line).unwrap_or_else(|e| panic!("{e}: {line}"))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn run_group_attributes_every_line_and_exits_zero() {
    let fleet = Fleet::start().await;
    let out = run(fleet.cmd("run").args([
        "--group",
        "all",
        "--",
        "sh",
        "-c",
        "echo HI-$((1+1)); echo warn >&2",
    ]));
    assert!(out.status.success(), "stderr: {}", text(&out.stderr));
    let stdout = text(&out.stdout);
    for host in ["a", "b", "c"] {
        assert!(
            stdout.contains(&format!("{host}: HI-2\n")),
            "missing {host} line in:\n{stdout}"
        );
        assert!(
            text(&out.stderr).contains(&format!("{host}! warn\n")),
            "missing {host} stderr line in:\n{}",
            text(&out.stderr)
        );
    }
    // The summary table (stdout is not a tty here, so it goes to stderr).
    let stderr = text(&out.stderr);
    assert!(stderr.contains("host  exit  duration"), "{stderr}");
    fleet.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn run_json_is_an_ordered_array_of_run_results() {
    let fleet = Fleet::start().await;
    let out = run(fleet.cmd("run").args([
        "--json",
        "--hosts",
        "c,a",
        "--group",
        "all",
        "--",
        "sh",
        "-c",
        "echo HI-$((1+1)); exit 3",
    ]));
    assert_eq!(out.status.code(), Some(1), "stderr: {}", text(&out.stderr));
    let rows: Vec<RunResult> = results(&out);
    let hosts: Vec<&str> = rows.iter().map(|r| r.host.as_str()).collect();
    assert_eq!(
        hosts,
        ["c", "a", "b"],
        "duplicates removed, order preserved"
    );
    for r in &rows {
        assert!(!r.ok);
        assert_eq!(r.exit, Some(3));
        assert_eq!(r.stdout.as_bytes(), b"HI-2\n");
        assert!(r.error.is_none(), "{r:?}");
    }
    let stderr = text(&out.stderr);
    assert!(
        !stderr.contains("HI-2"),
        "json mode must not stream lines: {stderr}"
    );
    fleet.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn run_jobs_bounds_concurrency() {
    let fleet = Fleet::start().await;
    let started = Instant::now();
    let out = run(fleet
        .cmd("run")
        .args(["-j", "2", "--group", "all", "--", "sleep", "0.5"]));
    let elapsed = started.elapsed();
    assert!(out.status.success(), "stderr: {}", text(&out.stderr));
    assert!(
        elapsed >= Duration::from_millis(900),
        "three sleeps of 0.5 s at -j 2 must take two rounds, took {elapsed:?}"
    );
    assert!(
        elapsed < Duration::from_millis(1450),
        "-j 2 must overlap two hosts, took {elapsed:?}"
    );
    fleet.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn dead_host_is_connect_failed_without_affecting_the_others() {
    let fleet = Fleet::start().await;
    let out = run(fleet
        .cmd("run")
        .args(["--json", "--group", "mixed", "--", "echo", "ok"]));
    assert_eq!(out.status.code(), Some(1));
    let rows: Vec<RunResult> = results(&out);
    assert_eq!(rows.len(), 3);
    for r in &rows[..2] {
        assert!(r.ok, "{r:?}");
        assert_eq!(r.exit, Some(0));
        assert_eq!(r.stdout.as_bytes(), b"ok\n");
    }
    let dead = &rows[2];
    assert_eq!(dead.host, "d");
    assert!(!dead.ok);
    assert_eq!(dead.exit, None);
    assert_eq!(
        dead.error.as_ref().map(|e| e.code.as_str()),
        Some("connect_failed"),
        "{dead:?}"
    );
    fleet.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn put_hosts_lands_the_file_on_every_server() {
    let fleet = Fleet::start().await;
    let src = fleet.a.dir.join("payload.txt");
    std::fs::write(&src, b"fleet payload\n").expect("write");
    let out = run(fleet.cmd("put").args([
        "--json",
        "--group",
        "all",
        &src.display().to_string(),
        "~/landed.txt",
    ]));
    assert!(out.status.success(), "stderr: {}", text(&out.stderr));
    let rows: Vec<TransferResult> = results(&out);
    assert_eq!(rows.len(), 3);
    for (row, server) in rows.iter().zip([&fleet.a, &fleet.b, &fleet.c]) {
        assert!(row.ok, "{row:?}");
        assert_eq!(row.transfer.as_ref().map(|t| t.files), Some(1));
        let landed = std::fs::read(server.home.join("landed.txt")).expect("landed");
        assert_eq!(landed, b"fleet payload\n");
    }
    fleet.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn get_hosts_puts_each_host_in_its_own_subdirectory() {
    let fleet = Fleet::start().await;
    for (server, body) in [(&fleet.a, "A"), (&fleet.b, "B"), (&fleet.c, "C")] {
        std::fs::write(server.home.join("who.txt"), body).expect("write");
    }
    let dest = fleet.a.dir.join("collected");
    let out =
        run(fleet
            .cmd("get")
            .args(["--hosts", "a,b,c", "~/who.txt", &dest.display().to_string()]));
    assert!(out.status.success(), "stderr: {}", text(&out.stderr));
    for (host, body) in [("a", "A"), ("b", "B"), ("c", "C")] {
        let got = std::fs::read(dest.join(host).join("who.txt")).expect("collected file");
        assert_eq!(got, body.as_bytes());
    }
    let stdout = text(&out.stdout);
    assert!(stdout.contains("a: 1 file"), "{stdout}");
    fleet.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn hosts_flag_is_refused_on_single_host_commands_and_unknown_groups_are_usage_errors() {
    let fleet = Fleet::start().await;
    let out = run(fleet.cmd("run").args(["--group", "nope", "--", "true"]));
    assert_eq!(out.status.code(), Some(2));
    assert!(text(&out.stderr).contains("groups.nope"));
    let out = run(fleet.cmd("session").args(["--hosts", "a,b", "a", "list"]));
    assert_eq!(out.status.code(), Some(2));
    assert!(text(&out.stderr).contains("--hosts/--group"));
    fleet.stop().await;
}

/// `run` goes through a host's control socket when a master serves it.
/// Server `a` admits one handshake per minute: the master takes it, so a
/// result from `a` proves the fan-out reused the master's connection.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn run_reuses_a_hosts_master() {
    let fleet = Fleet::start_with(common::ServerOpts {
        handshakes_per_minute: Some(1),
        ..Default::default()
    })
    .await;
    let run_dir = common::TempDir::short("fleetm");
    let mut env = common::client_env(&fleet.a);
    env.retain(|(k, _)| k != "XDG_RUNTIME_DIR");
    env.push((
        "XDG_RUNTIME_DIR".into(),
        run_dir.path().display().to_string(),
    ));
    let sock = run_dir
        .join("mysh")
        .join(format!("127.0.0.1_{}.sock", fleet.a.port()));

    let mut master = tokio::process::Command::new(common::mysh_bin());
    master
        .env_clear()
        .envs(env.iter().map(|(k, v)| (k, v)))
        .args(["master", "--idle", "60s", "--accept-new", "a"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(true);
    let mut master = master.spawn().expect("spawn master");
    let deadline = Instant::now() + Duration::from_secs(10);
    while tokio::net::UnixStream::connect(&sock).await.is_err() {
        assert!(
            Instant::now() < deadline,
            "no master socket at {}",
            sock.display()
        );
        tokio::time::sleep(Duration::from_millis(25)).await;
    }

    let mut cmd = Command::new(common::mysh_bin());
    cmd.env_clear()
        .envs(env.iter().map(|(k, v)| (k, v)))
        .args([
            "run",
            "--json",
            "--accept-new",
            "--group",
            "all",
            "--",
            "echo",
            "via",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let out = run(&mut cmd);
    assert!(out.status.success(), "stderr: {}", text(&out.stderr));
    let rows: Vec<RunResult> = results(&out);
    assert_eq!(rows.len(), 3);
    for r in &rows {
        assert!(r.ok, "{r:?}");
        assert_eq!(r.stdout.as_bytes(), b"via\n");
    }

    // Without the master, `a` is rate-limited and fails on its own.
    master.kill().await.expect("kill master");
    let _ = master.wait().await;
    let out = run(fleet
        .cmd("run")
        .args(["--json", "--hosts", "a", "--", "echo", "via"]));
    assert_eq!(out.status.code(), Some(1));
    let rows: Vec<RunResult> = results(&out);
    assert!(!rows[0].ok, "{rows:?}");
    fleet.stop().await;
}
