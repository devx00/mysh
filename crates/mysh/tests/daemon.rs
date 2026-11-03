//! `mysh serve --daemon` / `mysh accept --daemon`: the parent exits 0 only
//! once the detached child is up, the child lives in its own process group
//! with the pid file and log where asked, survives `SIGHUP`, and a clean
//! `SIGTERM` removes the pid file. A child that fails before it is up makes
//! the parent fail with the child's log.

mod common;

use std::{
    path::{Path, PathBuf},
    process::{Command, Output, Stdio},
    time::{Duration, Instant},
};

use mysh_net::keys::{SecretKey, write_public_key, write_secret_key};

const SOON: Duration = Duration::from_secs(10);

struct Tree {
    dir: common::TempDir,
    config: PathBuf,
    client: PathBuf,
}

impl Tree {
    fn new() -> Self {
        let dir = common::TempDir::new("daemon");
        let config = dir.join("server");
        let client = dir.join("client");
        for d in [&config, &client, &dir.join("home"), &dir.join("run")] {
            std::fs::create_dir_all(d).expect("mkdir");
        }
        let key = SecretKey::generate();
        write_secret_key(&client.join("id"), &key).expect("client key");
        write_public_key(&client.join("id.pub"), &key.public(), Some("it")).expect("pub");
        Self {
            dir,
            config,
            client,
        }
    }

    fn env(&self, config_dir: &Path) -> Vec<(String, String)> {
        vec![
            ("MYSH_CONFIG_DIR".into(), config_dir.display().to_string()),
            ("HOME".into(), self.dir.join("home").display().to_string()),
            (
                "XDG_STATE_HOME".into(),
                self.dir.join("state").display().to_string(),
            ),
            (
                "XDG_RUNTIME_DIR".into(),
                self.dir.join("run").display().to_string(),
            ),
            ("PATH".into(), std::env::var("PATH").unwrap_or_default()),
            ("SSH_AUTH_SOCK".into(), String::new()),
        ]
    }

    fn mysh(&self, config_dir: &Path, args: &[&str]) -> Output {
        Command::new(common::mysh_bin())
            .env_clear()
            .envs(self.env(config_dir))
            .args(args)
            .stdin(Stdio::null())
            .output()
            .expect("run mysh")
    }

    fn authorized_line(&self) -> String {
        std::fs::read_to_string(self.client.join("id.pub")).expect("id.pub")
    }
}

fn pid_alive(pid: u32) -> bool {
    // `kill -0` without libc: `ps` is universal on the supported platforms.
    Command::new("ps")
        .args(["-p", &pid.to_string(), "-o", "pid="])
        .output()
        .is_ok_and(|o| o.status.success() && !String::from_utf8_lossy(&o.stdout).trim().is_empty())
}

fn signal(pid: u32, sig: &str) {
    assert!(
        Command::new("kill")
            .args([sig, &pid.to_string()])
            .status()
            .expect("kill")
            .success(),
        "kill {sig} {pid}"
    );
}

fn wait_until(what: &str, mut cond: impl FnMut() -> bool) {
    let deadline = Instant::now() + SOON;
    while !cond() {
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        std::thread::sleep(Duration::from_millis(50));
    }
}

fn pgid(pid: u32) -> String {
    let out = Command::new("ps")
        .args(["-p", &pid.to_string(), "-o", "pgid="])
        .output()
        .expect("ps");
    String::from_utf8_lossy(&out.stdout).trim().to_owned()
}

#[test]
fn serve_daemon_detaches_reports_readiness_and_cleans_up() {
    let t = Tree::new();
    let pid_file = t.dir.join("serve.pid");
    let authorized = t.authorized_line();
    let out = t.mysh(
        &t.config,
        &[
            "serve",
            "--daemon",
            "--listen",
            "127.0.0.1:0",
            "--pid-file",
            pid_file.to_str().expect("utf8"),
            "--authorized-key",
            authorized.trim(),
            "-v",
        ],
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "parent failed: {stdout}\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(stdout.contains("started, pid"), "{stdout}");
    // The parent only returns once the child reported ready, so the pid
    // file is there and names a live process in its own process group.
    let pid: u32 = std::fs::read_to_string(&pid_file)
        .expect("pid file")
        .trim()
        .parse()
        .expect("pid");
    assert!(pid_alive(pid));
    assert_eq!(
        pgid(pid),
        pid.to_string(),
        "the daemon leads its own process group"
    );
    assert!(stdout.contains(&format!("pid {pid}")), "{stdout}");

    // The default log is next to the history file and holds the listen line.
    let log = t.dir.join("state").join("mysh").join("serve.log");
    let text = std::fs::read_to_string(&log).expect("log");
    let port: u16 = text
        .lines()
        .find_map(|l| l.split("listening addr=127.0.0.1:").nth(1))
        .and_then(|rest| rest.split_whitespace().next())
        .and_then(|p| p.parse().ok())
        .expect("listening line in the log");

    // It serves.
    let out = t.mysh(
        &t.client,
        &["--accept-new", &format!("127.0.0.1:{port}"), "echo", "ok"],
    );
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "ok");

    // SIGHUP is ignored; SIGTERM ends it and removes the pid file.
    signal(pid, "-HUP");
    std::thread::sleep(Duration::from_millis(300));
    assert!(pid_alive(pid), "SIGHUP must not end the daemon");
    signal(pid, "-TERM");
    wait_until("the daemon to exit", || !pid_alive(pid));
    wait_until("the pid file to go", || !pid_file.exists());
}

#[test]
fn serve_daemon_failure_before_ready_fails_the_parent_with_the_log() {
    let t = Tree::new();
    let authorized = t.authorized_line();
    // Port 1 needs privileges the test does not have.
    let out = t.mysh(
        &t.config,
        &[
            "serve",
            "--daemon",
            "--listen",
            "127.0.0.1:1",
            "--authorized-key",
            authorized.trim(),
        ],
    );
    assert!(!out.status.success());
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("before it was up"), "{err}");
    assert!(err.contains("bind 127.0.0.1:1"), "{err}");
}

#[test]
fn accept_daemon_reports_json_and_cleans_up() {
    let t = Tree::new();
    // The acceptor needs a callers file (any key) to start.
    let caller = SecretKey::generate().public().to_line(Some("box"));
    std::fs::write(t.client.join("callers"), caller).expect("callers");
    let pid_file = t.dir.join("accept.pid");
    let log = t.dir.join("accept.log");
    let out = t.mysh(
        &t.client,
        &[
            "accept",
            "127.0.0.1:0",
            "--daemon",
            "--json",
            "--pid-file",
            pid_file.to_str().expect("utf8"),
            "--log",
            log.to_str().expect("utf8"),
        ],
    );
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let started: serde_json::Value =
        serde_json::from_slice(&out.stdout).expect("one JSON document on stdout");
    let pid = u32::try_from(started["pid"].as_u64().expect("pid")).expect("pid fits");
    assert_eq!(started["log"], log.display().to_string());
    assert_eq!(
        std::fs::read_to_string(&pid_file).expect("pid file").trim(),
        pid.to_string()
    );
    assert!(
        std::fs::read_to_string(&log)
            .expect("log")
            .contains("accepting connections on 127.0.0.1:")
    );
    signal(pid, "-TERM");
    wait_until("the acceptor to exit", || !pid_alive(pid));
    wait_until("the pid file to go", || !pid_file.exists());
}
