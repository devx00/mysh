//! `mysh assets` and `mysh skill` through the binary, against a temp home:
//! directory resolution (`MYSH_ASSETS_DIR`, `[assets] dir`, XDG default),
//! `--for` picking, error codes, and skill installation into the agents
//! present under `$HOME`.

mod common;

use std::{
    path::Path,
    process::{Command, Output, Stdio},
};

fn mysh(home: &Path, env: &[(&str, &str)], args: &[&str]) -> Output {
    let mut cmd = Command::new(common::mysh_bin());
    cmd.env_clear()
        .env("HOME", home)
        .env("MYSH_CONFIG_DIR", home.join("cfg"))
        .env("PATH", std::env::var("PATH").unwrap_or_default())
        .args(args)
        .stdin(Stdio::null());
    for (k, v) in env {
        cmd.env(k, v);
    }
    cmd.output().expect("run mysh")
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

fn fake_dist(dir: &Path) {
    std::fs::create_dir_all(dir).expect("mkdir");
    for (name, body) in [
        ("mysh-0.1.0-aarch64-unknown-linux-musl", "a"),
        ("mysh-0.1.0-universal-apple-darwin", "bb"),
        ("mysh-0.1.0-x86_64-unknown-freebsd", "ccc"),
        ("README", "not an artifact"),
    ] {
        std::fs::write(dir.join(name), body).expect("write");
    }
    std::fs::write(
        dir.join("SHA256SUMS"),
        "ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb  mysh-0.1.0-aarch64-unknown-linux-musl\n",
    )
    .expect("sums");
}

#[test]
fn assets_resolve_the_directory_and_pick_by_uname() {
    let dir = common::TempDir::new("assets");
    let home = dir.join("home");
    std::fs::create_dir_all(home.join("cfg")).expect("mkdir");

    // Nothing installed: not_found with the XDG default in the message.
    let out = mysh(&home, &[], &["assets", "--json"]);
    assert_eq!(out.status.code(), Some(1));
    let err: serde_json::Value =
        serde_json::from_str(text(&out.stderr).trim()).expect("json error");
    assert_eq!(err["error"]["code"], "not_found");
    assert!(
        err["error"]["message"]
            .as_str()
            .expect("message")
            .contains(&home.join(".local/share/mysh").display().to_string())
    );

    // `[assets] dir` in the config file (with `~`), then the env override.
    let assets = dir.join("assets");
    fake_dist(&assets);
    std::fs::write(
        home.join("cfg/config.toml"),
        format!("[assets]\ndir = \"{}\"\n", assets.display()),
    )
    .expect("config");
    let out = mysh(&home, &[], &["assets", "--json"]);
    assert!(out.status.success(), "{}", text(&out.stderr));
    let doc: serde_json::Value = serde_json::from_slice(&out.stdout).expect("json");
    assert_eq!(doc["dir"], assets.display().to_string());
    let targets: Vec<&str> = doc["artifacts"]
        .as_array()
        .expect("array")
        .iter()
        .map(|a| a["target"].as_str().expect("target"))
        .collect();
    assert_eq!(
        targets,
        [
            "aarch64-unknown-linux-musl",
            "universal-apple-darwin",
            "x86_64-unknown-freebsd"
        ],
        "sorted, README skipped"
    );
    assert_eq!(
        doc["artifacts"][0]["sha256"],
        "ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb"
    );
    assert_eq!(doc["artifacts"][1]["sha256"], serde_json::Value::Null);

    let other = dir.join("other");
    fake_dist(&other);
    let out = mysh(
        &home,
        &[("MYSH_ASSETS_DIR", other.to_str().expect("utf8"))],
        &["assets"],
    );
    assert!(out.status.success());
    assert!(
        text(&out.stdout).starts_with(&other.display().to_string()),
        "{}",
        text(&out.stdout)
    );

    // `--for` prints exactly one path; the universal binary backs a missing slice.
    let out = mysh(&home, &[], &["assets", "--for", "Linux aarch64"]);
    assert_eq!(
        text(&out.stdout).trim(),
        assets
            .join("mysh-0.1.0-aarch64-unknown-linux-musl")
            .display()
            .to_string()
    );
    let out = mysh(&home, &[], &["assets", "--for", "Darwin arm64", "--json"]);
    let doc: serde_json::Value = serde_json::from_slice(&out.stdout).expect("json");
    assert_eq!(doc["target"], "universal-apple-darwin");
    let out = mysh(&home, &[], &["assets", "--for", "freebsd/amd64"]);
    assert!(text(&out.stdout).contains("x86_64-unknown-freebsd"));

    // Nothing for the arch: not_found naming the target to build; garbage: usage.
    let out = mysh(&home, &[], &["assets", "--json", "--for", "Linux riscv64"]);
    assert_eq!(out.status.code(), Some(1));
    let err: serde_json::Value = serde_json::from_str(text(&out.stderr).trim()).expect("json");
    assert_eq!(err["error"]["code"], "not_found");
    assert!(
        err["error"]["message"]
            .as_str()
            .expect("m")
            .contains("riscv64gc-unknown-linux-musl")
    );
    let out = mysh(&home, &[], &["assets", "--json", "--for", "nonsense"]);
    assert_eq!(out.status.code(), Some(1));
    let err: serde_json::Value = serde_json::from_str(text(&out.stderr).trim()).expect("json");
    assert_eq!(err["error"]["code"], "usage");
}

#[test]
fn skill_installs_for_present_agents_and_reports_status() {
    let dir = common::TempDir::new("skill");
    let home = dir.join("home");
    std::fs::create_dir_all(home.join(".claude")).expect("mkdir");
    std::fs::create_dir_all(home.join("cfg")).expect("mkdir");

    let out = mysh(&home, &[], &["skill", "list", "--json"]);
    let rows: Vec<serde_json::Value> = serde_json::from_slice(&out.stdout).expect("json");
    let status = |rows: &[serde_json::Value], agent: &str| -> String {
        rows.iter()
            .find(|r| r["agent"] == agent)
            .map(|r| r["status"].as_str().expect("status").to_owned())
            .expect(agent)
    };
    assert_eq!(
        status(&rows, "agents"),
        "missing",
        "the shared dir is always a target"
    );
    assert_eq!(status(&rows, "claude"), "missing");
    assert_eq!(status(&rows, "cursor"), "skipped", "no ~/.cursor here");

    let out = mysh(&home, &[], &["skill", "install", "--json"]);
    assert!(out.status.success(), "{}", text(&out.stderr));
    let rows: Vec<serde_json::Value> = serde_json::from_slice(&out.stdout).expect("json");
    assert_eq!(status(&rows, "agents"), "installed");
    assert_eq!(status(&rows, "claude"), "installed");
    assert_eq!(status(&rows, "cursor"), "skipped");
    assert!(
        !home.join(".cursor").exists(),
        "skipped agents get no directory"
    );
    let installed =
        std::fs::read_to_string(home.join(".claude/skills/mysh/SKILL.md")).expect("skill");
    let shown = text(&mysh(&home, &[], &["skill", "show"]).stdout);
    assert_eq!(installed, shown);
    assert!(installed.starts_with("---\nname: mysh\n"));

    // Idempotent; an edited copy is reported outdated and then updated.
    let out = mysh(&home, &[], &["skill", "install", "--json"]);
    let rows: Vec<serde_json::Value> = serde_json::from_slice(&out.stdout).expect("json");
    assert_eq!(status(&rows, "claude"), "unchanged");
    std::fs::write(home.join(".claude/skills/mysh/SKILL.md"), "stale").expect("write");
    let out = mysh(&home, &[], &["skill", "list", "--json"]);
    let rows: Vec<serde_json::Value> = serde_json::from_slice(&out.stdout).expect("json");
    assert_eq!(status(&rows, "claude"), "outdated");
    let out = mysh(&home, &[], &["skill", "install", "--json"]);
    let rows: Vec<serde_json::Value> = serde_json::from_slice(&out.stdout).expect("json");
    assert_eq!(status(&rows, "claude"), "updated");

    // `--to` replaces detection.
    let custom = dir.join("custom-skills");
    let out = mysh(
        &home,
        &[],
        &[
            "skill",
            "install",
            "--to",
            custom.to_str().expect("utf8"),
            "--json",
        ],
    );
    let rows: Vec<serde_json::Value> = serde_json::from_slice(&out.stdout).expect("json");
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0]["status"], "installed");
    assert!(custom.join("mysh/SKILL.md").is_file());
}
