//! `mysh skill` (docs/05-meta-shell.md, "Skill"): the agent skill that
//! ships with the binary (`skills/mysh/SKILL.md`, embedded at build time),
//! installed into the skills directories of the coding agents present on
//! this machine. The format is the cross-agent `SKILL.md` convention: one
//! directory per skill holding `SKILL.md`.

use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result, anyhow};
use clap::{Args, Subcommand};
use serde::Serialize;

use crate::client::console::Console;

/// The skill text built into this binary.
pub const SKILL: &str = include_str!("../../../skills/mysh/SKILL.md");
/// The skill's directory name under a skills directory.
pub const NAME: &str = "mysh";

/// `mysh skill <install|list|show>`.
#[derive(Args, Clone, Debug)]
pub struct SkillArgs {
    #[command(subcommand)]
    pub command: SkillCommand,
}

#[derive(Subcommand, Clone, Debug)]
pub enum SkillCommand {
    /// Write the skill into every detected agent's skills directory (and
    /// the shared `~/.agents/skills`), or into `--to` directories only.
    Install {
        /// A skills directory to install into (repeatable); the skill lands
        /// at `DIR/mysh/SKILL.md`. Replaces agent detection.
        #[arg(long, value_name = "DIR")]
        to: Vec<PathBuf>,
        /// One JSON array on stdout.
        #[arg(long)]
        json: bool,
    },
    /// Show the agents this machine has and whether each has the skill.
    List {
        /// One JSON array on stdout.
        #[arg(long)]
        json: bool,
    },
    /// Print the skill to stdout.
    Show,
}

/// Where one agent reads personal skills from.
#[derive(Debug, Clone, Serialize)]
pub struct Location {
    /// Agent name (`claude`, `codex`, …; `agents` is the shared directory).
    pub agent: String,
    /// The skills directory.
    pub dir: PathBuf,
    /// Whether the agent's home directory exists here.
    pub present: bool,
}

/// Outcome per location.
#[derive(Debug, Clone, Serialize)]
pub struct Report {
    pub agent: String,
    pub path: PathBuf,
    /// `installed`, `updated`, `unchanged`, `missing`, `outdated`,
    /// `skipped` (agent not present), or `error`.
    pub status: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// The agents whose personal skills directory is a known path. The shared
/// `~/.agents/skills` is read by Codex, Cursor, Copilot, Gemini CLI,
/// `OpenCode` and others, so it is always a target; the rest (`~/.claude`,
/// `~/.codex`, `~/.cursor`, `~/.copilot`, `~/.openclaw`, omp's
/// `~/.omp/agent/skills`) are used when their home directory exists.
/// Environment overrides match each agent's own (`CLAUDE_CONFIG_DIR`,
/// `CODEX_HOME`).
pub fn locations(home: &Path, env: &dyn Fn(&str) -> Option<String>) -> Vec<Location> {
    let dir_of = |var: &str, default: &str| -> PathBuf {
        env(var)
            .filter(|v| !v.is_empty())
            .map_or_else(|| home.join(default), PathBuf::from)
    };
    // (agent, directory whose presence means "this agent is here", its
    // skills directory, always a target)
    let table: [(&str, PathBuf, PathBuf, bool); 7] = [
        (
            "agents",
            home.join(".agents"),
            home.join(".agents/skills"),
            true,
        ),
        (
            "claude",
            dir_of("CLAUDE_CONFIG_DIR", ".claude"),
            dir_of("CLAUDE_CONFIG_DIR", ".claude").join("skills"),
            false,
        ),
        (
            "codex",
            dir_of("CODEX_HOME", ".codex"),
            dir_of("CODEX_HOME", ".codex").join("skills"),
            false,
        ),
        (
            "cursor",
            home.join(".cursor"),
            home.join(".cursor/skills"),
            false,
        ),
        (
            "copilot",
            home.join(".copilot"),
            home.join(".copilot/skills"),
            false,
        ),
        (
            "openclaw",
            home.join(".openclaw"),
            home.join(".openclaw/skills"),
            false,
        ),
        (
            "omp",
            home.join(".omp"),
            home.join(".omp/agent/skills"),
            false,
        ),
    ];
    table
        .into_iter()
        .map(|(agent, base, dir, always)| Location {
            agent: agent.to_owned(),
            present: always || base.is_dir(),
            dir,
        })
        .collect()
}

/// Install into `dir/mysh/SKILL.md`: `installed`, `updated` or `unchanged`.
pub fn install_into(dir: &Path) -> Result<&'static str> {
    let skill_dir = dir.join(NAME);
    let path = skill_dir.join("SKILL.md");
    let status = match std::fs::read_to_string(&path) {
        Ok(existing) if existing == SKILL => return Ok("unchanged"),
        Ok(_) => "updated",
        Err(_) => "installed",
    };
    std::fs::create_dir_all(&skill_dir)
        .with_context(|| format!("creating {}", skill_dir.display()))?;
    let tmp = skill_dir.join("SKILL.md.tmp");
    std::fs::write(&tmp, SKILL).with_context(|| format!("writing {}", tmp.display()))?;
    std::fs::rename(&tmp, &path).with_context(|| format!("replacing {}", path.display()))?;
    Ok(status)
}

fn status_of(dir: &Path) -> &'static str {
    match std::fs::read_to_string(dir.join(NAME).join("SKILL.md")) {
        Ok(existing) if existing == SKILL => "installed",
        Ok(_) => "outdated",
        Err(_) => "missing",
    }
}

fn home() -> Result<PathBuf> {
    std::env::var_os("HOME")
        .filter(|h| !h.is_empty())
        .map(PathBuf::from)
        .ok_or_else(|| anyhow!("HOME is not set; use `mysh skill install --to DIR`"))
}

fn process_env(key: &str) -> Option<String> {
    std::env::var(key).ok()
}

/// Run the command; the exit code (1 when any install failed).
pub async fn run(args: &SkillArgs, console: &Console) -> Result<i32> {
    match &args.command {
        SkillCommand::Show => {
            console.print(SKILL);
            console.flush().await;
            Ok(0)
        }
        SkillCommand::List { .. } => {
            let home = home()?;
            let reports: Vec<Report> = locations(&home, &process_env)
                .into_iter()
                .map(|loc| Report {
                    path: loc.dir.join(NAME).join("SKILL.md"),
                    status: if loc.present {
                        status_of(&loc.dir)
                    } else {
                        "skipped"
                    },
                    agent: loc.agent,
                    error: None,
                })
                .collect();
            console.report(&reports, || table(&reports));
            console.flush().await;
            Ok(0)
        }
        SkillCommand::Install { to, .. } => {
            let targets: Vec<(String, PathBuf, bool)> = if to.is_empty() {
                locations(&home()?, &process_env)
                    .into_iter()
                    .map(|l| (l.agent, l.dir, l.present))
                    .collect()
            } else {
                to.iter()
                    .map(|d| (d.display().to_string(), d.clone(), true))
                    .collect()
            };
            let mut failed = false;
            let reports: Vec<Report> = targets
                .into_iter()
                .map(|(agent, dir, present)| {
                    let path = dir.join(NAME).join("SKILL.md");
                    if !present {
                        return Report {
                            agent,
                            path,
                            status: "skipped",
                            error: None,
                        };
                    }
                    match install_into(&dir) {
                        Ok(status) => Report {
                            agent,
                            path,
                            status,
                            error: None,
                        },
                        Err(e) => {
                            failed = true;
                            Report {
                                agent,
                                path,
                                status: "error",
                                error: Some(format!("{e:#}")),
                            }
                        }
                    }
                })
                .collect();
            console.report(&reports, || table(&reports));
            console.flush().await;
            Ok(i32::from(failed))
        }
    }
}

fn table(reports: &[Report]) -> String {
    use std::fmt::Write as _;
    let width = reports
        .iter()
        .map(|r| r.agent.len())
        .max()
        .unwrap_or(5)
        .max(5);
    let mut s = String::new();
    for r in reports {
        let _ = write!(
            s,
            "{:<width$}  {:<9}  {}",
            r.agent,
            r.status,
            r.path.display()
        );
        if let Some(e) = &r.error {
            let _ = write!(s, "  ({e})");
        }
        s.push('\n');
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedded_skill_has_frontmatter() {
        assert!(SKILL.starts_with("---\nname: mysh\n"), "{}", &SKILL[..40]);
        assert!(SKILL.contains("mysh assets"));
    }

    #[test]
    fn locations_follow_presence_and_env_overrides() {
        let home = std::env::temp_dir().join(format!("mysh-skill-loc-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&home);
        std::fs::create_dir_all(home.join(".claude")).expect("mkdir");
        let codex_home = home.join("elsewhere");
        std::fs::create_dir_all(&codex_home).expect("mkdir");
        let env = |k: &str| (k == "CODEX_HOME").then(|| codex_home.display().to_string());
        let locs = locations(&home, &env);
        let get = |a: &str| locs.iter().find(|l| l.agent == a).expect(a);
        assert!(get("agents").present, "the shared dir is always a target");
        assert_eq!(get("agents").dir, home.join(".agents").join("skills"));
        assert!(get("claude").present);
        assert!(get("codex").present);
        assert_eq!(get("codex").dir, codex_home.join("skills"));
        assert!(!get("cursor").present);
        assert!(!get("omp").present);
        std::fs::create_dir_all(home.join(".omp")).expect("mkdir");
        let locs = locations(&home, &env);
        let omp = locs.iter().find(|l| l.agent == "omp").expect("omp");
        assert!(omp.present);
        assert_eq!(omp.dir, home.join(".omp").join("agent").join("skills"));
        let _ = std::fs::remove_dir_all(&home);
    }

    #[test]
    fn install_reports_installed_then_unchanged_then_updated() {
        let dir = std::env::temp_dir().join(format!("mysh-skill-inst-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(install_into(&dir).expect("first"), "installed");
        assert_eq!(
            std::fs::read_to_string(dir.join("mysh/SKILL.md")).expect("read"),
            SKILL
        );
        assert_eq!(install_into(&dir).expect("second"), "unchanged");
        std::fs::write(dir.join("mysh/SKILL.md"), "old").expect("write");
        assert_eq!(status_of(&dir), "outdated");
        assert_eq!(install_into(&dir).expect("third"), "updated");
        assert_eq!(status_of(&dir), "installed");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
