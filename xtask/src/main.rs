//! Repository tasks. `cargo xtask install` builds the client, installs it
//! and the cross-built server binaries from `dist/` where `mysh assets`
//! looks for them, and installs the agent skill.
#![forbid(unsafe_code)]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus};

use anyhow::{Context, Result, anyhow, bail};
use clap::Parser;

#[derive(Debug, Parser)]
#[command(name = "cargo xtask", bin_name = "cargo xtask")]
enum Cmd {
    /// Build the client and install it, the `dist/` artifacts and the agent skill.
    Install(Install),
}

#[allow(clippy::struct_excessive_bools)] // independent switches
#[derive(Debug, Parser)]
struct Install {
    /// Where the client binary goes [default: ~/.local/bin].
    #[arg(long, value_name = "DIR")]
    bin_dir: Option<PathBuf>,
    /// Where the server binaries go [default: `$XDG_DATA_HOME/mysh` or `~/.local/share/mysh`].
    #[arg(long, value_name = "DIR")]
    assets_dir: Option<PathBuf>,
    /// Directory holding `mysh-<version>-<target>` files [default: dist/ in the repo].
    #[arg(long, value_name = "DIR")]
    dist_dir: Option<PathBuf>,
    /// Run scripts/release.sh first to (re)build the server binaries.
    #[arg(long)]
    dist: bool,
    /// Pass `--stretch` to scripts/release.sh.
    #[arg(long, requires = "dist")]
    stretch: bool,
    /// Do not run `mysh skill install`.
    #[arg(long)]
    no_skill: bool,
    /// Print what would be done and change nothing.
    #[arg(long)]
    dry_run: bool,
}

fn main() -> Result<()> {
    let Cmd::Install(args) = Cmd::parse();
    install(&args)
}

fn home() -> Result<PathBuf> {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .context("HOME is not set")
}

/// `$VAR` when set and absolute, else `~/<fallback>`.
fn xdg(var: &str, fallback: &str) -> Result<PathBuf> {
    match std::env::var_os(var).map(PathBuf::from) {
        Some(p) if p.is_absolute() => Ok(p),
        _ => Ok(home()?.join(fallback)),
    }
}

fn config_file() -> Result<PathBuf> {
    let dir = match std::env::var_os("MYSH_CONFIG_DIR") {
        Some(d) => PathBuf::from(d),
        None => xdg("XDG_CONFIG_HOME", ".config")?.join("mysh"),
    };
    Ok(dir.join("config.toml"))
}

/// The `[assets]` table of `config.toml`.
#[derive(Debug)]
enum AssetsTable {
    Absent,
    /// Present, with its `dir = "…"` value if any.
    Present(Option<PathBuf>),
}

fn config_assets_table(config: &Path) -> AssetsTable {
    let Ok(text) = fs::read_to_string(config) else {
        return AssetsTable::Absent;
    };
    let mut in_assets = false;
    let mut found = AssetsTable::Absent;
    for line in text.lines().map(str::trim) {
        if line.starts_with('[') {
            in_assets = line == "[assets]";
            if in_assets && matches!(found, AssetsTable::Absent) {
                found = AssetsTable::Present(None);
            }
        } else if in_assets
            && let Some(rest) = line.strip_prefix("dir")
            && let Some(value) = rest.trim_start().strip_prefix('=')
        {
            let value = value.trim();
            let value = value.split_once('#').map_or(value, |(v, _)| v.trim());
            found = AssetsTable::Present(Some(PathBuf::from(value.trim_matches(['"', '\'']))));
        }
    }
    found
}

/// The directory `mysh assets` would use with no further configuration.
fn resolved_assets_dir(config: &Path) -> Result<PathBuf> {
    if let Some(dir) = std::env::var_os("MYSH_ASSETS_DIR") {
        return Ok(PathBuf::from(dir));
    }
    if let AssetsTable::Present(Some(dir)) = config_assets_table(config) {
        return Ok(dir);
    }
    Ok(xdg("XDG_DATA_HOME", ".local/share")?.join("mysh"))
}

fn absolute(path: &Path) -> Result<PathBuf> {
    std::path::absolute(path).with_context(|| format!("resolving {}", path.display()))
}

fn run(desc: &str, cmd: &mut Command) -> Result<ExitStatus> {
    cmd.status().with_context(|| format!("running {desc}"))
}

fn run_ok(desc: &str, cmd: &mut Command) -> Result<()> {
    let status = run(desc, cmd)?;
    if !status.success() {
        bail!("{desc} failed: {status}");
    }
    Ok(())
}

/// Copy `src` into `dir/name` through a temporary name in the same directory,
/// so a running binary is replaced, not written over.
fn install_file(src: &Path, dir: &Path, name: &str, mode: u32) -> Result<PathBuf> {
    let dest = dir.join(name);
    let tmp = dir.join(format!(".{name}.tmp-{}", std::process::id()));
    fs::copy(src, &tmp)
        .with_context(|| format!("copying {} to {}", src.display(), tmp.display()))?;
    fs::set_permissions(&tmp, fs::Permissions::from_mode(mode))?;
    fs::rename(&tmp, &dest).with_context(|| format!("renaming to {}", dest.display()))?;
    Ok(dest)
}

fn on_path(dir: &Path) -> bool {
    let dir = dir.canonicalize().unwrap_or_else(|_| dir.to_path_buf());
    std::env::var_os("PATH").is_some_and(|path| {
        std::env::split_paths(&path).any(|p| p.canonicalize().unwrap_or(p) == dir)
    })
}

fn dist_files(dist_dir: &Path) -> Result<Vec<PathBuf>> {
    let Ok(entries) = fs::read_dir(dist_dir) else {
        return Ok(Vec::new());
    };
    let mut files = Vec::new();
    for entry in entries {
        let path = entry?.path();
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or_default();
        if path.is_file() && (name.starts_with("mysh-") || name == "SHA256SUMS") {
            files.push(path);
        }
    }
    files.sort();
    Ok(files)
}

#[allow(clippy::too_many_lines)]
fn install(args: &Install) -> Result<()> {
    let repo = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .ok_or_else(|| anyhow!("xtask has no parent directory"))?
        .to_path_buf();
    let dry = args.dry_run;
    let bin_dir = match &args.bin_dir {
        Some(dir) => absolute(dir)?,
        None => home()?.join(".local/bin"),
    };
    let config = config_file()?;
    let default_assets = resolved_assets_dir(&config)?;
    let assets_dir = absolute(args.assets_dir.as_ref().unwrap_or(&default_assets))?;
    let dist_dir = absolute(&args.dist_dir.clone().unwrap_or_else(|| repo.join("dist")))?;
    let client = bin_dir.join("mysh");

    // 1. client
    let target =
        std::env::var_os("CARGO_TARGET_DIR").map_or_else(|| repo.join("target"), PathBuf::from);
    let built = target.join("release/mysh");
    if dry {
        println!("would run: cargo build --release --locked -p mysh");
        println!("would install {} -> {}", built.display(), client.display());
    } else {
        run_ok(
            "cargo build",
            Command::new("cargo")
                .args(["build", "--release", "--locked", "-p", "mysh"])
                .current_dir(&repo),
        )?;
        fs::create_dir_all(&bin_dir).with_context(|| format!("creating {}", bin_dir.display()))?;
        install_file(&built, &bin_dir, "mysh", 0o755)?;
    }
    if !on_path(&bin_dir) {
        eprintln!("warning: {} is not on $PATH", bin_dir.display());
    }

    // 2. assets
    if args.dist {
        let mut cmd = Command::new(repo.join("scripts/release.sh"));
        if args.stretch {
            cmd.arg("--stretch");
        }
        if dry {
            println!(
                "would run: scripts/release.sh{}",
                if args.stretch { " --stretch" } else { "" }
            );
        } else {
            run_ok("scripts/release.sh", cmd.current_dir(&repo))?;
        }
    }
    let files = dist_files(&dist_dir)?;
    let binaries = files
        .iter()
        .filter(|f| f.file_name().is_some_and(|n| n != "SHA256SUMS"))
        .count();
    if binaries == 0 {
        println!(
            "no server binaries in {}: none installed (build them with `cargo xtask install --dist` or `scripts/release.sh TARGET`)",
            dist_dir.display()
        );
    } else if dry {
        println!(
            "would install {binaries} server binaries from {} into {}",
            dist_dir.display(),
            assets_dir.display()
        );
    } else {
        fs::create_dir_all(&assets_dir)
            .with_context(|| format!("creating {}", assets_dir.display()))?;
        for file in &files {
            let name = file
                .file_name()
                .and_then(|n| n.to_str())
                .context("non-UTF-8 dist file name")?;
            let mode = if name == "SHA256SUMS" { 0o644 } else { 0o755 };
            install_file(file, &assets_dir, name, mode)?;
        }
    }

    // 3. config
    let mut config_note = None;
    if assets_dir != absolute(&default_assets)? {
        let line = format!("dir = \"{}\"", assets_dir.display());
        match config_assets_table(&config) {
            AssetsTable::Present(_) => {
                println!(
                    "{} already has an [assets] table; set `{line}` there",
                    config.display()
                );
            }
            AssetsTable::Absent if dry => {
                println!("would append [assets] {line} to {}", config.display());
            }
            AssetsTable::Absent => {
                if let Some(dir) = config.parent() {
                    fs::create_dir_all(dir)
                        .with_context(|| format!("creating {}", dir.display()))?;
                    fs::set_permissions(dir, fs::Permissions::from_mode(0o700))?;
                }
                let mut text = fs::read_to_string(&config).unwrap_or_default();
                if !text.is_empty() && !text.ends_with('\n') {
                    text.push('\n');
                }
                text.push_str("\n[assets]\n");
                text.push_str(&line);
                text.push('\n');
                fs::write(&config, text)
                    .with_context(|| format!("writing {}", config.display()))?;
                fs::set_permissions(&config, fs::Permissions::from_mode(0o600))?;
                config_note = Some(format!("added [assets] {line} to {}", config.display()));
            }
        }
    }

    // 4. skill
    let skill = if args.no_skill {
        "skipped (--no-skill)".to_owned()
    } else if dry {
        println!("would run: {} skill install", client.display());
        "not run (dry run)".to_owned()
    } else {
        match run(
            "mysh skill install",
            Command::new(&client).args(["skill", "install"]),
        ) {
            Ok(s) if s.success() => "installed".to_owned(),
            Ok(s) => format!("mysh skill install failed: {s}"),
            Err(e) => format!("mysh skill install failed: {e:#}"),
        }
    };

    // 5. summary
    if dry {
        return Ok(());
    }
    let version = Command::new(&client)
        .arg("--version")
        .output()
        .ok()
        .filter(|o| o.status.success());
    let version = version.map_or_else(
        || "unknown version".to_owned(),
        |o| String::from_utf8_lossy(&o.stdout).trim().to_owned(),
    );
    println!("client: {} ({version})", client.display());
    let installed = dist_files(&assets_dir)?
        .iter()
        .filter(|f| f.file_name().is_some_and(|n| n != "SHA256SUMS"))
        .count();
    println!(
        "assets: {} ({installed} server binaries)",
        assets_dir.display()
    );
    if let Some(note) = config_note {
        println!("config: {note}");
    }
    println!("skill:  {skill}");
    let _ = Command::new(&client).arg("assets").status();
    Ok(())
}
