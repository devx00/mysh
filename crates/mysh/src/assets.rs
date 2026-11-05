//! `mysh assets` (docs/05-meta-shell.md, "Assets"): where the per-target
//! release binaries are on this machine, and which one a given remote
//! needs. The directory is flat — what `scripts/release.sh` writes to
//! `dist/` and `cargo xtask install` copies: `mysh-<version>-<target>`
//! files plus `SHA256SUMS`. Resolution: `$MYSH_ASSETS_DIR`, then
//! `[assets] dir` in the config file, then `$XDG_DATA_HOME/mysh`
//! (`~/.local/share/mysh`).

use std::{
    collections::HashMap,
    path::{Path, PathBuf},
};

use anyhow::{Context as _, Result, anyhow};
use clap::Args;
use mysh_client::types::{coded, codes};
use serde::Serialize;

use crate::{
    client::console::Console,
    config::{Config, Paths},
};

/// `mysh assets [--json] [--for SPEC] [--dir DIR]`.
#[derive(Args, Clone, Debug, Default)]
pub struct AssetsArgs {
    /// Pick the artifact for a remote machine: its `uname -sm` output
    /// (`"Linux aarch64"`, `"Darwin arm64"`, `"FreeBSD amd64"`), `OS/ARCH`
    /// (`android/aarch64` — Android's `uname` says `Linux`), or a full
    /// target triple. Prints its path.
    #[arg(long = "for", value_name = "SPEC")]
    pub for_spec: Option<String>,

    /// Look in DIR instead of the configured directory.
    #[arg(long, value_name = "DIR")]
    pub dir: Option<PathBuf>,

    /// One JSON document on stdout.
    #[arg(long)]
    pub json: bool,
}

/// One installed release artifact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Artifact {
    /// Target triple (`aarch64-unknown-linux-musl`, `universal-apple-darwin`).
    pub target: String,
    /// mysh version baked into the file name.
    pub version: String,
    /// Absolute path.
    pub path: PathBuf,
    /// Size in bytes.
    pub size: u64,
    /// From `SHA256SUMS` next to it; `None` when not listed there.
    pub sha256: Option<String>,
}

/// The listing document.
#[derive(Debug, Clone, Serialize)]
pub struct AssetsOut {
    pub dir: PathBuf,
    pub artifacts: Vec<Artifact>,
}

/// Scan `dir` for `mysh-<version>-<target>` files; checksums come from
/// `SHA256SUMS` when present. A missing directory is an empty listing.
pub fn list(dir: &Path) -> Result<Vec<Artifact>> {
    let entries = match std::fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(anyhow!(e).context(format!("reading {}", dir.display()))),
    };
    let sums = read_sums(&dir.join("SHA256SUMS"));
    let mut out = Vec::new();
    for entry in entries {
        let entry = entry.with_context(|| format!("reading {}", dir.display()))?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        let Some((version, target)) = parse_name(name) else {
            continue;
        };
        let meta = entry.metadata()?;
        if !meta.is_file() {
            continue;
        }
        out.push(Artifact {
            target: target.to_owned(),
            version: version.to_owned(),
            path: dir.join(name),
            size: meta.len(),
            sha256: sums.get(name).cloned(),
        });
    }
    out.sort_by(|a, b| a.target.cmp(&b.target).then(b.version.cmp(&a.version)));
    Ok(out)
}

/// `mysh-<version>-<target>` → `(version, target)`. The version is the
/// first dash-separated field after `mysh-` (release.sh writes
/// `mysh-$VERSION-$TARGET`), the target everything after it.
fn parse_name(name: &str) -> Option<(&str, &str)> {
    let rest = name.strip_prefix("mysh-")?;
    let (version, target) = rest.split_once('-')?;
    let plausible_version =
        version.chars().all(|c| c.is_ascii_digit() || c == '.') && version.contains('.');
    (plausible_version && !target.is_empty() && name != "SHA256SUMS").then_some((version, target))
}

fn read_sums(path: &Path) -> HashMap<String, String> {
    let Ok(text) = std::fs::read_to_string(path) else {
        return HashMap::new();
    };
    text.lines()
        .filter_map(|line| {
            let mut it = line.split_whitespace();
            let sum = it.next()?;
            let name = it.next()?.trim_start_matches('*');
            Some((name.to_owned(), sum.to_owned()))
        })
        .collect()
}

/// The target triples that would run on the machine `spec` describes,
/// most specific first. `spec` is `uname -sm` output, `OS/ARCH`, or a
/// target triple (returned as is).
pub fn candidates(spec: &str) -> Result<Vec<&'static str>> {
    let lower = spec.trim().to_ascii_lowercase();
    let words: Vec<&str> = lower
        .split(|c: char| c.is_whitespace() || c == '/')
        .filter(|w| !w.is_empty())
        .collect();
    if let [triple] = words.as_slice()
        && let Some(known) = TARGETS.iter().find(|t| **t == *triple)
    {
        return Ok(vec![known]);
    }
    let [os, arch, ..] = words.as_slice() else {
        return Err(coded(
            codes::USAGE,
            anyhow!(
                "cannot read {spec:?}: pass `uname -sm` output (\"Linux aarch64\"), OS/ARCH \
                 (android/aarch64), or a target triple"
            ),
        ));
    };
    let os = match *os {
        "linux" => "linux",
        "android" => "android",
        "darwin" | "macos" | "mac" | "osx" => "darwin",
        "freebsd" => "freebsd",
        "netbsd" => "netbsd",
        "openbsd" => "openbsd",
        other => {
            return Err(coded(
                codes::NOT_FOUND,
                anyhow!("no artifacts are built for the operating system {other:?}"),
            ));
        }
    };
    let arch = match *arch {
        "x86_64" | "amd64" | "x64" => "x86_64",
        "aarch64" | "arm64" | "evbarm" | "arm64e" => "aarch64",
        "armv7l" | "armv7" | "armhf" => "armv7",
        "armv6l" | "armv6" => "armv6",
        "armv5tel" | "armv5te" | "armv5" | "armel" => "armv5te",
        "i686" | "i386" | "i586" | "x86" => "i686",
        "riscv64" => "riscv64",
        "ppc64le" | "powerpc64le" => "ppc64le",
        "s390x" => "s390x",
        "loongarch64" | "loong64" => "loongarch64",
        "mips" => "mips",
        "mipsel" | "mipsle" => "mipsel",
        other => {
            return Err(coded(
                codes::NOT_FOUND,
                anyhow!("no artifacts are built for the architecture {other:?}"),
            ));
        }
    };
    let list: &[&'static str] = match (os, arch) {
        ("linux", "x86_64") => &["x86_64-unknown-linux-musl"],
        ("linux", "aarch64") => &["aarch64-unknown-linux-musl"],
        ("linux", "armv7") => &["armv7-unknown-linux-musleabihf"],
        ("linux", "armv6") => &["arm-unknown-linux-musleabihf"],
        ("linux", "armv5te") => &["armv5te-unknown-linux-musleabi"],
        ("linux", "i686") => &["i686-unknown-linux-musl"],
        ("linux", "riscv64") => &["riscv64gc-unknown-linux-musl"],
        ("linux", "ppc64le") => &["powerpc64le-unknown-linux-musl"],
        ("linux", "s390x") => &["s390x-unknown-linux-musl", "s390x-unknown-linux-gnu"],
        ("linux", "loongarch64") => &["loongarch64-unknown-linux-musl"],
        ("linux", "mips") => &["mips-unknown-linux-musl"],
        ("linux", "mipsel") => &["mipsel-unknown-linux-musl"],
        ("android", "aarch64") => &["aarch64-linux-android"],
        ("android", "armv7") => &["armv7-linux-androideabi"],
        ("android", "x86_64") => &["x86_64-linux-android"],
        ("android", "i686") => &["i686-linux-android"],
        ("darwin", "aarch64") => &["aarch64-apple-darwin", "universal-apple-darwin"],
        ("darwin", "x86_64") => &["x86_64-apple-darwin", "universal-apple-darwin"],
        ("freebsd", "x86_64") => &["x86_64-unknown-freebsd"],
        ("freebsd", "aarch64") => &["aarch64-unknown-freebsd"],
        ("netbsd", "x86_64") => &["x86_64-unknown-netbsd"],
        ("netbsd", "aarch64") => &["aarch64-unknown-netbsd"],
        ("openbsd", "x86_64") => &["x86_64-unknown-openbsd"],
        ("openbsd", "aarch64") => &["aarch64-unknown-openbsd"],
        _ => {
            return Err(coded(
                codes::NOT_FOUND,
                anyhow!("no artifact is built for {os}/{arch}"),
            ));
        }
    };
    Ok(list.to_vec())
}

/// Every target `scripts/release.sh` knows (for triple input).
const TARGETS: &[&str] = &[
    "x86_64-unknown-linux-musl",
    "aarch64-unknown-linux-musl",
    "i686-unknown-linux-musl",
    "armv7-unknown-linux-musleabihf",
    "arm-unknown-linux-musleabihf",
    "riscv64gc-unknown-linux-musl",
    "x86_64-unknown-freebsd",
    "aarch64-unknown-freebsd",
    "aarch64-linux-android",
    "armv7-linux-androideabi",
    "x86_64-linux-android",
    "aarch64-apple-darwin",
    "x86_64-apple-darwin",
    "universal-apple-darwin",
    "i686-linux-android",
    "armv5te-unknown-linux-musleabi",
    "powerpc64le-unknown-linux-musl",
    "s390x-unknown-linux-gnu",
    "s390x-unknown-linux-musl",
    "loongarch64-unknown-linux-musl",
    "mipsel-unknown-linux-musl",
    "mips-unknown-linux-musl",
    "x86_64-unknown-netbsd",
    "aarch64-unknown-netbsd",
    "x86_64-unknown-openbsd",
    "aarch64-unknown-openbsd",
];

/// The artifact for `spec` among `artifacts`: the first candidate target
/// that is present, preferring the running client's version.
pub fn pick<'a>(artifacts: &'a [Artifact], spec: &str) -> Result<&'a Artifact> {
    let wanted = candidates(spec)?;
    let own = env!("CARGO_PKG_VERSION");
    for target in &wanted {
        let mut matching: Vec<&Artifact> =
            artifacts.iter().filter(|a| a.target == *target).collect();
        if matching.is_empty() {
            continue;
        }
        matching.sort_by(|a, b| {
            (b.version == own)
                .cmp(&(a.version == own))
                .then(b.version.cmp(&a.version))
        });
        return Ok(matching[0]);
    }
    Err(coded(
        codes::NOT_FOUND,
        anyhow!(
            "no installed artifact for {spec:?} (wanted {}); build it with `scripts/release.sh {}` \
             or `cargo xtask install --dist`",
            wanted.join(" or "),
            wanted[0]
        ),
    ))
}

/// Run the command; the exit code.
pub async fn run(
    args: &AssetsArgs,
    config: &Config,
    paths: &Paths,
    console: &Console,
) -> Result<i32> {
    let dir = args.dir.clone().unwrap_or_else(|| config.assets_dir(paths));
    let artifacts = list(&dir)?;
    if let Some(spec) = &args.for_spec {
        let chosen = pick(&artifacts, spec)?;
        console.report(chosen, || format!("{}\n", chosen.path.display()));
        console.flush().await;
        return Ok(0);
    }
    if artifacts.is_empty() {
        return Err(coded(
            codes::NOT_FOUND,
            anyhow!(
                "no release artifacts in {}: build them with `scripts/release.sh` (one target: \
                 `scripts/release.sh TARGET`) and install with `cargo xtask install`, or set \
                 `[assets] dir` in {} / `MYSH_ASSETS_DIR`",
                dir.display(),
                paths.config_file.display()
            ),
        ));
    }
    let out = AssetsOut {
        dir: dir.clone(),
        artifacts,
    };
    console.report(&out, || human(&out));
    console.flush().await;
    Ok(0)
}

fn human(out: &AssetsOut) -> String {
    use std::fmt::Write as _;
    let mut s = format!("{}\n", out.dir.display());
    let width = out
        .artifacts
        .iter()
        .map(|a| a.target.len())
        .max()
        .unwrap_or(6)
        .max(6);
    let _ = writeln!(s, "{:<width$}  VERSION        SIZE  SHA256", "TARGET");
    for a in &out.artifacts {
        let _ = writeln!(
            s,
            "{:<width$}  {:<8}  {:>9}  {}",
            a.target,
            a.version,
            a.size,
            a.sha256.as_deref().map_or("-", |h| &h[..h.len().min(12)])
        );
    }
    s.push_str("`mysh assets --for \"$(uname -sm)\"` on the remote's output picks one (android/ARCH for Android).\n");
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_parse_and_reject_noise() {
        assert_eq!(
            parse_name("mysh-0.1.0-aarch64-unknown-linux-musl"),
            Some(("0.1.0", "aarch64-unknown-linux-musl"))
        );
        assert_eq!(
            parse_name("mysh-0.1.0-universal-apple-darwin"),
            Some(("0.1.0", "universal-apple-darwin"))
        );
        assert_eq!(parse_name("SHA256SUMS"), None);
        assert_eq!(parse_name("mysh"), None);
        assert_eq!(parse_name("mysh-notes-x"), None);
    }

    #[test]
    fn uname_output_maps_to_targets() {
        assert_eq!(
            candidates("Linux aarch64").unwrap(),
            vec!["aarch64-unknown-linux-musl"]
        );
        assert_eq!(
            candidates("Linux armv6l").unwrap(),
            vec!["arm-unknown-linux-musleabihf"]
        );
        assert_eq!(
            candidates("Darwin arm64").unwrap(),
            vec!["aarch64-apple-darwin", "universal-apple-darwin"]
        );
        assert_eq!(
            candidates("FreeBSD amd64").unwrap(),
            vec!["x86_64-unknown-freebsd"]
        );
        assert_eq!(
            candidates("android/aarch64").unwrap(),
            vec!["aarch64-linux-android"]
        );
        assert_eq!(
            candidates("Linux s390x").unwrap(),
            vec!["s390x-unknown-linux-musl", "s390x-unknown-linux-gnu"]
        );
        assert_eq!(
            candidates("x86_64-unknown-netbsd").unwrap(),
            vec!["x86_64-unknown-netbsd"]
        );
        assert!(candidates("Plan9 amd64").is_err());
        assert!(candidates("Linux vax").is_err());
        assert!(candidates("nonsense").is_err());
    }

    fn artifact(target: &str, version: &str) -> Artifact {
        Artifact {
            target: target.to_owned(),
            version: version.to_owned(),
            path: PathBuf::from(format!("/a/mysh-{version}-{target}")),
            size: 1,
            sha256: None,
        }
    }

    #[test]
    fn pick_prefers_the_first_present_candidate_and_own_version() {
        let own = env!("CARGO_PKG_VERSION");
        let arts = vec![
            artifact("universal-apple-darwin", own),
            artifact("aarch64-unknown-linux-musl", "0.0.1"),
            artifact("aarch64-unknown-linux-musl", own),
            artifact("s390x-unknown-linux-gnu", own),
        ];
        // The specific slice is absent, the universal binary is the fallback.
        assert_eq!(
            pick(&arts, "Darwin arm64").unwrap().target,
            "universal-apple-darwin"
        );
        assert_eq!(pick(&arts, "Linux aarch64").unwrap().version, own);
        assert_eq!(
            pick(&arts, "Linux s390x").unwrap().target,
            "s390x-unknown-linux-gnu"
        );
        let err = pick(&arts, "Linux riscv64").unwrap_err();
        assert!(
            err.to_string().contains("riscv64gc-unknown-linux-musl"),
            "{err}"
        );
    }

    #[test]
    fn listing_reads_sums_and_skips_other_files() {
        let dir = std::env::temp_dir().join(format!("mysh-assets-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("mkdir");
        std::fs::write(dir.join("mysh-0.1.0-x86_64-unknown-linux-musl"), b"abc").expect("w");
        std::fs::write(dir.join("mysh-0.1.0-aarch64-unknown-linux-musl"), b"abcd").expect("w");
        std::fs::write(dir.join("README"), b"x").expect("w");
        std::fs::write(
            dir.join("SHA256SUMS"),
            "deadbeef  mysh-0.1.0-x86_64-unknown-linux-musl\n",
        )
        .expect("w");
        let got = list(&dir).expect("list");
        assert_eq!(got.len(), 2);
        assert_eq!(got[0].target, "aarch64-unknown-linux-musl");
        assert_eq!(got[0].size, 4);
        assert_eq!(got[0].sha256, None);
        assert_eq!(got[1].sha256.as_deref(), Some("deadbeef"));
        assert_eq!(list(&dir.join("missing")).expect("missing dir"), Vec::new());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
