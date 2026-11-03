//! Fleet fan-out (docs/05-meta-shell.md "Fleet"): the same exec on many
//! hosts, `jobs` at a time, each host's events attributed to it.
//!
//! [`run`] connects to every target with its own [`Client`] and folds the
//! exec into one [`RunResult`] per host, in the order given; a host that
//! cannot be reached gets an `error` instead of an exit status and never
//! fails the whole run. The host selection helpers ([`parse_hosts`],
//! [`expand_hosts`]) are what `--hosts` / `--group` go through.

use std::{sync::Arc, time::Instant};

use tokio::{sync::Semaphore, task::JoinSet};

use crate::{
    client::{Client, ExecRequest},
    config::{Config, Paths, Target},
    identity::Baked,
    report::{Reporter, TrustPrompt},
    types::{Event, RunResult},
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

/// Attributes one host's events to it on the shared reporter.
struct HostReporter {
    host: String,
    inner: Arc<dyn Reporter>,
}

impl Reporter for HostReporter {
    fn event(&self, ev: &Event) {
        self.inner.event(&Event::Host {
            host: self.host.clone(),
            data: Box::new(ev.clone()),
        });
    }
}

/// Run `req` on every target, at most `jobs` at a time. Each host's
/// events reach `reporter` wrapped in [`Event::Host`]; the results come
/// back in the order of `targets`. The `host` of each result is the
/// target's `display` name.
pub async fn run(
    targets: &[Target],
    req: ExecRequest,
    jobs: usize,
    paths: &Paths,
    baked: &Baked,
    reporter: Arc<dyn Reporter>,
    prompt: Arc<dyn TrustPrompt>,
) -> Vec<RunResult> {
    let limit = Arc::new(Semaphore::new(jobs.max(1)));
    let paths = Arc::new(paths.clone());
    let baked = Arc::new(baked.clone());
    let mut tasks = JoinSet::new();
    for (index, target) in targets.iter().cloned().enumerate() {
        let limit = Arc::clone(&limit);
        let paths = Arc::clone(&paths);
        let baked = Arc::clone(&baked);
        let prompt = Arc::clone(&prompt);
        let req = req.clone();
        let host_reporter: Arc<dyn Reporter> = Arc::new(HostReporter {
            host: target.display.clone(),
            inner: Arc::clone(&reporter),
        });
        tasks.spawn(async move {
            let _permit = limit.acquire_owned().await;
            let started = Instant::now();
            let result = run_one(&target, req, &paths, &baked, host_reporter, prompt).await;
            let result = match result {
                Ok(result) => result,
                Err(e) => RunResult::failed(
                    &target.display,
                    e.inner(),
                    u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
                ),
            };
            (index, result)
        });
    }
    let mut results: Vec<Option<RunResult>> = targets.iter().map(|_| None).collect();
    while let Some(joined) = tasks.join_next().await {
        if let Ok((index, result)) = joined {
            results[index] = Some(result);
        }
    }
    results
        .into_iter()
        .zip(targets)
        .map(|(r, t)| {
            r.unwrap_or_else(|| {
                RunResult::failed(&t.display, &anyhow::anyhow!("fan-out task panicked"), 0)
            })
        })
        .collect()
}

async fn run_one(
    target: &Target,
    req: ExecRequest,
    paths: &Paths,
    baked: &Baked,
    reporter: Arc<dyn Reporter>,
    prompt: Arc<dyn TrustPrompt>,
) -> crate::Result<RunResult> {
    let client = Client::connect(target, paths, baked, Arc::clone(&reporter), prompt).await?;
    let exec = client.exec_stream(req, |ev| reporter.event(&ev)).await;
    client.close().await;
    let exec = exec?;
    Ok(RunResult {
        host: target.display.clone(),
        ok: exec.exit == Some(0) && !exec.timed_out,
        exit: exec.exit,
        signal: exec.signal,
        stdout: exec.stdout,
        stderr: exec.stderr,
        duration_ms: exec.duration_ms,
        error: None,
    })
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
}
