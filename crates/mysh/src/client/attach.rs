//! Session persistence, client side (docs/05-meta-shell.md "Session
//! persistence", docs/03-protocol.md §10bis): `ListSessions` over the
//! connection, the rules that pick a session for `attach`/`--attach`, the
//! `detach` command, and the `sessions -a` listing.

use std::{
    fmt::Write as _,
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::{Context as _, Result, bail};
use mysh_net::framing::read_msg;
use mysh_proto::{caps, open::Open, session::DetachedSession};

use crate::client::{
    conn::Connection,
    console::{Console, human},
    session::Stack,
};

/// Whether the server advertised `caps::PERSIST` (detach grace > 0).
pub fn supported(conn: &Connection) -> bool {
    conn.server_hello().caps & caps::PERSIST != 0
}

fn require_support(conn: &Connection) -> Result<()> {
    if !supported(conn) {
        bail!("the server does not keep detached sessions (persistence is off)");
    }
    Ok(())
}

/// `Open::ListSessions`: this client key's PTY sessions on the server,
/// detached ones first.
pub async fn list(conn: &Connection) -> Result<Vec<DetachedSession>> {
    require_support(conn)?;
    let mut stream = conn
        .open(&Open::ListSessions)
        .await
        .context("listing sessions")?;
    read_msg(&mut stream)
        .await
        .context("reading the session list")
}

/// Pick the session to attach: `id` when given (it must be detached), else
/// the only detached one. Several candidates without an id is an error
/// listing them.
pub fn choose(rows: &[DetachedSession], id: Option<u32>) -> Result<u32> {
    if let Some(id) = id {
        return match rows.iter().find(|row| row.id == id) {
            Some(row) if row.detached.is_some() => Ok(id),
            Some(_) => bail!("session {id} is attached by another connection"),
            None => bail!("no detached session {id}"),
        };
    }
    let detached: Vec<&DetachedSession> = rows.iter().filter(|r| r.detached.is_some()).collect();
    match detached.as_slice() {
        [] => bail!("no detached sessions"),
        [only] => Ok(only.id),
        several => bail!(
            "{} detached sessions; pass an id:\n{}",
            several.len(),
            format(rows)
        ),
    }
}

fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
}

/// `3m12s`-style age of a unix timestamp.
fn age(since: i64, now: i64) -> String {
    let s = now.saturating_sub(since).max(0);
    if s >= 3600 {
        format!("{}h{:02}m", s / 3600, (s / 60) % 60)
    } else if s >= 60 {
        format!("{}m{:02}s", s / 60, s % 60)
    } else {
        format!("{s}s")
    }
}

/// Table for `sessions -a` and the "several candidates" error.
pub fn format(rows: &[DetachedSession]) -> String {
    format_at(rows, unix_now())
}

fn format_at(rows: &[DetachedSession], now: i64) -> String {
    let mut out = String::from("  ID   PID     KIND             STATE               BUFFERED\n");
    for row in rows {
        let state = match row.detached {
            Some(since) => format!("detached {} ago", age(since, now)),
            None => "attached".to_owned(),
        };
        let buffered = if row.buffered == 0 {
            "-".to_owned()
        } else {
            human(row.buffered)
        };
        let _ = writeln!(
            out,
            "  {:<4} {:<7} {:<16} {state:<19} {buffered}",
            row.id, row.pid, row.kind
        );
    }
    out
}

/// `sessions -a`: print the server's view below the local listing.
pub async fn print_remote(conn: &Connection, console: &Console) -> Result<()> {
    let rows = list(conn).await?;
    if rows.is_empty() {
        console.println("no sessions on the server");
    } else {
        console.print(&format(&rows));
    }
    Ok(())
}

/// `attach [ID]` / `--attach[=ID]`: list, choose, open `Open::Attach`, and
/// install the session in `stack` (not yet foregrounded). Returns its id.
pub async fn attach(conn: &Connection, stack: &mut Stack, id: Option<u32>) -> Result<u32> {
    let rows = list(conn).await?;
    let id = choose(&rows, id)?;
    let kind = rows
        .iter()
        .find(|row| row.id == id)
        .map_or_else(|| "shell".to_owned(), |row| row.kind.clone());
    stack.open_attached(conn, id, &kind).await
}

/// `detach [ID]` (default: most recently used): leave the session running
/// on the server and drop it from the stack. Refused when the server would
/// hang it up instead.
pub fn detach(
    conn: &Connection,
    console: &Console,
    stack: &mut Stack,
    id: Option<u32>,
) -> Result<()> {
    require_support(conn).context("detach")?;
    let Some(id) = id.or_else(|| stack.mru()) else {
        bail!("detach: no sessions");
    };
    stack.detach(id).context("detach")?;
    console.notice(&format!(
        "session {id} detached; reattach with: mysh --attach={id} {}",
        conn.target().display
    ));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(id: u32, detached: Option<i64>) -> DetachedSession {
        DetachedSession {
            id,
            pid: 100 + id,
            kind: "shell".to_owned(),
            started: 1_000,
            detached,
            buffered: u64::from(id) * 512,
        }
    }

    #[test]
    fn choose_rules() {
        assert!(
            choose(&[], None)
                .unwrap_err()
                .to_string()
                .contains("no detached")
        );
        assert_eq!(choose(&[row(3, Some(5))], None).unwrap(), 3);
        // Attached rows are not candidates.
        assert_eq!(choose(&[row(1, None), row(4, Some(5))], None).unwrap(), 4);
        let several = [row(1, Some(5)), row(2, Some(6))];
        let err = choose(&several, None).unwrap_err().to_string();
        assert!(err.contains("2 detached sessions"), "{err}");
        assert!(err.contains("ID   PID"), "{err}");
        assert_eq!(choose(&several, Some(2)).unwrap(), 2);
        assert!(
            choose(&several, Some(9))
                .unwrap_err()
                .to_string()
                .contains("no detached session 9")
        );
        assert!(
            choose(&[row(1, None)], Some(1))
                .unwrap_err()
                .to_string()
                .contains("attached by another")
        );
    }

    #[test]
    fn format_rows() {
        let text = format_at(&[row(2, Some(1_000)), row(5, None)], 1_000 + 3 * 60 + 12);
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 3);
        assert!(lines[1].starts_with("  2    102     shell"), "{}", lines[1]);
        assert!(lines[1].contains("detached 3m12s ago"), "{}", lines[1]);
        assert!(lines[1].ends_with("1.0 KiB"), "{}", lines[1]);
        assert!(lines[2].contains("attached "), "{}", lines[2]);
        assert!(lines[2].ends_with("2.5 KiB"), "{}", lines[2]);
        assert!(format_at(&[], 0).ends_with("BUFFERED\n"));
        assert_eq!(age(0, 3_725), "1h02m");
        assert_eq!(age(10, 15), "5s");
    }
}
