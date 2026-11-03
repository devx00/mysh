//! Remote process API; lives in [`mysh_client::session_api`]. The binary's
//! [`run`] adds what the library refuses to do: read this process's stdin
//! for `session send --stdin`.

use anyhow::{Context as _, Result};
use tokio::io::AsyncReadExt as _;

pub use mysh_client::session_api::*;
use mysh_client::{
    args::{SessionArgs, SessionCmd},
    conn::Connection,
};

use super::console::Console;

/// [`mysh_client::session_api::run`] for the CLI. `stdin` carries the
/// bytes of a `send --stdin` that came over the control socket; `None`
/// reads the process's own stdin. Returns the process exit code.
pub async fn run(
    conn: &Connection,
    console: &Console,
    args: &SessionArgs,
    stdin: Option<&[u8]>,
) -> Result<i32> {
    let mut own = Vec::new();
    let stdin = match (&args.cmd, stdin) {
        (SessionCmd::Send(send), None) if send.stdin => {
            tokio::io::stdin()
                .read_to_end(&mut own)
                .await
                .context("reading stdin")?;
            Some(own.as_slice())
        }
        (_, stdin) => stdin,
    };
    mysh_client::session_api::run(conn, console, args, stdin).await
}
