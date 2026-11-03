//! `mysh pair HOST CODE` (docs/02-security.md "Pairing"): the CLI wrapper
//! around `mysh_client::pair`, which does the SPAKE2 exchange and pins the
//! server key.

pub use mysh_client::pair::{exchange, known_hosts_line, pair, pairing_handshake};

use anyhow::Result;

use super::console::{Console, ConsolePrompt};
use crate::{
    config::{Paths, Target},
    identity::Baked,
    output::Mode as OutputMode,
};

/// Run `mysh pair`; returns the process exit code (0 on success). Errors
/// are usage/trust failures (exit 2 by the caller).
pub async fn run(
    target: &Target,
    code: &str,
    paths: &Paths,
    baked: &Baked,
    mode: OutputMode,
) -> Result<i32> {
    let console = Console::with_mode(mode);
    let prompt = ConsolePrompt::new(console.clone());
    let result = pair(target, code, paths, baked, &console, &prompt).await;
    console.flush().await;
    result.map(|_| 0)
}
