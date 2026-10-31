//! `mysh`: client, server, and utilities in one binary.
//!
//! Scaffold only. Module layout planned in `docs/01-architecture.md`:
//! `cli`, `client` (terminal driver, meta shell, forwards), `server`
//! (sessions, files, forwards), `config`.

mod baked {
    include!(concat!(env!("OUT_DIR"), "/baked.rs"));
}

fn main() {
    let peers = baked::PEERS.map_or(0, |p| p.lines().filter(|l| !l.trim().is_empty()).count());
    println!(
        "mysh {} (protocol v{}, baked identity: {}, baked peers: {peers})",
        env!("CARGO_PKG_VERSION"),
        mysh_proto::PROTOCOL_VERSION,
        baked::IDENTITY.is_some(),
    );
}
