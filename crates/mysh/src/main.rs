//! `mysh` entry point; everything lives in the library crate.

fn main() {
    println!(
        "mysh {} (protocol v{}, baked identity: {})",
        env!("CARGO_PKG_VERSION"),
        mysh_proto::PROTOCOL_VERSION,
        mysh::baked::IDENTITY.is_some(),
    );
}
