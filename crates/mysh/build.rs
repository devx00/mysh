//! Embeds key material for the `baked` feature.
//!
//! The build script does no parsing: it emits `include_str!` of the two input
//! files so the runtime uses the same key-file parsers as the on-disk paths.
//! Without the feature both constants are `None` and nothing is embedded.

use std::{env, fs, path::PathBuf};

fn main() {
    println!("cargo:rerun-if-env-changed=MYSH_BAKED_IDENTITY");
    println!("cargo:rerun-if-env-changed=MYSH_BAKED_PEERS");

    let out = PathBuf::from(env::var_os("OUT_DIR").expect("cargo sets OUT_DIR")).join("baked.rs");
    let src = if env::var_os("CARGO_FEATURE_BAKED").is_some() {
        let identity = required("MYSH_BAKED_IDENTITY");
        let peers = required("MYSH_BAKED_PEERS");
        format!(
            "pub const IDENTITY: Option<&str> = Some(include_str!({identity:?}));\n\
             pub const PEERS: Option<&str> = Some(include_str!({peers:?}));\n"
        )
    } else {
        "pub const IDENTITY: Option<&str> = None;\n\
         pub const PEERS: Option<&str> = None;\n"
            .to_owned()
    };
    fs::write(&out, src).expect("write baked.rs into OUT_DIR");
}

fn required(var: &str) -> String {
    let Some(value) = env::var_os(var) else {
        panic!("feature `baked` requires {var}=<path to key file>");
    };
    let path = fs::canonicalize(&value)
        .unwrap_or_else(|e| panic!("{var}={}: {e}", PathBuf::from(&value).display()));
    println!("cargo:rerun-if-changed={}", path.display());
    path.to_str()
        .unwrap_or_else(|| panic!("{var}: path is not valid UTF-8"))
        .to_owned()
}
