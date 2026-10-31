#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let mut passphrase = |_prompt: &str| -> std::io::Result<String> {
        Err(std::io::Error::other("fuzz: no passphrase"))
    };
    let _ = mysh_net::keys::parse_secret_key(text, "fuzz", &mut passphrase);
});
