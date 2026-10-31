#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let hosts = mysh_net::trust::KnownHosts::parse(text, "fuzz");
    let key = mysh_net::keys::PublicKey::from_bytes([7u8; 32]);
    let _ = hosts.check("host", 7722, &key);
});
