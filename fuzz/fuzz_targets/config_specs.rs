#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let _ = text.parse::<mysh::config::HostSpec>();
    let _ = mysh::config::ForwardSpec::parse_local(text);
    let _ = mysh::config::ForwardSpec::parse_dynamic(text);
    let _ = mysh::config::parse_meta_key(text);
    let _ = mysh::config::decode_send_text(text);
    let _ = mysh::cli::parse_meta_line(text);
});
