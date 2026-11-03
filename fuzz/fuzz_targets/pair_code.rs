#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let once = mysh_proto::pair::normalize_code(text);
    let twice = mysh_proto::pair::normalize_code(&once);
    assert_eq!(once, twice, "normalize_code must be idempotent");
    assert!(!once.starts_with('-') && !once.ends_with('-') && !once.contains("--"));
    assert!(
        !once
            .chars()
            .any(|c| c.is_whitespace() || c.is_ascii_uppercase())
    );
});
