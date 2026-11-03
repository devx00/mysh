#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    use mysh::client::fleet::{expand_hosts, parse_hosts};
    use mysh::config::Config;
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let hosts = parse_hosts(text);
    for host in &hosts {
        assert!(!host.is_empty() && host.trim() == host);
    }
    // First line = host list, rest = config TOML (group definitions).
    let (list, toml) = text.split_once('\n').unwrap_or((text, ""));
    if let Ok(config) = Config::parse(toml) {
        let groups: Vec<String> = config.groups.keys().cloned().collect();
        let _ = expand_hosts(&[list.to_owned()], &groups, &config);
        let _ = expand_hosts(&hosts, &["nope".to_owned()], &config);
    }
});
