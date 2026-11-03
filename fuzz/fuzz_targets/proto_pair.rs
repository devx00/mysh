#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    use mysh_proto::pair::{PairMsg, normalize_code};
    if let Ok(PairMsg::Failed { reason }) = mysh_proto::frame::decode::<PairMsg>(data) {
        let _ = normalize_code(&reason);
    }
    if let Ok(text) = std::str::from_utf8(data) {
        let _ = normalize_code(text);
    }
});
