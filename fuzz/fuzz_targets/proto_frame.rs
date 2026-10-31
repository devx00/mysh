#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    use mysh_proto::frame::{HEADER_LEN, body_len, decode};
    if let Some(header) = data.first_chunk::<HEADER_LEN>() {
        let _ = body_len(*header);
    }
    let _ = decode::<Vec<u8>>(data);
});
