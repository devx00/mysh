#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    use mysh_proto::frame::decode;
    use mysh_proto::handshake::{ClientHello, ServerHello, Verdict};
    let _ = decode::<ServerHello>(data);
    let _ = decode::<ClientHello>(data);
    let _ = decode::<Verdict>(data);
});
