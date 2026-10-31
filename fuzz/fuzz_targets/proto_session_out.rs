#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = mysh_proto::frame::decode::<mysh_proto::session::SessionOut>(data);
});
