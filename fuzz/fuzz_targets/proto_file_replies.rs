#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    use mysh_proto::file::{Attrs, DirEntry, ListPage, PutDone};
    use mysh_proto::frame::decode;
    let _ = decode::<Attrs>(data);
    let _ = decode::<ListPage>(data);
    let _ = decode::<PutDone>(data);
    let _ = decode::<DirEntry>(data);
});
