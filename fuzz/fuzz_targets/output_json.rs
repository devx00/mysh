#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    use mysh::output::{ExecResult, RunResult};
    if let Ok(v) = serde_json::from_slice::<ExecResult>(data) {
        let _ = v.code();
        let json = serde_json::to_vec(&v).expect("ExecResult serializes");
        let back: ExecResult = serde_json::from_slice(&json).expect("ExecResult round-trips");
        assert_eq!(v, back);
    }
    if let Ok(v) = serde_json::from_slice::<RunResult>(data) {
        let json = serde_json::to_vec(&v).expect("RunResult serializes");
        let _ = serde_json::from_slice::<RunResult>(&json).expect("RunResult round-trips");
    }
});
