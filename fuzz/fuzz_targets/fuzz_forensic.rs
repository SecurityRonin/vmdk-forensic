//! Fuzz target: run the full forensic analyzer over arbitrary bytes.
//!
//! Invariant: VmdkIntegrity must never panic/hang/OOM on crafted input — the very
//! reason it reparses raw bytes with saturating, bounds-checked arithmetic.
#![no_main]
use libfuzzer_sys::fuzz_target;
use std::io::Cursor;

fuzz_target!(|data: &[u8]| {
    let mut a = vmdk_forensic::VmdkIntegrity::new(Cursor::new(data));
    let _ = a.analyse();
});
