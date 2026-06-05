//! Fuzz target: exercise the opt-in RGD recovery paths against crafted input.
//!
//! The recovery code resolves attacker-controlled GD/RGD/GT pointers; it must never
//! panic, hang, or OOM on any input — only Ok/Err.
//!
//! Run with:  cargo +nightly fuzz run fuzz_recover
#![no_main]
use libfuzzer_sys::fuzz_target;
use std::io::{Cursor, Read};

fuzz_target!(|data: &[u8]| {
    let Ok(mut r) = vmdk::VmdkReader::open(Cursor::new(data)) else {
        return;
    };
    r.enable_rgd_fallback();
    let mut buf = [0u8; 65536];
    let mut total = 0usize;
    while total < 1 << 20 {
        match r.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => total += n,
            Err(_) => break,
        }
    }
    let _ = r.iter_allocated_grains();
    let _ = r.check_integrity();
    let _ = r.grain_directory_recovery();
    let _ = r.rgd_recovery_count();
});
