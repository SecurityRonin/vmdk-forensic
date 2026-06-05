//! Fuzz target: open arbitrary bytes and exercise the full read/inspect surface.
//!
//! Invariant: must never panic, hang, or OOM — only Ok/Err. Covers grain_location,
//! decompression, seSparse, the allocation scan, integrity walk, and RGD validation.
//!
//! Run with:  cargo +nightly fuzz run fuzz_read
#![no_main]
use libfuzzer_sys::fuzz_target;
use std::io::{Cursor, Read};

fuzz_target!(|data: &[u8]| {
    let Ok(mut r) = vmdk::VmdkReader::open(Cursor::new(data)) else {
        return;
    };
    // Bound the work: the virtual size is attacker-controlled, so read at most 1 MiB.
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
    let _ = r.validate_rgd();
});
