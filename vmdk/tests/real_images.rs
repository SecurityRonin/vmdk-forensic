//! Integration tests against committed VMDK real-image corpus.
//!
//! All fixtures are in `tests/data/` — provenance in `tests/data/README.md`.
//! Images that the reader doesn't support must return `Err`, not panic.

use std::io::{Cursor, Read, Seek, SeekFrom};

const DATA_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data");

fn read_fixture(name: &str) -> Vec<u8> {
    let path = format!("{DATA_DIR}/{name}");
    std::fs::read(&path).unwrap_or_else(|e| panic!("read {name}: {e}"))
}

// ── minimal.vmdk (monolithicSparse v1, 1 MiB virtual) ────────────────────────

#[test]
fn minimal_vmdk_virtual_disk_size() {
    let data = read_fixture("minimal.vmdk");
    let reader = vmdk::VmdkReader::open(Cursor::new(data)).expect("minimal.vmdk must open");
    assert_eq!(
        reader.virtual_disk_size(),
        1_048_576,
        "minimal.vmdk: 1 MiB virtual disk (README)"
    );
}

#[test]
fn minimal_vmdk_sector0_is_zeros() {
    let data = read_fixture("minimal.vmdk");
    let mut reader = vmdk::VmdkReader::open(Cursor::new(data)).expect("open");
    let mut buf = [0xFFu8; 512];
    reader.seek(SeekFrom::Start(0)).expect("seek");
    reader.read_exact(&mut buf).expect("read sector 0");
    assert_eq!(
        buf,
        [0u8; 512],
        "freshly-created sparse VMDK — sector 0 must be all zeros"
    );
}

// ── dfvfs_ext2.vmdk (dfvfs corpus, ext2 filesystem) ──────────────────────────

#[test]
fn dfvfs_ext2_vmdk_opens_and_has_nonzero_size() {
    let data = read_fixture("dfvfs_ext2.vmdk");
    let reader = vmdk::VmdkReader::open(Cursor::new(data)).expect("dfvfs_ext2.vmdk must open");
    assert!(
        reader.virtual_disk_size() > 0,
        "dfvfs_ext2.vmdk virtual_disk_size must be > 0"
    );
}

#[test]
fn dfvfs_ext2_vmdk_read_is_stable() {
    let data = read_fixture("dfvfs_ext2.vmdk");
    let mut reader = vmdk::VmdkReader::open(Cursor::new(data)).expect("open");
    let mut a = [0u8; 512];
    reader.seek(SeekFrom::Start(0)).expect("seek");
    reader.read_exact(&mut a).expect("first read");
    let mut b = [0u8; 512];
    reader.seek(SeekFrom::Start(0)).expect("seek");
    reader.read_exact(&mut b).expect("second read");
    assert_eq!(a, b, "repeated reads at offset 0 must be identical");
}

// ── disk_type from embedded descriptor ───────────────────────────────────────

#[test]
fn minimal_vmdk_disk_type_is_monolithic_sparse() {
    let data = read_fixture("minimal.vmdk");
    let reader = vmdk::VmdkReader::open(Cursor::new(data)).expect("open");
    assert_eq!(
        reader.disk_type(),
        "monolithicSparse",
        "minimal.vmdk must report createType monolithicSparse"
    );
}

#[test]
fn dfvfs_ext2_disk_type_is_monolithic_sparse() {
    let data = read_fixture("dfvfs_ext2.vmdk");
    let reader = vmdk::VmdkReader::open(Cursor::new(data)).expect("open");
    assert_eq!(
        reader.disk_type(),
        "monolithicSparse",
        "dfvfs_ext2.vmdk (VMware4 origin) must report createType monolithicSparse"
    );
}

// ── Unsupported formats — must return Err, never panic ────────────────────────

#[test]
fn stream_opt_vmdk_returns_err() {
    let data = read_fixture("stream_opt.vmdk");
    let result = vmdk::VmdkReader::open(Cursor::new(data));
    assert!(
        result.is_err(),
        "streamOptimized VMDK (v3) must be rejected with Err, not panic"
    );
}

#[test]
fn flat_vmdk_descriptor_returns_err() {
    let data = read_fixture("flat.vmdk");
    let result = vmdk::VmdkReader::open(Cursor::new(data));
    assert!(
        result.is_err(),
        "monolithic flat VMDK descriptor must be rejected with Err, not panic"
    );
}
