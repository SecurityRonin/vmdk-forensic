//! Pure-Rust read-only VMware VMDK sparse disk image reader.
//!
//! Supports monolithic sparse VMDKs (VMware Workstation/Fusion format).
//! Flat extents and compressed (stream-optimized) VMDKs are not supported.

use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::path::Path;

mod error;
mod header;

pub use error::VmdkError;

use header::{SparseExtentHeader, SECTOR_SIZE};

/// Read-only VMDK container reader.
///
/// Implements `Read + Seek` over the virtual sector stream.
pub struct VmdkReader {
    file: File,
    virtual_disk_size: u64,
    grain_size_bytes: u64,
    grain_dir: Vec<u32>,
    num_gtes_per_gt: u64,
    pos: u64,
}

impl VmdkReader {
    /// Open a monolithic sparse VMDK disk image.
    pub fn open(path: &Path) -> Result<Self, VmdkError> {
        todo!("implement VmdkReader::open")
    }

    /// Virtual disk size in bytes as recorded in the VMDK header.
    pub fn virtual_disk_size(&self) -> u64 {
        self.virtual_disk_size
    }
}

impl Read for VmdkReader {
    fn read(&mut self, _buf: &mut [u8]) -> io::Result<usize> {
        todo!("implement VmdkReader::read")
    }
}

impl Seek for VmdkReader {
    fn seek(&mut self, _pos: SeekFrom) -> io::Result<u64> {
        todo!("implement VmdkReader::seek")
    }
}

// ── Test helpers ──────────────────────────────────────────────────────────────

#[cfg(feature = "test-helpers")]
pub mod testutil;
#[cfg(not(feature = "test-helpers"))]
mod testutil;

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use testutil::test_sparse_vmdk;

    fn write_tmp(data: &[u8]) -> tempfile::NamedTempFile {
        use std::io::Write;
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(data).unwrap();
        f
    }

    #[test]
    fn open_nonexistent_returns_err() {
        assert!(VmdkReader::open(Path::new("/tmp/no_such.vmdk")).is_err());
    }

    #[test]
    fn open_empty_file_returns_err() {
        let f = write_tmp(&[]);
        assert!(VmdkReader::open(f.path()).is_err());
    }

    #[test]
    fn open_non_vmdk_file_returns_err() {
        let f = write_tmp(b"this is not a vmdk file at all");
        assert!(VmdkReader::open(f.path()).is_err());
    }

    #[test]
    fn sparse_vmdk_virtual_disk_size() {
        let vmdk = test_sparse_vmdk(&[0u8; 512]);
        let f = write_tmp(&vmdk);
        let reader = VmdkReader::open(f.path()).expect("open");
        // 1 grain of 8 sectors = 4096 bytes
        assert_eq!(reader.virtual_disk_size(), testutil::GRAIN_SIZE_BYTES as u64);
    }

    #[test]
    fn sparse_vmdk_read_returns_sector_data() {
        let mut data = vec![0u8; 512];
        data[42] = 0xDE;
        data[43] = 0xAD;
        let vmdk = test_sparse_vmdk(&data);
        let f = write_tmp(&vmdk);
        let mut reader = VmdkReader::open(f.path()).expect("open");
        let mut buf = vec![0u8; 512];
        reader.read_exact(&mut buf).expect("read");
        assert_eq!(buf[42], 0xDE);
        assert_eq!(buf[43], 0xAD);
    }

    #[test]
    fn seek_and_read_at_offset() {
        let mut data = vec![0u8; testutil::GRAIN_SIZE_BYTES];
        data[100] = 0xBE;
        data[101] = 0xEF;
        let vmdk = test_sparse_vmdk(&data);
        let f = write_tmp(&vmdk);
        let mut reader = VmdkReader::open(f.path()).expect("open");
        reader.seek(SeekFrom::Start(100)).unwrap();
        let mut buf = [0u8; 2];
        reader.read_exact(&mut buf).unwrap();
        assert_eq!(buf, [0xBE, 0xEF]);
    }

    #[test]
    fn vmdk_reader_is_send() {
        fn assert_send<T: Send>() {}
        assert_send::<VmdkReader>();
    }
}
