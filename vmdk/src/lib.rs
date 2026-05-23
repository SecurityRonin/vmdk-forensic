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
        let mut file = File::open(path)?;

        let mut hdr_bytes = [0u8; 512];
        file.read_exact(&mut hdr_bytes)?;
        let hdr = SparseExtentHeader::parse(&hdr_bytes)?;

        let grain_size_bytes = hdr.grain_size * SECTOR_SIZE;
        let virtual_disk_size = hdr.capacity * SECTOR_SIZE;

        // Load grain directory (small enough to keep in memory).
        let num_grains = (hdr.capacity + hdr.grain_size - 1) / hdr.grain_size;
        let num_gts = (num_grains + u64::from(hdr.num_gtes_per_gt) - 1)
            / u64::from(hdr.num_gtes_per_gt);
        let gd_byte_len = num_gts * 4;

        file.seek(SeekFrom::Start(hdr.gd_offset * SECTOR_SIZE))?;
        let mut gd_bytes = vec![0u8; gd_byte_len as usize];
        file.read_exact(&mut gd_bytes)?;

        let grain_dir = gd_bytes
            .chunks_exact(4)
            .map(|c| u32::from_le_bytes(c.try_into().unwrap()))
            .collect();

        Ok(VmdkReader {
            file,
            virtual_disk_size,
            grain_size_bytes,
            grain_dir,
            num_gtes_per_gt: u64::from(hdr.num_gtes_per_gt),
            pos: 0,
        })
    }

    /// Virtual disk size in bytes as recorded in the VMDK header.
    pub fn virtual_disk_size(&self) -> u64 {
        self.virtual_disk_size
    }

    /// Resolve `virtual_offset` → file offset, or `None` for a sparse grain.
    fn file_offset_for(&mut self, virtual_offset: u64) -> io::Result<Option<u64>> {
        let grain_idx = virtual_offset / self.grain_size_bytes;
        let offset_in_grain = virtual_offset % self.grain_size_bytes;

        let gd_idx = grain_idx / self.num_gtes_per_gt;
        let gte_idx = grain_idx % self.num_gtes_per_gt;

        let gt_sector = self.grain_dir.get(gd_idx as usize).copied().unwrap_or(0);
        if gt_sector == 0 {
            return Ok(None);
        }

        let gte_file_pos = u64::from(gt_sector) * SECTOR_SIZE + gte_idx * 4;
        self.file.seek(SeekFrom::Start(gte_file_pos))?;
        let mut gte_bytes = [0u8; 4];
        self.file.read_exact(&mut gte_bytes)?;
        let gte = u32::from_le_bytes(gte_bytes);

        if gte <= 1 {
            return Ok(None); // sparse or zeroed
        }

        Ok(Some(u64::from(gte) * SECTOR_SIZE + offset_in_grain))
    }
}

impl Read for VmdkReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.pos >= self.virtual_disk_size || buf.is_empty() {
            return Ok(0);
        }

        let remaining_virtual = (self.virtual_disk_size - self.pos) as usize;
        // Don't cross a grain boundary in a single read.
        let remaining_in_grain =
            (self.grain_size_bytes - (self.pos % self.grain_size_bytes)) as usize;
        let to_read = buf.len().min(remaining_virtual).min(remaining_in_grain);

        let n = match self.file_offset_for(self.pos)? {
            Some(file_off) => {
                self.file.seek(SeekFrom::Start(file_off))?;
                self.file.read(&mut buf[..to_read])?
            }
            None => {
                // Sparse grain — return zeros.
                buf[..to_read].fill(0);
                to_read
            }
        };

        self.pos += n as u64;
        Ok(n)
    }
}

impl Seek for VmdkReader {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        let new_pos = match pos {
            SeekFrom::Start(n) => n as i64,
            SeekFrom::Current(n) => self.pos as i64 + n,
            SeekFrom::End(n) => self.virtual_disk_size as i64 + n,
        };
        if new_pos < 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "seek before start",
            ));
        }
        self.pos = new_pos as u64;
        Ok(self.pos)
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

    // ── Helpers ───────────────────────────────────────────────────────────────

    /// Build a minimal valid VMDK header (512 bytes) with configurable geometry.
    fn vmdk_header_bytes(capacity_sectors: u64, grain_size: u64, num_gtes_per_gt: u32) -> Vec<u8> {
        let mut h = vec![0u8; 512];
        h[0..4].copy_from_slice(&0x564D_444B_u32.to_le_bytes());         // magic
        h[4..8].copy_from_slice(&1u32.to_le_bytes());                    // version 1
        h[12..20].copy_from_slice(&capacity_sectors.to_le_bytes());      // capacity (sectors)
        h[20..28].copy_from_slice(&grain_size.to_le_bytes());            // grain_size (sectors)
        h[44..48].copy_from_slice(&num_gtes_per_gt.to_le_bytes());       // num_gtes_per_gt
        // compress_algorithm at bytes 77..79 stays 0 (no compression)
        h
    }

    // ── Panic regression tests (RED until header.rs validates grain geometry) ─

    #[test]
    fn grain_size_zero_rejected() {
        // grain_size=0 triggers div-by-zero on `(capacity + grain_size - 1) / grain_size`
        // (lib.rs line 42) or u64 underflow if capacity is also 0.
        let f = write_tmp(&vmdk_header_bytes(8, 0, 512));
        assert!(VmdkReader::open(f.path()).is_err());
    }

    #[test]
    fn num_gtes_per_gt_zero_rejected() {
        // num_gtes_per_gt=0 triggers div-by-zero on `(num_grains + 0 - 1) / 0`
        // (lib.rs line 43-44).
        let f = write_tmp(&vmdk_header_bytes(8, 8, 0));
        assert!(VmdkReader::open(f.path()).is_err());
    }

    // ── Existing tests ────────────────────────────────────────────────────────

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

    // ── Property tests: open() never panics on arbitrary input ────────────────

    proptest::proptest! {
        #[test]
        fn open_never_panics_on_arbitrary_bytes(
            bytes in proptest::collection::vec(proptest::prelude::any::<u8>(), 0..8192)
        ) {
            let f = write_tmp(&bytes);
            let _ = VmdkReader::open(f.path());
        }

        #[test]
        fn open_never_panics_on_valid_magic_plus_garbage(
            suffix in proptest::collection::vec(proptest::prelude::any::<u8>(), 0..8192)
        ) {
            // Correct magic + version 1 prefix — exercises field parsing with random data.
            let mut bytes = vec![0u8; 8];
            bytes[0..4].copy_from_slice(&0x564D_444B_u32.to_le_bytes());
            bytes[4..8].copy_from_slice(&1u32.to_le_bytes());
            bytes.extend_from_slice(&suffix);
            let f = write_tmp(&bytes);
            let _ = VmdkReader::open(f.path());
        }
    }

    // ── Differential test: bytes must match qemu-img convert -O raw output ────

    #[test]
    fn reads_match_qemu_raw_convert() {
        const QEMU_IMG: &str = "/opt/homebrew/bin/qemu-img";
        if !Path::new(QEMU_IMG).exists() {
            return;
        }
        let tmp = tempfile::tempdir().expect("tempdir");

        // 1 MiB source with a deterministic non-trivial pattern covering
        // sector and grain boundaries (default grain = 128 sectors = 65536 B).
        let size: usize = 1 << 20;
        let raw_data: Vec<u8> = (0..size).map(|i| (i ^ (i >> 8)) as u8).collect();
        let raw_path = tmp.path().join("source.raw");
        std::fs::write(&raw_path, &raw_data).expect("write raw");

        let vmdk_path = tmp.path().join("test.vmdk");
        let status = std::process::Command::new(QEMU_IMG)
            .args(["convert", "-O", "vmdk",
                   raw_path.to_str().unwrap(),
                   vmdk_path.to_str().unwrap()])
            .status()
            .expect("spawn qemu-img");
        assert!(status.success(), "qemu-img convert failed");

        let mut reader = VmdkReader::open(&vmdk_path).expect("open");
        assert_eq!(reader.virtual_disk_size(), size as u64);

        // Sample: start, mid-sector, grain boundary, grain+sector, near-end.
        let grain = 512 * 128; // 65536 B — qemu default VMDK grain size
        for &offset in &[0usize, 511, grain, grain + 512, size - 512] {
            let len = 512.min(size - offset);
            let mut buf = vec![0u8; len];
            reader.seek(SeekFrom::Start(offset as u64)).expect("seek");
            reader.read_exact(&mut buf).expect("read");
            assert_eq!(
                buf,
                raw_data[offset..offset + len],
                "byte mismatch at offset {offset:#x}",
            );
        }
    }

    // ── Corpus differential test: qemu-img generated minimal.vmdk ────────────

    #[test]
    fn corpus_minimal_vmdk_reads_match_qemu_raw_convert() {
        const QEMU_IMG: &str = "/opt/homebrew/bin/qemu-img";
        if !Path::new(QEMU_IMG).exists() {
            return;
        }
        let corpus = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/data/minimal.vmdk");
        if !corpus.exists() {
            return;
        }
        let tmp = tempfile::tempdir().expect("tempdir");
        let raw_path = tmp.path().join("minimal.raw");
        let ok = std::process::Command::new(QEMU_IMG)
            .args(["convert", "-O", "raw",
                   corpus.to_str().unwrap(),
                   raw_path.to_str().unwrap()])
            .status().expect("spawn qemu-img").success();
        assert!(ok, "qemu-img convert failed");
        let ref_data = std::fs::read(&raw_path).expect("read raw");

        let mut reader = VmdkReader::open(&corpus).expect("open corpus");
        assert_eq!(reader.virtual_disk_size(), ref_data.len() as u64,
            "virtual_disk_size must match reference raw length");

        let vsize = ref_data.len();
        let grain = 65536usize;
        let samples = [0usize, 511, grain, grain + 512, vsize - 512];
        for &offset in &samples {
            let len = 512.min(vsize - offset);
            let mut buf = vec![0u8; len];
            reader.seek(SeekFrom::Start(offset as u64)).expect("seek");
            reader.read_exact(&mut buf).expect("read");
            assert_eq!(
                buf, ref_data[offset..offset + len],
                "byte mismatch at offset {offset:#x}",
            );
        }
    }
}
