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
