//! Pure-Rust read-only VMDK disk image reader.
//!
//! Supports monolithic sparse (`monolithicSparse`), stream-optimised
//! (`streamOptimized`, including allocated compressed grains), flat-extent
//! VMDKs (`twoGbMaxExtentFlat`, `monolithicFlat`), and multi-file sparse
//! extents (`twoGbMaxExtentSparse`).

use std::fs::File;
use std::io::{self, BufReader, Read, Seek, SeekFrom};
use std::path::Path;

mod descriptor;
pub(crate) mod error;
mod flat;
mod header;
mod sparse_multi;

pub use error::VmdkError;

use descriptor::parse_text_descriptor;
use flat::MultiExtentReader;
use header::{GD_AT_END, SparseExtentHeader, SECTOR_SIZE};
use sparse_multi::MultiSparseReader;

// ── Public API types ──────────────────────────────────────────────────────────

/// Object-safe combination of [`Read`] and [`Seek`].
///
/// Automatically implemented for all `T: Read + Seek`.  Used as the inner
/// reader type for [`VmdkFileReader`].
pub trait ReadSeek: Read + Seek {}
impl<T: Read + Seek> ReadSeek for T {}

/// A VMDK reader opened from a file-system path, with an erased inner type.
///
/// Returned by [`VmdkReader::open_path`]; supports all formats including
/// multi-file flat extents that cannot be opened from a single stream.
pub type VmdkFileReader = VmdkReader<Box<dyn ReadSeek + Send>>;

// ── Internal format dispatch ──────────────────────────────────────────────────

enum FormatState {
    Sparse {
        grain_dir: Vec<u32>,
        grain_size_bytes: u64,
        num_gtes_per_gt: u64,
        /// `true` for stream-optimised VMDKs: allocated grains carry a zlib-wrapped payload.
        compressed: bool,
    },
    /// Raw flat extents — reads pass through directly to the inner reader.
    Flat,
}

/// Result of resolving a virtual offset to a physical grain location.
enum GrainLookup {
    /// Grain is not allocated — fill output with zeros.
    Sparse,
    /// Grain is uncompressed; data begins at this file byte offset.
    FileOffset(u64),
    /// Grain is zlib-compressed (streamOptimized); `data_offset` is the first
    /// byte of compressed payload (after the 12-byte `GrainMarker` header),
    /// `data_size` is the compressed length, and `offset_in_grain` is where
    /// to start reading within the decompressed grain.
    Compressed {
        data_offset: u64,
        data_size: u32,
        offset_in_grain: u64,
    },
}

// ── VmdkReader ────────────────────────────────────────────────────────────────

/// Read-only VMDK container reader, generic over any `Read + Seek` source.
///
/// Implements `Read + Seek` over the virtual sector stream.
///
/// # Examples
///
/// ```no_run
/// use std::fs::File;
/// use vmdk::VmdkReader;
///
/// let file = File::open("disk.vmdk").unwrap();
/// let mut reader = VmdkReader::open(file).unwrap();
/// println!("virtual disk size: {} bytes", reader.virtual_disk_size());
/// ```
pub struct VmdkReader<R: Read + Seek> {
    inner: R,
    fmt: FormatState,
    virtual_disk_size: u64,
    disk_type: Box<str>,
    pos: u64,
}

/// Maximum bytes read from an embedded descriptor (guards against crafted images).
const MAX_DESCRIPTOR_BYTES: u64 = 64 * 1024;

fn read_descriptor_create_type<R: Read + Seek>(
    reader: &mut R,
    hdr: &SparseExtentHeader,
) -> io::Result<Box<str>> {
    if hdr.descriptor_offset == 0 || hdr.descriptor_size == 0 {
        return Ok(Box::from(""));
    }
    let byte_offset = hdr
        .descriptor_offset
        .checked_mul(SECTOR_SIZE)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "descriptor_offset overflow"))?;
    let byte_len = hdr
        .descriptor_size
        .checked_mul(SECTOR_SIZE)
        .unwrap_or(MAX_DESCRIPTOR_BYTES)
        .min(MAX_DESCRIPTOR_BYTES);
    reader.seek(SeekFrom::Start(byte_offset))?;
    let mut buf = vec![0u8; byte_len as usize];
    reader.read_exact(&mut buf)?;
    Ok(Box::from(parse_create_type(&buf)))
}

fn parse_create_type(buf: &[u8]) -> &str {
    let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    let text = match std::str::from_utf8(&buf[..end]) {
        Ok(s) => s,
        Err(_) => return "",
    };
    for line in text.lines() {
        if let Some(rest) = line.trim().strip_prefix("createType=") {
            return rest.trim_matches('"');
        }
    }
    ""
}

impl<R: Read + Seek> VmdkReader<R> {
    /// Open a binary VMDK (monolithic sparse or stream-optimised) from any
    /// `Read + Seek` source.
    ///
    /// For multi-file flat VMDKs (text descriptor + extent files) use
    /// [`VmdkReader::open_path`] instead.
    pub fn open(mut reader: R) -> Result<Self, VmdkError> {
        let mut hdr_bytes = [0u8; 512];
        reader.read_exact(&mut hdr_bytes)?;
        let hdr = SparseExtentHeader::parse(&hdr_bytes)?;

        let grain_size_bytes = hdr
            .grain_size
            .checked_mul(SECTOR_SIZE)
            .ok_or_else(|| VmdkError::InvalidGeometry("grain_size overflow".into()))?;
        let virtual_disk_size = hdr
            .capacity
            .checked_mul(SECTOR_SIZE)
            .ok_or_else(|| VmdkError::InvalidGeometry("capacity overflow".into()))?;

        let disk_type = read_descriptor_create_type(&mut reader, &hdr)?;

        let num_grains = hdr
            .capacity
            .checked_add(hdr.grain_size - 1)
            .ok_or_else(|| VmdkError::InvalidGeometry("capacity+grain_size overflow".into()))?
            / hdr.grain_size;
        let num_gts = num_grains
            .checked_add(u64::from(hdr.num_gtes_per_gt) - 1)
            .ok_or_else(|| VmdkError::InvalidGeometry("num_grains overflow".into()))?
            / u64::from(hdr.num_gtes_per_gt);
        let gd_byte_len = num_gts
            .checked_mul(4)
            .ok_or_else(|| VmdkError::InvalidGeometry("gd_byte_len overflow".into()))?;

        const MAX_GD_BYTES: u64 = 16 * 1024 * 1024;
        if gd_byte_len > MAX_GD_BYTES {
            return Err(VmdkError::InvalidGeometry(
                "grain directory too large".into(),
            ));
        }
        // For streamOptimized, the primary header carries GD_AT_END as a sentinel;
        // the real GD offset is in the footer header at file_end − 1024 (VDF 1.1 §4.6).
        let gd_offset = if hdr.gd_offset == GD_AT_END {
            reader.seek(SeekFrom::End(-1024))?;
            let mut footer_bytes = [0u8; 512];
            reader.read_exact(&mut footer_bytes)?;
            SparseExtentHeader::parse(&footer_bytes)?.gd_offset
        } else {
            hdr.gd_offset
        };

        let gd_sector_offset = gd_offset
            .checked_mul(SECTOR_SIZE)
            .ok_or_else(|| VmdkError::InvalidGeometry("gd_offset overflow".into()))?;
        reader.seek(SeekFrom::Start(gd_sector_offset))?;
        let mut gd_bytes = vec![0u8; gd_byte_len as usize];
        reader.read_exact(&mut gd_bytes)?;

        let grain_dir = gd_bytes
            .chunks_exact(4)
            .map(|c| u32::from_le_bytes(c.try_into().expect("4-byte chunk from chunks_exact(4)")))
            .collect();

        Ok(VmdkReader {
            inner: reader,
            fmt: FormatState::Sparse {
                grain_dir,
                grain_size_bytes,
                num_gtes_per_gt: u64::from(hdr.num_gtes_per_gt),
                compressed: hdr.compressed,
            },
            virtual_disk_size,
            disk_type,
            pos: 0,
        })
    }

    /// Virtual disk size in bytes.
    pub fn virtual_disk_size(&self) -> u64 {
        self.virtual_disk_size
    }

    /// `createType` from the embedded text descriptor (e.g. `"monolithicSparse"`).
    ///
    /// Returns an empty string when no embedded descriptor is present.
    pub fn disk_type(&self) -> &str {
        &self.disk_type
    }

    /// Resolve `virtual_offset` to a [`GrainLookup`] describing where to find the data.
    fn grain_location(&mut self, virtual_offset: u64) -> io::Result<GrainLookup> {
        let (gt_sector, gte_idx, offset_in_grain, compressed) = {
            let FormatState::Sparse {
                grain_dir,
                grain_size_bytes,
                num_gtes_per_gt,
                compressed,
            } = &self.fmt
            else {
                return Ok(GrainLookup::Sparse); // Flat — not reached from Read::read
            };
            let grain_idx = virtual_offset / grain_size_bytes;
            let offset_in_grain = virtual_offset % grain_size_bytes;
            let gd_idx = (grain_idx / num_gtes_per_gt) as usize;
            let gte_idx = grain_idx % num_gtes_per_gt;
            let gt_sector = grain_dir.get(gd_idx).copied().unwrap_or(0);
            (gt_sector, gte_idx, offset_in_grain, *compressed)
        };
        if gt_sector == 0 {
            return Ok(GrainLookup::Sparse);
        }
        let gte_file_pos = u64::from(gt_sector) * SECTOR_SIZE + gte_idx * 4;
        self.inner.seek(SeekFrom::Start(gte_file_pos))?;
        let mut gte_bytes = [0u8; 4];
        self.inner.read_exact(&mut gte_bytes)?;
        let gte = u32::from_le_bytes(gte_bytes);
        if gte <= 1 {
            return Ok(GrainLookup::Sparse); // sparse or explicitly-zeroed grain
        }
        if compressed {
            // GrainMarker layout: u64 LBA (8 bytes) + u32 dataSize (4 bytes) + data.
            let marker_offset = u64::from(gte) * SECTOR_SIZE;
            self.inner.seek(SeekFrom::Start(marker_offset))?;
            let mut marker_hdr = [0u8; 12];
            self.inner.read_exact(&mut marker_hdr)?;
            let data_size = u32::from_le_bytes(marker_hdr[8..12].try_into().expect("4 bytes"));
            return Ok(GrainLookup::Compressed {
                data_offset: marker_offset + 12,
                data_size,
                offset_in_grain,
            });
        }
        Ok(GrainLookup::FileOffset(
            u64::from(gte) * SECTOR_SIZE + offset_in_grain,
        ))
    }

    /// Decompress a zlib-wrapped grain and copy the requested slice into `buf`.
    fn read_compressed_grain(
        &mut self,
        buf: &mut [u8],
        data_offset: u64,
        data_size: u32,
        offset_in_grain: u64,
    ) -> io::Result<usize> {
        use flate2::read::ZlibDecoder;

        self.inner.seek(SeekFrom::Start(data_offset))?;
        let mut compressed = vec![0u8; data_size as usize];
        self.inner.read_exact(&mut compressed)?;

        let mut decoder = ZlibDecoder::new(compressed.as_slice());
        let mut grain_data = Vec::new();
        decoder.read_to_end(&mut grain_data)?;

        let start = offset_in_grain as usize;
        let end = (start + buf.len()).min(grain_data.len());
        let n = end.saturating_sub(start);
        if n > 0 {
            buf[..n].copy_from_slice(&grain_data[start..end]);
        }
        Ok(n)
    }
}

// ── open_path (path-aware, all formats) ──────────────────────────────────────

impl VmdkFileReader {
    /// Open any VMDK format from a file-system path.
    ///
    /// Unlike [`VmdkReader::open`], this constructor handles text-descriptor
    /// VMDKs (`twoGbMaxExtentFlat`) that reference external extent files, as
    /// well as binary VMDKs that can be opened from a single stream.
    pub fn open_path(path: &Path) -> Result<Self, VmdkError> {
        // Peek at the first byte to distinguish text descriptors from binary VMDKs.
        let first_byte = {
            let mut buf = [0u8; 1];
            File::open(path)?.read_exact(&mut buf)?;
            buf[0]
        };

        if first_byte == b'#' {
            // Text descriptor: parse extents and route by createType.
            let text = std::fs::read_to_string(path)?;
            let desc = parse_text_descriptor(&text)?;
            let dir = path.parent().unwrap_or(Path::new("."));

            match desc.create_type.as_ref() {
                "twoGbMaxExtentFlat" | "monolithicFlat" => {
                    let multi = MultiExtentReader::open(dir, &desc.extents)?;
                    let virtual_disk_size = desc
                        .capacity_sectors
                        .checked_mul(SECTOR_SIZE)
                        .ok_or_else(|| VmdkError::InvalidGeometry("capacity overflow".into()))?;
                    Ok(VmdkReader {
                        inner: Box::new(multi) as Box<dyn ReadSeek + Send>,
                        fmt: FormatState::Flat,
                        virtual_disk_size,
                        disk_type: desc.create_type,
                        pos: 0,
                    })
                }
                "twoGbMaxExtentSparse" => {
                    let multi = MultiSparseReader::open(dir, &desc.sparse_extents)?;
                    let virtual_disk_size = desc
                        .sparse_capacity_sectors
                        .checked_mul(SECTOR_SIZE)
                        .ok_or_else(|| VmdkError::InvalidGeometry("capacity overflow".into()))?;
                    Ok(VmdkReader {
                        inner: Box::new(multi) as Box<dyn ReadSeek + Send>,
                        fmt: FormatState::Flat,
                        virtual_disk_size,
                        disk_type: desc.create_type,
                        pos: 0,
                    })
                }
                _ => Err(VmdkError::UnsupportedDiskType(
                    desc.create_type.into_string(),
                )),
            }
        } else {
            // Binary VMDK — parse normally then erase the reader type.
            let file = BufReader::new(File::open(path)?);
            Ok(VmdkReader::open(file)?.into_file_reader())
        }
    }
}

impl<R: Read + Seek + Send + 'static> VmdkReader<R> {
    fn into_file_reader(self) -> VmdkFileReader {
        VmdkFileReader {
            inner: Box::new(self.inner),
            fmt: self.fmt,
            virtual_disk_size: self.virtual_disk_size,
            disk_type: self.disk_type,
            pos: self.pos,
        }
    }
}

// ── Read + Seek impls ─────────────────────────────────────────────────────────

impl<R: Read + Seek> Read for VmdkReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.pos >= self.virtual_disk_size || buf.is_empty() {
            return Ok(0);
        }
        let remaining_virtual = (self.virtual_disk_size - self.pos) as usize;

        // Flat: direct pass-through to the inner reader at the current position.
        if matches!(self.fmt, FormatState::Flat) {
            let to_read = buf.len().min(remaining_virtual);
            self.inner.seek(SeekFrom::Start(self.pos))?;
            let n = self.inner.read(&mut buf[..to_read])?;
            self.pos += n as u64;
            return Ok(n);
        }

        // Sparse / StreamOptimized: clamp at grain boundary then do GTE lookup.
        let grain_size_bytes = match &self.fmt {
            FormatState::Sparse {
                grain_size_bytes, ..
            } => *grain_size_bytes,
            FormatState::Flat => unreachable!(),
        };
        let remaining_in_grain = (grain_size_bytes - (self.pos % grain_size_bytes)) as usize;
        let to_read = buf.len().min(remaining_virtual).min(remaining_in_grain);

        let location = self.grain_location(self.pos)?;
        let n = match location {
            GrainLookup::Sparse => {
                buf[..to_read].fill(0);
                to_read
            }
            GrainLookup::FileOffset(file_off) => {
                self.inner.seek(SeekFrom::Start(file_off))?;
                self.inner.read(&mut buf[..to_read])?
            }
            GrainLookup::Compressed {
                data_offset,
                data_size,
                offset_in_grain,
            } => self.read_compressed_grain(&mut buf[..to_read], data_offset, data_size, offset_in_grain)?,
        };

        self.pos += n as u64;
        Ok(n)
    }
}

impl<R: Read + Seek> Seek for VmdkReader<R> {
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
    use std::io::Cursor;
    use testutil::{
        compressed_vmdk_with_oversized_marker, gd_at_end_stream_opt_vmdk, test_sparse_vmdk,
        GRAIN_SIZE_BYTES,
    };

    fn vmdk_header_bytes(capacity_sectors: u64, grain_size: u64, num_gtes_per_gt: u32) -> Vec<u8> {
        let mut h = vec![0u8; 512];
        h[0..4].copy_from_slice(&0x564D_444B_u32.to_le_bytes());
        h[4..8].copy_from_slice(&1u32.to_le_bytes());
        h[12..20].copy_from_slice(&capacity_sectors.to_le_bytes());
        h[20..28].copy_from_slice(&grain_size.to_le_bytes());
        h[44..48].copy_from_slice(&num_gtes_per_gt.to_le_bytes());
        h
    }

    #[test]
    fn grain_size_zero_rejected() {
        let img = vmdk_header_bytes(8, 0, 512);
        assert!(VmdkReader::open(Cursor::new(img)).is_err());
    }

    #[test]
    fn num_gtes_per_gt_zero_rejected() {
        let img = vmdk_header_bytes(8, 8, 0);
        assert!(VmdkReader::open(Cursor::new(img)).is_err());
    }

    #[test]
    fn open_empty_file_returns_err() {
        assert!(VmdkReader::open(Cursor::new(vec![])).is_err());
    }

    #[test]
    fn open_non_vmdk_file_returns_err() {
        assert!(VmdkReader::open(Cursor::new(b"this is not a vmdk file at all".to_vec())).is_err());
    }

    #[test]
    fn sparse_vmdk_virtual_disk_size() {
        let vmdk = test_sparse_vmdk(&[0u8; 512]);
        let reader = VmdkReader::open(Cursor::new(vmdk)).expect("open");
        assert_eq!(reader.virtual_disk_size(), GRAIN_SIZE_BYTES as u64);
    }

    #[test]
    fn sparse_vmdk_read_returns_sector_data() {
        let mut data = vec![0u8; 512];
        data[42] = 0xDE;
        data[43] = 0xAD;
        let vmdk = test_sparse_vmdk(&data);
        let mut reader = VmdkReader::open(Cursor::new(vmdk)).expect("open");
        let mut buf = vec![0u8; 512];
        reader.read_exact(&mut buf).expect("read");
        assert_eq!(buf[42], 0xDE);
        assert_eq!(buf[43], 0xAD);
    }

    #[test]
    fn seek_and_read_at_offset() {
        let mut data = vec![0u8; GRAIN_SIZE_BYTES];
        data[100] = 0xBE;
        data[101] = 0xEF;
        let vmdk = test_sparse_vmdk(&data);
        let mut reader = VmdkReader::open(Cursor::new(vmdk)).expect("open");
        reader.seek(SeekFrom::Start(100)).expect("seek");
        let mut buf = [0u8; 2];
        reader.read_exact(&mut buf).expect("read");
        assert_eq!(buf, [0xBE, 0xEF]);
    }

    #[test]
    fn vmdk_reader_is_send() {
        fn assert_send<T: Send>() {}
        assert_send::<VmdkReader<Cursor<Vec<u8>>>>();
    }

    #[test]
    fn stream_opt_gd_at_end_opens_correctly() {
        let vmdk = gd_at_end_stream_opt_vmdk();
        let reader = VmdkReader::open(Cursor::new(vmdk))
            .expect("streamOptimized GD_AT_END must open via footer lookup");
        assert_eq!(reader.virtual_disk_size(), 1_048_576);
        assert_eq!(reader.disk_type(), "streamOptimized");
    }

    #[test]
    fn stream_opt_gd_at_end_reads_zeros() {
        let vmdk = gd_at_end_stream_opt_vmdk();
        let mut reader =
            VmdkReader::open(Cursor::new(vmdk)).expect("open GD_AT_END vmdk");
        let mut buf = [0xFFu8; 512];
        reader.read_exact(&mut buf).expect("read sector 0");
        assert_eq!(buf, [0u8; 512]);
    }

    proptest::proptest! {
        #[test]
        fn open_never_panics_on_arbitrary_bytes(
            bytes in proptest::collection::vec(proptest::prelude::any::<u8>(), 0..8192)
        ) {
            let _ = VmdkReader::open(Cursor::new(bytes));
        }

        #[test]
        fn open_never_panics_on_valid_magic_plus_garbage(
            suffix in proptest::collection::vec(proptest::prelude::any::<u8>(), 0..8192)
        ) {
            let mut bytes = vec![0u8; 8];
            bytes[0..4].copy_from_slice(&0x564D_444B_u32.to_le_bytes());
            bytes[4..8].copy_from_slice(&1u32.to_le_bytes());
            bytes.extend_from_slice(&suffix);
            let _ = VmdkReader::open(Cursor::new(bytes));
        }
    }

    // ── Fuzz / malicious-input defence ───────────────────────────────────────

    #[test]
    fn compressed_grain_oversized_data_size_returns_invaliddata() {
        let vmdk = compressed_vmdk_with_oversized_marker(4 * 1024 * 1024);
        let mut reader = VmdkReader::open(Cursor::new(vmdk))
            .expect("VMDK with oversized marker must open — error only on read");
        let mut buf = [0u8; 512];
        let err = reader.read(&mut buf).expect_err("oversized data_size must return Err");
        assert_eq!(
            err.kind(),
            io::ErrorKind::InvalidData,
            "must return InvalidData from cap check, not UnexpectedEof from allocation attempt"
        );
    }

    #[test]
    fn grain_size_below_spec_minimum_is_rejected() {
        let mut hdr = vec![0u8; 512];
        hdr[0..4].copy_from_slice(&0x564D_444B_u32.to_le_bytes());
        hdr[4..8].copy_from_slice(&1u32.to_le_bytes());
        hdr[12..20].copy_from_slice(&128u64.to_le_bytes()); // capacity = 128 sectors
        hdr[20..28].copy_from_slice(&4u64.to_le_bytes()); // grain_size = 4 (below VDF 1.1 minimum of 8)
        hdr[44..48].copy_from_slice(&512u32.to_le_bytes()); // num_gtes_per_gt
        let result = VmdkReader::open(Cursor::new(hdr));
        assert!(
            result.is_err(),
            "grain_size=4 is below VDF 1.1 minimum of 8 sectors; open must return Err"
        );
    }

    proptest::proptest! {
        #[test]
        fn open_never_panics_on_stream_opt_magic_plus_garbage(
            suffix in proptest::collection::vec(proptest::prelude::any::<u8>(), 0..8192)
        ) {
            let mut bytes = vec![0u8; 8];
            bytes[0..4].copy_from_slice(&0x564D_444B_u32.to_le_bytes());
            bytes[4..8].copy_from_slice(&3u32.to_le_bytes()); // version = 3 (streamOptimized path)
            bytes.extend_from_slice(&suffix);
            let _ = VmdkReader::open(Cursor::new(bytes));
        }
    }

    #[test]
    fn reads_match_qemu_raw_convert() {
        use std::fs::File;
        const QEMU_IMG: &str = "/opt/homebrew/bin/qemu-img";
        if !std::path::Path::new(QEMU_IMG).exists() {
            return;
        }
        let tmp = tempfile::tempdir().expect("tempdir");
        let size: usize = 1 << 20;
        let raw_data: Vec<u8> = (0..size).map(|i| (i ^ (i >> 8)) as u8).collect();
        let raw_path = tmp.path().join("source.raw");
        std::fs::write(&raw_path, &raw_data).expect("write raw");
        let vmdk_path = tmp.path().join("test.vmdk");
        let status = std::process::Command::new(QEMU_IMG)
            .args([
                "convert",
                "-O",
                "vmdk",
                raw_path.to_str().expect("UTF-8 path"),
                vmdk_path.to_str().expect("UTF-8 path"),
            ])
            .status()
            .expect("spawn qemu-img");
        assert!(status.success(), "qemu-img convert failed");
        let file = File::open(&vmdk_path).expect("open vmdk file");
        let mut reader = VmdkReader::open(file).expect("open");
        assert_eq!(reader.virtual_disk_size(), size as u64);
        let grain = 512 * 128;
        for &offset in &[0usize, 511, grain, grain + 512, size - 512] {
            let len = 512.min(size - offset);
            let mut buf = vec![0u8; len];
            reader.seek(SeekFrom::Start(offset as u64)).expect("seek");
            reader.read_exact(&mut buf).expect("read");
            assert_eq!(
                buf,
                raw_data[offset..offset + len],
                "byte mismatch at {offset:#x}"
            );
        }
    }

    #[test]
    fn corpus_dfvfs_ext2_vmdk_reads_match_qemu_raw_convert() {
        use std::fs::File;
        const QEMU_IMG: &str = "/opt/homebrew/bin/qemu-img";
        if !std::path::Path::new(QEMU_IMG).exists() {
            return;
        }
        let corpus =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/data/dfvfs_ext2.vmdk");
        if !corpus.exists() {
            return;
        }
        let tmp = tempfile::tempdir().expect("tempdir");
        let raw_path = tmp.path().join("ext2.raw");
        let ok = std::process::Command::new(QEMU_IMG)
            .args([
                "convert",
                "-O",
                "raw",
                corpus.to_str().expect("UTF-8 path"),
                raw_path.to_str().expect("UTF-8 path"),
            ])
            .status()
            .expect("spawn qemu-img")
            .success();
        assert!(ok, "qemu-img convert failed for dfvfs_ext2.vmdk");
        let ref_data = std::fs::read(&raw_path).expect("read reference raw");
        let file = File::open(&corpus).expect("open dfvfs_ext2.vmdk");
        let mut reader = VmdkReader::open(file).expect("open");
        assert_eq!(
            reader.virtual_disk_size(),
            ref_data.len() as u64,
            "virtual_disk_size must match qemu-img raw for dfvfs_ext2.vmdk"
        );
        let vsize = ref_data.len();
        let step = 4096usize;
        let mut offset = 0usize;
        while offset < vsize {
            let len = 512.min(vsize - offset);
            let mut buf = vec![0u8; len];
            reader.seek(SeekFrom::Start(offset as u64)).expect("seek");
            reader.read_exact(&mut buf).expect("read");
            assert_eq!(
                buf,
                ref_data[offset..offset + len],
                "byte mismatch at {offset:#x} in dfvfs_ext2.vmdk"
            );
            offset += step;
        }
    }

    #[test]
    fn corpus_minimal_vmdk_reads_match_qemu_raw_convert() {
        use std::fs::File;
        const QEMU_IMG: &str = "/opt/homebrew/bin/qemu-img";
        if !std::path::Path::new(QEMU_IMG).exists() {
            return;
        }
        let corpus =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/data/minimal.vmdk");
        if !corpus.exists() {
            return;
        }
        let tmp = tempfile::tempdir().expect("tempdir");
        let raw_path = tmp.path().join("minimal.raw");
        let ok = std::process::Command::new(QEMU_IMG)
            .args([
                "convert",
                "-O",
                "raw",
                corpus.to_str().expect("UTF-8 path"),
                raw_path.to_str().expect("UTF-8 path"),
            ])
            .status()
            .expect("spawn qemu-img")
            .success();
        assert!(ok, "qemu-img convert failed");
        let ref_data = std::fs::read(&raw_path).expect("read raw");
        let file = File::open(&corpus).expect("open corpus vmdk");
        let mut reader = VmdkReader::open(file).expect("open");
        assert_eq!(reader.virtual_disk_size(), ref_data.len() as u64);
        let vsize = ref_data.len();
        let grain = 65536usize;
        for &offset in &[0usize, 511, grain, grain + 512, vsize - 512] {
            let len = 512.min(vsize - offset);
            let mut buf = vec![0u8; len];
            reader.seek(SeekFrom::Start(offset as u64)).expect("seek");
            reader.read_exact(&mut buf).expect("read");
            assert_eq!(
                buf,
                ref_data[offset..offset + len],
                "byte mismatch at {offset:#x}"
            );
        }
    }
}
