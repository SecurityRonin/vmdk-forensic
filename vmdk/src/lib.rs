//! Pure-Rust read-only VMDK disk image reader.
//!
//! Supports monolithic sparse (`monolithicSparse`), stream-optimised
//! (`streamOptimized`, including allocated compressed grains), flat-extent
//! VMDKs (`twoGbMaxExtentFlat`, `monolithicFlat`), and multi-file sparse
//! extents (`twoGbMaxExtentSparse`).

use std::collections::HashMap;
use std::fs::File;
use std::io::{self, BufReader, Read, Seek, SeekFrom};
use std::path::Path;

mod chain;
mod cowd;
mod descriptor;
pub(crate) mod error;
mod flat;
mod header;
mod sesparse;
mod sparse_multi;

pub use chain::VmdkChainReader;

pub use error::VmdkError;

use descriptor::parse_text_descriptor;
use flat::MultiExtentReader;
use header::{SparseExtentHeader, GD_AT_END, SECTOR_SIZE};
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

/// SHA-256 and MD5 hash of the full virtual disk contents.
///
/// Produced by [`VmdkReader::hash`]. Both digests are computed in a single
/// sequential pass over the virtual disk.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct VmdkDigest {
    /// SHA-256 digest (32 bytes), hex-encoded.
    pub sha256: String,
    /// MD5 digest (16 bytes), hex-encoded.
    pub md5: String,
}

/// A contiguous range of allocated (non-sparse) sectors in a VMDK virtual disk.
///
/// Returned by [`VmdkReader::iter_allocated_grains`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct AllocatedGrain {
    /// First LBA (512-byte sector number) of this allocated range.
    pub start_lba: u64,
    /// Number of sectors in this range (always a multiple of `grain_size_sectors`).
    pub sector_count: u64,
}

/// Structured metadata for a VMDK virtual disk.
///
/// Returned by [`VmdkReader::info`].  All fields are `Clone`-able so callers
/// can store or serialise the snapshot independently of the reader.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct VmdkInfo {
    /// `createType` from the embedded descriptor (e.g. `"monolithicSparse"`).
    pub disk_type: String,
    /// Header format version: 1 for `monolithicSparse`; 3 for `streamOptimized`; 0 for flat.
    pub version: u32,
    /// Content ID (CID) from the descriptor, or `0xffff_ffff` if absent.
    pub cid: u32,
    /// Parent content ID; `0xffff_ffff` means no parent (not a delta/snapshot).
    pub parent_cid: u32,
    /// Grain size in sectors (0 for flat/raw extents).
    pub grain_size_sectors: u64,
    /// Grain size in bytes (0 for flat/raw extents).
    pub grain_size_bytes: u64,
    /// Total virtual disk size in bytes.
    pub virtual_disk_size: u64,
    /// Total virtual disk size in 512-byte sectors.
    pub sector_count: u64,
    /// `true` for `streamOptimized` VMDKs whose allocated grains are zlib-compressed.
    pub compressed: bool,
    /// Raw embedded descriptor text; empty when no embedded descriptor is present.
    pub descriptor_text: String,
}

// ── Internal format dispatch ──────────────────────────────────────────────────

enum FormatState {
    Sparse {
        grain_dir: Vec<u32>,
        grain_size_bytes: u64,
        num_gtes_per_gt: u64,
        /// `true` for stream-optimised VMDKs: allocated grains carry a zlib-wrapped payload.
        compressed: bool,
    },
    /// seSparse (vSphere 6.5+, VMFS6): nibble-typed, bit-rotated 8-byte grain entries.
    SeSparse {
        /// Raw L1 (grain directory) entries — high nibble 0x1 = allocated, low 32 bits = GT index.
        grain_dir: Vec<u64>,
        grain_size_bytes: u64,
        /// First sector of the grain-table region (`grain_tables_offset`).
        gt_offset_sectors: u64,
        /// First sector of the grain-data region (`grains_offset`).
        grains_offset_sectors: u64,
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
    version: u32,
    cid: u32,
    parent_cid: u32,
    descriptor_text: Box<str>,
    /// RGD (redundant grain directory) sector offset; 0 when absent.
    rgd_offset: u64,
    /// Number of GD entries — stored for RGD validation without re-deriving.
    gd_entry_count: usize,
    /// Cache of grain tables: maps GT sector number → Vec of GTE values.
    /// Avoids redundant seeks for repeated grain reads within the same GT.
    gt_cache: HashMap<u32, Vec<u32>>,
}

/// Maximum bytes read from an embedded descriptor (guards against crafted images).
const MAX_DESCRIPTOR_BYTES: u64 = 64 * 1024;

/// Read the embedded text descriptor from a binary VMDK and parse it.
///
/// Returns a `TextDescriptor` with all metadata fields populated.
/// When no embedded descriptor is present (`descriptor_offset=0` or `descriptor_size=0`),
/// returns a descriptor with empty `create_type` and sentinel values for CID fields.
fn read_descriptor<R: Read + Seek>(
    reader: &mut R,
    hdr: &SparseExtentHeader,
) -> io::Result<descriptor::TextDescriptor> {
    if hdr.descriptor_offset == 0 || hdr.descriptor_size == 0 {
        return descriptor::parse_text_descriptor("")
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()));
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

    let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    let text = std::str::from_utf8(&buf[..end]).unwrap_or("").to_owned();
    descriptor::parse_text_descriptor(&text)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))
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

        // Detect COWD magic ("COWD", big-endian) before attempting VMDK4 parse.
        let magic_be = u32::from_be_bytes(hdr_bytes[0..4].try_into().expect("4 bytes"));
        if magic_be == cowd::COWD_MAGIC {
            return Self::open_cowd(reader, &hdr_bytes);
        }
        // Detect seSparse magic (0x0000_0000_CAFE_BABE, u64 little-endian at offset 0).
        if hdr_bytes.len() >= 8 {
            let se_magic = u64::from_le_bytes(hdr_bytes[0..8].try_into().expect("8 bytes"));
            if se_magic == sesparse::SE_CONST_MAGIC {
                return Self::open_sesparse(reader, &hdr_bytes);
            }
        }

        let hdr = SparseExtentHeader::parse(&hdr_bytes)?;

        let grain_size_bytes = hdr
            .grain_size
            .checked_mul(SECTOR_SIZE)
            .ok_or_else(|| VmdkError::InvalidGeometry("grain_size overflow".into()))?;
        let virtual_disk_size = hdr
            .capacity
            .checked_mul(SECTOR_SIZE)
            .ok_or_else(|| VmdkError::InvalidGeometry("capacity overflow".into()))?;

        let desc = read_descriptor(&mut reader, &hdr)?;

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
            disk_type: desc.create_type,
            pos: 0,
            version: hdr.version,
            cid: desc.cid,
            parent_cid: desc.parent_cid,
            descriptor_text: desc.raw_text,
            rgd_offset: hdr.rgd_offset,
            gd_entry_count: num_gts as usize,
            gt_cache: HashMap::new(),
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

    /// Validate the redundant grain directory (RGD) against the primary GD.
    ///
    /// Returns `Ok(true)` if both directories are present and identical,
    /// `Ok(false)` if the RGD is absent or mismatches (indicating corruption),
    /// and `Err(_)` on I/O failure.
    ///
    /// For flat and COWD/seSparse formats (which have no RGD) this always returns `Ok(false)`.
    pub fn validate_rgd(&mut self) -> io::Result<bool> {
        let (primary_gd, rgd_offset, gd_entry_count) = match &self.fmt {
            FormatState::Sparse { grain_dir, .. } => {
                (grain_dir.clone(), self.rgd_offset, self.gd_entry_count)
            }
            _ => return Ok(false), // Flat/seSparse/COWD have no RGD
        };
        if rgd_offset == 0 || rgd_offset == crate::header::GD_AT_END {
            return Ok(false);
        }
        let rgd_byte_offset = rgd_offset
            .checked_mul(SECTOR_SIZE)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "rgd_offset overflow"))?;
        self.inner.seek(SeekFrom::Start(rgd_byte_offset))?;
        let mut rgd_bytes = vec![0u8; gd_entry_count * 4];
        self.inner.read_exact(&mut rgd_bytes)?;
        let rgd: Vec<u32> = rgd_bytes
            .chunks_exact(4)
            .map(|c| u32::from_le_bytes(c.try_into().expect("4 bytes")))
            .collect();
        Ok(primary_gd == rgd)
    }

    /// CID from the embedded descriptor; `0xffff_ffff` when absent.
    pub fn cid(&self) -> u32 {
        self.cid
    }

    /// Parent CID; `0xffff_ffff` means this is a base image (no parent).
    pub fn parent_cid(&self) -> u32 {
        self.parent_cid
    }

    /// Virtual disk size in 512-byte sectors.
    pub fn sector_count(&self) -> u64 {
        self.virtual_disk_size / SECTOR_SIZE
    }

    /// Raw embedded descriptor text; empty when no embedded descriptor is present.
    pub fn descriptor_text(&self) -> &str {
        &self.descriptor_text
    }

    /// Structured snapshot of all metadata for this image.
    pub fn info(&self) -> VmdkInfo {
        let (grain_size_sectors, grain_size_bytes, compressed) = match &self.fmt {
            FormatState::Sparse {
                grain_size_bytes,
                compressed,
                ..
            } => (
                *grain_size_bytes / SECTOR_SIZE,
                *grain_size_bytes,
                *compressed,
            ),
            FormatState::SeSparse {
                grain_size_bytes, ..
            } => (*grain_size_bytes / SECTOR_SIZE, *grain_size_bytes, false),
            FormatState::Flat => (0, 0, false),
        };
        VmdkInfo {
            disk_type: self.disk_type.to_string(),
            version: self.version,
            cid: self.cid,
            parent_cid: self.parent_cid,
            grain_size_sectors,
            grain_size_bytes,
            virtual_disk_size: self.virtual_disk_size,
            sector_count: self.virtual_disk_size / SECTOR_SIZE,
            compressed,
            descriptor_text: self.descriptor_text.to_string(),
        }
    }

    /// Open a seSparse extent file (vSphere 6.5+ VMFS6 snapshots).
    ///
    /// Called from `open()` when seSparse constant-header magic is detected.
    fn open_sesparse(mut reader: R, hdr_bytes: &[u8]) -> Result<Self, VmdkError> {
        use sesparse::open_sesparse;
        reader.seek(SeekFrom::Start(0))?;
        let (grain_dir, grain_size_bytes, grains_offset_sectors) = open_sesparse(&mut reader)?;

        let se_hdr = sesparse::SeConstHeader::parse(hdr_bytes)?;
        let virtual_disk_size = se_hdr
            .capacity
            .checked_mul(SECTOR_SIZE)
            .ok_or_else(|| VmdkError::InvalidGeometry("seSparse capacity overflow".into()))?;

        Ok(VmdkReader {
            inner: reader,
            fmt: FormatState::SeSparse {
                grain_dir,
                grain_size_bytes,
                gt_offset_sectors: se_hdr.gt_offset,
                grains_offset_sectors,
            },
            virtual_disk_size,
            disk_type: Box::from("seSparse"),
            pos: 0,
            version: 0,
            cid: 0xffff_ffff,
            parent_cid: 0xffff_ffff,
            descriptor_text: Box::from(""),
            rgd_offset: 0,
            gd_entry_count: 0,
            gt_cache: HashMap::new(),
        })
    }

    /// Open a COWD extent file (vmfsSparse / vmfsThin).
    ///
    /// Called from `open()` when COWD magic is detected.
    fn open_cowd(mut reader: R, hdr_bytes: &[u8]) -> Result<Self, VmdkError> {
        use cowd::{open_cowd, COWD_GTES_PER_GT};

        // Reader is positioned after the 512-byte header; seek back to start so
        // open_cowd() can re-read the header for its own parsing.
        reader.seek(SeekFrom::Start(0))?;
        let (grain_dir, grain_size_bytes) = open_cowd(&mut reader)?;

        // COWD capacity is 32-bit sectors; derive virtual_disk_size.
        let cowd_hdr = cowd::CowdHeader::parse(hdr_bytes)?;
        let virtual_disk_size = u64::from(cowd_hdr.capacity)
            .checked_mul(SECTOR_SIZE)
            .ok_or_else(|| VmdkError::InvalidGeometry("COWD capacity overflow".into()))?;

        Ok(VmdkReader {
            inner: reader,
            fmt: FormatState::Sparse {
                grain_dir,
                grain_size_bytes,
                num_gtes_per_gt: COWD_GTES_PER_GT as u64,
                compressed: false,
            },
            virtual_disk_size,
            disk_type: Box::from("vmfsSparse"),
            pos: 0,
            version: 1,
            cid: 0xffff_ffff,
            parent_cid: 0xffff_ffff,
            descriptor_text: Box::from(""),
            rgd_offset: 0,
            gd_entry_count: 0,
            gt_cache: HashMap::new(),
        })
    }

    /// Returns `true` if the 512-byte sector at `lba` is allocated (non-sparse).
    ///
    /// An `lba` beyond the virtual disk boundary always returns `false`.
    /// For flat/raw-extent VMDKs every sector is implicitly allocated; returns `true` for
    /// any in-bounds LBA.
    pub fn is_allocated(&mut self, lba: u64) -> io::Result<bool> {
        if lba >= self.virtual_disk_size / SECTOR_SIZE {
            return Ok(false);
        }
        // Extract all values from self.fmt before any mutable borrow of self.inner.
        let virtual_offset = lba * SECTOR_SIZE;
        match &self.fmt {
            FormatState::Flat => return Ok(true),
            FormatState::Sparse {
                grain_dir,
                grain_size_bytes,
                num_gtes_per_gt,
                ..
            } => {
                let grain_idx = virtual_offset / grain_size_bytes;
                let gd_idx = (grain_idx / num_gtes_per_gt) as usize;
                let gte_idx = grain_idx % num_gtes_per_gt;
                let gt_sector = grain_dir.get(gd_idx).copied().unwrap_or(0);
                let _ = ();
                if gt_sector == 0 {
                    return Ok(false);
                }
                let gte_pos = u64::from(gt_sector) * SECTOR_SIZE + gte_idx * 4;
                self.inner.seek(SeekFrom::Start(gte_pos))?;
                let mut b = [0u8; 4];
                self.inner.read_exact(&mut b)?;
                return Ok(u32::from_le_bytes(b) > 1);
            }
            FormatState::SeSparse {
                grain_dir,
                grain_size_bytes,
                gt_offset_sectors,
                ..
            } => {
                let gd_entry = {
                    let grain_idx = virtual_offset / grain_size_bytes;
                    let gd_idx = (grain_idx / sesparse::SE_GTES_PER_GT) as usize;
                    grain_dir.get(gd_idx).copied().unwrap_or(0)
                };
                let grain_idx = virtual_offset / grain_size_bytes;
                let gte_idx = grain_idx % sesparse::SE_GTES_PER_GT;
                let gt_off = *gt_offset_sectors;
                let Some(gte) = self.se_read_gte(gd_entry, gt_off, gte_idx)? else {
                    return Ok(false);
                };
                // Allocated only when the GTE type nibble is "allocated" (0x3).
                return Ok(gte & sesparse::SE_GTE_TYPE_MASK == sesparse::SE_GTE_TYPE_ALLOCATED);
            }
        }
    }

    /// Read a seSparse L2 (grain-table) entry given its L1 (GD) entry.
    ///
    /// Returns `Ok(None)` if the GD entry is unallocated, `Ok(Some(gte))` otherwise.
    /// Validates the GD allocated-marker nibble per the seSparse encoding.
    fn se_read_gte(
        &mut self,
        gd_entry: u64,
        gt_offset_sectors: u64,
        gte_idx: u64,
    ) -> io::Result<Option<u64>> {
        if gd_entry == 0 {
            return Ok(None);
        }
        if gd_entry & sesparse::SE_GD_ALLOC_MASK != sesparse::SE_GD_ALLOC_FLAG {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "seSparse GD entry has invalid allocated marker",
            ));
        }
        let gt_table_idx = gd_entry & sesparse::SE_GD_INDEX_MASK;
        let gt_sector = gt_offset_sectors + gt_table_idx * sesparse::SE_GT_SECTORS;
        let gte_pos = gt_sector * SECTOR_SIZE + gte_idx * 8;
        self.inner.seek(SeekFrom::Start(gte_pos))?;
        let mut b = [0u8; 8];
        self.inner.read_exact(&mut b)?;
        Ok(Some(u64::from_le_bytes(b)))
    }

    /// Iterate over all allocated (non-sparse) grain ranges in LBA order.
    ///
    /// Each yielded [`AllocatedGrain`] covers exactly one grain; contiguous allocated
    /// grains are not coalesced so the caller can apply its own merging if desired.
    /// The iterator is eager — it collects all GTE reads upfront to avoid borrow issues.
    pub fn iter_allocated_grains(&mut self) -> io::Result<Vec<AllocatedGrain>> {
        let (grain_dir, grain_size_bytes, num_gtes_per_gt) = match &self.fmt {
            FormatState::Flat => {
                // All sectors allocated; yield the entire virtual disk as one grain.
                let sector_count = self.virtual_disk_size / SECTOR_SIZE;
                return Ok(if sector_count == 0 {
                    vec![]
                } else {
                    vec![AllocatedGrain {
                        start_lba: 0,
                        sector_count,
                    }]
                });
            }
            FormatState::Sparse {
                grain_dir,
                grain_size_bytes,
                num_gtes_per_gt,
                ..
            } => (grain_dir.clone(), *grain_size_bytes, *num_gtes_per_gt),
            FormatState::SeSparse {
                grain_dir,
                grain_size_bytes,
                gt_offset_sectors,
                ..
            } => {
                let (gd, gsz, goff) = (grain_dir.clone(), *grain_size_bytes, *gt_offset_sectors);
                let grain_sectors = gsz / SECTOR_SIZE;
                let max_lba = self.virtual_disk_size / SECTOR_SIZE;
                let mut result = Vec::new();
                for (gd_idx, &gd_entry) in gd.iter().enumerate() {
                    // Skip unallocated GD slots; require the allocated-marker nibble.
                    if gd_entry == 0 {
                        continue;
                    }
                    if gd_entry & sesparse::SE_GD_ALLOC_MASK != sesparse::SE_GD_ALLOC_FLAG {
                        continue; // malformed GD entry — skip rather than abort the scan
                    }
                    let gt_table_idx = gd_entry & sesparse::SE_GD_INDEX_MASK;
                    let gt_sector = goff + gt_table_idx * sesparse::SE_GT_SECTORS;
                    let gt_bytes_len = sesparse::SE_GTES_PER_GT as usize * 8;
                    self.inner.seek(SeekFrom::Start(gt_sector * SECTOR_SIZE))?;
                    let mut gt_bytes = vec![0u8; gt_bytes_len];
                    self.inner.read_exact(&mut gt_bytes)?;
                    for gte_idx in 0..sesparse::SE_GTES_PER_GT as usize {
                        let gte = u64::from_le_bytes(
                            gt_bytes[gte_idx * 8..gte_idx * 8 + 8]
                                .try_into()
                                .expect("8 bytes"),
                        );
                        // Only "allocated" (0x3) grains hold real data; zero/unmapped are sparse.
                        if gte & sesparse::SE_GTE_TYPE_MASK == sesparse::SE_GTE_TYPE_ALLOCATED {
                            let grain_idx =
                                gd_idx as u64 * sesparse::SE_GTES_PER_GT + gte_idx as u64;
                            let start_lba = grain_idx * grain_sectors;
                            if start_lba < max_lba {
                                result.push(AllocatedGrain {
                                    start_lba,
                                    sector_count: grain_sectors,
                                });
                            }
                        }
                    }
                }
                return Ok(result);
            }
        };
        let grain_sectors = grain_size_bytes / SECTOR_SIZE;
        let mut result = Vec::new();

        for (gd_idx, &gt_sector) in grain_dir.iter().enumerate() {
            if gt_sector == 0 {
                continue;
            }
            let gt_byte_offset = u64::from(gt_sector) * SECTOR_SIZE;
            let gt_size = num_gtes_per_gt as usize * 4;
            self.inner.seek(SeekFrom::Start(gt_byte_offset))?;
            let mut gt_bytes = vec![0u8; gt_size];
            self.inner.read_exact(&mut gt_bytes)?;

            for gte_idx in 0..num_gtes_per_gt as usize {
                let gte = u32::from_le_bytes(
                    gt_bytes[gte_idx * 4..gte_idx * 4 + 4]
                        .try_into()
                        .expect("4 bytes"),
                );
                if gte > 1 {
                    let grain_idx = gd_idx as u64 * num_gtes_per_gt + gte_idx as u64;
                    let start_lba = grain_idx * grain_sectors;
                    if start_lba < self.virtual_disk_size / SECTOR_SIZE {
                        result.push(AllocatedGrain {
                            start_lba,
                            sector_count: grain_sectors,
                        });
                    }
                }
            }
        }
        Ok(result)
    }

    /// Compute SHA-256 and MD5 digests of the full virtual disk in one sequential pass.
    ///
    /// Reads from the current seek position (normally the caller should seek to 0 first).
    /// Uses a 64 KiB streaming buffer to avoid loading the whole disk into memory.
    pub fn hash(&mut self) -> io::Result<VmdkDigest> {
        use md5::Md5;
        use sha2::{Digest as _, Sha256};

        let mut sha = Sha256::new();
        let mut md = Md5::new();
        let mut buf = vec![0u8; 65536];
        loop {
            let n = self.read(&mut buf)?;
            if n == 0 {
                break;
            }
            sha.update(&buf[..n]);
            md.update(&buf[..n]);
        }
        let sha_bytes = sha.finalize();
        let md_bytes = md.finalize();
        Ok(VmdkDigest {
            sha256: sha_bytes
                .iter()
                .fold(String::with_capacity(64), |mut s, b| {
                    use std::fmt::Write as _;
                    let _ = write!(s, "{b:02x}");
                    s
                }),
            md5: md_bytes.iter().fold(String::with_capacity(32), |mut s, b| {
                use std::fmt::Write as _;
                let _ = write!(s, "{b:02x}");
                s
            }),
        })
    }

    /// Number of grain tables currently held in the GT cache.
    ///
    /// Exposed for testing; not part of the stable public API.
    #[doc(hidden)]
    pub fn gt_cache_size(&self) -> usize {
        self.gt_cache.len()
    }

    /// Resolve `virtual_offset` to a [`GrainLookup`] describing where to find the data.
    fn grain_location(&mut self, virtual_offset: u64) -> io::Result<GrainLookup> {
        // Dispatch seSparse separately: nibble-typed, bit-rotated 8-byte grain entries.
        if let FormatState::SeSparse {
            grain_dir,
            grain_size_bytes,
            gt_offset_sectors,
            grains_offset_sectors,
        } = &self.fmt
        {
            let grain_size_bytes = *grain_size_bytes;
            let grain_sectors = grain_size_bytes / SECTOR_SIZE;
            let grains_offset = *grains_offset_sectors;
            let gt_off = *gt_offset_sectors;
            let grain_idx = virtual_offset / grain_size_bytes;
            let offset_in_grain = virtual_offset % grain_size_bytes;
            let gd_idx = (grain_idx / sesparse::SE_GTES_PER_GT) as usize;
            let gte_idx = grain_idx % sesparse::SE_GTES_PER_GT;
            let gd_entry = grain_dir.get(gd_idx).copied().unwrap_or(0);

            let Some(gte) = self.se_read_gte(gd_entry, gt_off, gte_idx)? else {
                return Ok(GrainLookup::Sparse);
            };
            return match gte & sesparse::SE_GTE_TYPE_MASK {
                // Unallocated: the whole entry must be zero (already handled by se_read_gte
                // for the GD level; a zero GTE here means a sparse grain within an allocated GT).
                0 if gte == 0 => Ok(GrainLookup::Sparse),
                sesparse::SE_GTE_TYPE_UNMAPPED | sesparse::SE_GTE_TYPE_ZERO => {
                    Ok(GrainLookup::Sparse)
                }
                sesparse::SE_GTE_TYPE_ALLOCATED => {
                    let grain_index = sesparse::se_gte_grain_index(gte);
                    let cluster_sector = grains_offset + grain_index * grain_sectors;
                    Ok(GrainLookup::FileOffset(
                        cluster_sector * SECTOR_SIZE + offset_in_grain,
                    ))
                }
                _ => Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "seSparse grain entry has unsupported type nibble",
                )),
            };
        }

        let (gt_sector, gte_idx, offset_in_grain, compressed, grain_size_bytes) = {
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
            (
                gt_sector,
                gte_idx,
                offset_in_grain,
                *compressed,
                *grain_size_bytes,
            )
        };
        if gt_sector == 0 {
            return Ok(GrainLookup::Sparse);
        }
        // Use cached GT if available; otherwise read from file and cache it.
        let gte = if let Some(gt) = self.gt_cache.get(&gt_sector) {
            gt.get(gte_idx as usize).copied().unwrap_or(0)
        } else {
            // Read the full GT (num_gtes_per_gt entries × 4 bytes) into the cache.
            let gt_byte_offset = u64::from(gt_sector) * SECTOR_SIZE;
            self.inner.seek(SeekFrom::Start(gt_byte_offset))?;
            let gt_size = {
                let FormatState::Sparse {
                    num_gtes_per_gt, ..
                } = &self.fmt
                else {
                    unreachable!()
                };
                *num_gtes_per_gt as usize * 4
            };
            let mut gt_bytes = vec![0u8; gt_size];
            self.inner.read_exact(&mut gt_bytes)?;
            let gt: Vec<u32> = gt_bytes
                .chunks_exact(4)
                .map(|c| u32::from_le_bytes(c.try_into().expect("4 bytes")))
                .collect();
            let gte = gt.get(gte_idx as usize).copied().unwrap_or(0);
            self.gt_cache.insert(gt_sector, gt);
            gte
        };
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
            // Cap data_size to prevent allocation amplification from crafted markers.
            // A legitimate compressed grain cannot expand to more than 64 KiB past the
            // raw grain size; 65536 bytes of headroom absorbs any real compressor overhead.
            let max_data = grain_size_bytes.saturating_add(65536);
            if u64::from(data_size) > max_data {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "compressed grain data_size {data_size} exceeds limit {max_data}: \
                         likely a crafted or corrupt VMDK"
                    ),
                ));
            }
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
                // Flat / device-passthrough formats — FLAT/VMFS/VMFSRAW/ZERO extents read
                // as raw bytes. Device maps (fullDevice/partitionedDevice/vmfsRaw/RDM)
                // reference a device path; present paths read, absent ones yield NotFound.
                "vmfs"
                | "vmfsPreallocated"
                | "vmfsEagerZeroedThick"
                | "vmfsRDM"
                | "vmfsRaw"
                | "vmfsRawDeviceMap"
                | "vmfsPassthroughRawDeviceMap"
                | "fullDevice"
                | "partitionedDevice"
                | "twoGbMaxExtentFlat"
                | "monolithicFlat" => {
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
                        version: 0,
                        cid: desc.cid,
                        parent_cid: desc.parent_cid,
                        descriptor_text: desc.raw_text,
                        rgd_offset: 0,
                        gd_entry_count: 0,
                        gt_cache: HashMap::new(),
                    })
                }
                // ESXi sparse formats: SPARSE/VMFSSPARSE extent type — binary VMDK4 or COWD.
                "vmfsSparse" | "vmfsThin" | "twoGbMaxExtentSparse" => {
                    let multi = MultiSparseReader::open(dir, &desc.sparse_extents)?;
                    let virtual_disk_size = desc
                        .sparse_capacity_sectors
                        .checked_mul(SECTOR_SIZE)
                        .ok_or_else(|| {
                        VmdkError::InvalidGeometry("capacity overflow".into())
                    })?;
                    Ok(VmdkReader {
                        inner: Box::new(multi) as Box<dyn ReadSeek + Send>,
                        fmt: FormatState::Flat,
                        virtual_disk_size,
                        disk_type: desc.create_type,
                        pos: 0,
                        version: 0,
                        cid: desc.cid,
                        parent_cid: desc.parent_cid,
                        descriptor_text: desc.raw_text,
                        rgd_offset: 0,
                        gd_entry_count: 0,
                        gt_cache: HashMap::new(),
                    })
                }
                // seSparse: a single binary extent whose CAFEBABE magic selects the reader.
                "seSparse" => {
                    let entry = desc.sparse_extents.first().ok_or_else(|| {
                        VmdkError::InvalidGeometry(
                            "seSparse descriptor has no SESPARSE extent".into(),
                        )
                    })?;
                    let extent_path = dir.join(entry.filename.as_ref());
                    let file = BufReader::new(File::open(&extent_path)?);
                    Ok(VmdkReader::open(file)?.into_file_reader())
                }
                // custom: an arbitrary extent mix — route by which extents are present.
                "custom" => {
                    if !desc.extents.is_empty() {
                        let multi = MultiExtentReader::open(dir, &desc.extents)?;
                        let virtual_disk_size = desc
                            .capacity_sectors
                            .checked_mul(SECTOR_SIZE)
                            .ok_or_else(|| {
                                VmdkError::InvalidGeometry("capacity overflow".into())
                            })?;
                        Ok(VmdkReader {
                            inner: Box::new(multi) as Box<dyn ReadSeek + Send>,
                            fmt: FormatState::Flat,
                            virtual_disk_size,
                            disk_type: desc.create_type,
                            pos: 0,
                            version: 0,
                            cid: desc.cid,
                            parent_cid: desc.parent_cid,
                            descriptor_text: desc.raw_text,
                            rgd_offset: 0,
                            gd_entry_count: 0,
                            gt_cache: HashMap::new(),
                        })
                    } else if !desc.sparse_extents.is_empty() {
                        let multi = MultiSparseReader::open(dir, &desc.sparse_extents)?;
                        let virtual_disk_size = desc
                            .sparse_capacity_sectors
                            .checked_mul(SECTOR_SIZE)
                            .ok_or_else(|| {
                                VmdkError::InvalidGeometry("capacity overflow".into())
                            })?;
                        Ok(VmdkReader {
                            inner: Box::new(multi) as Box<dyn ReadSeek + Send>,
                            fmt: FormatState::Flat,
                            virtual_disk_size,
                            disk_type: desc.create_type,
                            pos: 0,
                            version: 0,
                            cid: desc.cid,
                            parent_cid: desc.parent_cid,
                            descriptor_text: desc.raw_text,
                            rgd_offset: 0,
                            gd_entry_count: 0,
                            gt_cache: HashMap::new(),
                        })
                    } else {
                        Err(VmdkError::InvalidGeometry(
                            "custom descriptor has no recognised extents".into(),
                        ))
                    }
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
            version: self.version,
            cid: self.cid,
            parent_cid: self.parent_cid,
            descriptor_text: self.descriptor_text,
            rgd_offset: self.rgd_offset,
            gd_entry_count: self.gd_entry_count,
            gt_cache: self.gt_cache,
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

        // Sparse / StreamOptimized / SeSparse: clamp at grain boundary then do GTE lookup.
        let grain_size_bytes = match &self.fmt {
            FormatState::Sparse {
                grain_size_bytes, ..
            } => *grain_size_bytes,
            FormatState::SeSparse {
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
            } => self.read_compressed_grain(
                &mut buf[..to_read],
                data_offset,
                data_size,
                offset_in_grain,
            )?,
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
        compressed_vmdk_with_oversized_marker, gd_at_end_stream_opt_vmdk, test_cowd_vmdk,
        test_sesparse_vmdk, test_sparse_vmdk, GRAIN_SIZE_BYTES,
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

    // ── Header version 2 (zeroed-grain feature) + ZERO extent type ───────────

    #[test]
    fn header_version_2_zeroed_grain_opens() {
        // VMware images with the zeroed-grain feature carry version=2 + flag bit 2.
        // QEMU accepts any VMDK4-magic version; we must accept v2 too, not just 1/3.
        let mut vmdk = test_sparse_vmdk(&[0u8; 512]);
        vmdk[4..8].copy_from_slice(&2u32.to_le_bytes()); // version = 2
        vmdk[8..12].copy_from_slice(&0x0000_0004u32.to_le_bytes()); // VMDK4_FLAG_ZERO_GRAIN
        let reader = VmdkReader::open(Cursor::new(vmdk));
        assert!(
            reader.is_ok(),
            "version=2 (zeroed-grain) monolithicSparse must open, got: {:?}",
            reader.err()
        );
    }

    #[test]
    fn zero_extent_type_reads_as_zeros() {
        // A ZERO extent emulates a zero-filled region with NO backing file.
        // `RW <sectors> ZERO` — valid per the VMware descriptor spec.
        use std::io::Write as _;
        let dir = tempfile::tempdir().unwrap();
        let desc = "# Disk DescriptorFile\nversion=1\nCID=ffffffff\nparentCID=ffffffff\ncreateType=\"monolithicFlat\"\nRW 2048 ZERO\n";
        let desc_path = dir.path().join("zero.vmdk");
        std::fs::File::create(&desc_path)
            .unwrap()
            .write_all(desc.as_bytes())
            .unwrap();
        let mut reader =
            VmdkFileReader::open_path(&desc_path).expect("descriptor with a ZERO extent must open");
        assert_eq!(
            reader.virtual_disk_size(),
            2048 * 512,
            "ZERO extent contributes its sector count"
        );
        reader.seek(SeekFrom::Start(0)).unwrap();
        let mut buf = [0xFFu8; 512];
        reader.read_exact(&mut buf).expect("read");
        assert_eq!(buf, [0u8; 512], "ZERO extent must read as zeros");
    }

    // ── custom + device-passthrough createTypes ──────────────────────────────

    /// Write a descriptor + a flat extent file containing `byte0` at offset 0,
    /// then assert `open_path` reads it back through `create_type`/`extent_kw`.
    fn assert_flat_create_type_reads(create_type: &str, extent_kw: &str, byte0: u8) {
        use std::io::Write as _;
        let dir = tempfile::tempdir().unwrap();
        let mut extent = vec![0u8; 1024];
        extent[0] = byte0;
        let extent_path = dir.path().join("disk-flat.vmdk");
        std::fs::File::create(&extent_path)
            .unwrap()
            .write_all(&extent)
            .unwrap();
        let offset = if extent_kw == "FLAT" { " 0" } else { "" };
        let desc = format!(
            "# Disk DescriptorFile\nversion=1\nCID=ffffffff\nparentCID=ffffffff\n\
             createType=\"{create_type}\"\nRW 2 {extent_kw} \"disk-flat.vmdk\"{offset}\n"
        );
        let desc_path = dir.path().join("disk.vmdk");
        std::fs::write(&desc_path, desc.as_bytes()).unwrap();
        let mut reader = VmdkFileReader::open_path(&desc_path)
            .unwrap_or_else(|e| panic!("{create_type}/{extent_kw} must open: {e:?}"));
        let mut buf = [0u8; 1];
        reader.read_exact(&mut buf).expect("read");
        assert_eq!(
            buf[0], byte0,
            "{create_type}: must read the referenced extent"
        );
    }

    #[test]
    fn custom_create_type_with_flat_extent_opens() {
        // createType="custom" is an arbitrary extent mix — route by extent composition.
        assert_flat_create_type_reads("custom", "FLAT", 0xC0);
    }

    #[test]
    fn full_device_create_type_routes_to_flat() {
        // fullDevice / partitionedDevice map to a device path via a FLAT extent;
        // when the referenced path is present they read like any flat extent.
        assert_flat_create_type_reads("fullDevice", "FLAT", 0xFD);
        assert_flat_create_type_reads("partitionedDevice", "FLAT", 0xDE);
    }

    #[test]
    fn vmfs_raw_rdm_create_types_route_to_flat() {
        // vmfsRaw / vmfsRawDeviceMap reference a raw LUN via a VMFSRAW/FLAT extent;
        // present-path reads must succeed (offline-absent yields a clear NotFound).
        assert_flat_create_type_reads("vmfsRaw", "VMFSRAW", 0x4A);
        assert_flat_create_type_reads("vmfsRawDeviceMap", "VMFSRAW", 0x4B);
    }

    // ── extent_dependencies (companion-file discovery for evidence collection) ──

    #[test]
    fn extent_dependencies_lists_flat_companion() {
        // A twoGbMaxExtentFlat descriptor must report its companion extent file so a
        // forensic examiner knows what to collect before the disk can be read.
        use std::io::Write as _;
        let dir = tempfile::tempdir().unwrap();
        let desc = "# Disk DescriptorFile\nversion=1\nCID=ffffffff\nparentCID=ffffffff\ncreateType=\"twoGbMaxExtentFlat\"\nRW 2048 FLAT \"disk-f001.vmdk\" 0\n";
        let desc_path = dir.path().join("disk.vmdk");
        std::fs::File::create(&desc_path)
            .unwrap()
            .write_all(desc.as_bytes())
            .unwrap();
        let deps = VmdkFileReader::extent_dependencies(&desc_path).expect("extent_dependencies");
        assert_eq!(deps.len(), 1, "one companion extent");
        assert_eq!(
            deps[0].file_name().unwrap().to_string_lossy(),
            "disk-f001.vmdk"
        );
        // Paths must be resolved relative to the descriptor's directory.
        assert_eq!(deps[0].parent().unwrap(), dir.path());
    }

    #[test]
    fn extent_dependencies_lists_sparse_companions() {
        use std::io::Write as _;
        let dir = tempfile::tempdir().unwrap();
        let desc = "# Disk DescriptorFile\nversion=1\nCID=ffffffff\nparentCID=ffffffff\ncreateType=\"twoGbMaxExtentSparse\"\nRW 4194304 SPARSE \"disk-s001.vmdk\"\nRW 4194304 SPARSE \"disk-s002.vmdk\"\n";
        let desc_path = dir.path().join("disk.vmdk");
        std::fs::File::create(&desc_path)
            .unwrap()
            .write_all(desc.as_bytes())
            .unwrap();
        let deps = VmdkFileReader::extent_dependencies(&desc_path).expect("deps");
        let names: Vec<String> = deps
            .iter()
            .map(|p| p.file_name().unwrap().to_string_lossy().into_owned())
            .collect();
        assert_eq!(names, vec!["disk-s001.vmdk", "disk-s002.vmdk"]);
    }

    #[test]
    fn extent_dependencies_empty_for_self_contained_binary() {
        // A binary single-file VMDK (no text descriptor) is self-contained → no deps.
        use std::io::Write as _;
        let dir = tempfile::tempdir().unwrap();
        let vmdk = test_sparse_vmdk(&[0u8; 512]);
        let path = dir.path().join("mono.vmdk");
        std::fs::File::create(&path).unwrap().write_all(&vmdk).unwrap();
        let deps = VmdkFileReader::extent_dependencies(&path).expect("deps");
        assert!(deps.is_empty(), "self-contained binary VMDK has no companions");
    }

    #[test]
    fn extent_dependencies_excludes_zero_extents() {
        // ZERO extents have no backing file and must not appear as a dependency.
        use std::io::Write as _;
        let dir = tempfile::tempdir().unwrap();
        let desc = "# Disk DescriptorFile\nversion=1\nCID=ffffffff\nparentCID=ffffffff\ncreateType=\"monolithicFlat\"\nRW 2048 ZERO\nRW 2048 FLAT \"real-f001.vmdk\" 0\n";
        let desc_path = dir.path().join("disk.vmdk");
        std::fs::File::create(&desc_path)
            .unwrap()
            .write_all(desc.as_bytes())
            .unwrap();
        let deps = VmdkFileReader::extent_dependencies(&desc_path).expect("deps");
        let names: Vec<String> = deps
            .iter()
            .map(|p| p.file_name().unwrap().to_string_lossy().into_owned())
            .collect();
        assert_eq!(names, vec!["real-f001.vmdk"], "ZERO extent contributes no file");
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
        let mut reader = VmdkReader::open(Cursor::new(vmdk)).expect("open GD_AT_END vmdk");
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

    // ── RGD validation ───────────────────────────────────────────────────────

    #[test]
    fn validate_rgd_returns_true_for_valid_sparse_vmdk() {
        // test_sparse_vmdk builds a VMDK with matching GD and RGD.
        let vmdk = test_sparse_vmdk(&[0u8; 512]);
        let mut reader = VmdkReader::open(Cursor::new(vmdk)).expect("open");
        assert!(
            reader.validate_rgd().expect("validate_rgd"),
            "test_sparse_vmdk must have valid (matching) RGD"
        );
    }

    #[test]
    fn validate_rgd_returns_false_for_flat_format() {
        let vmdk = gd_at_end_stream_opt_vmdk(); // streamOptimized, no RGD
        let mut reader = VmdkReader::open(Cursor::new(vmdk)).expect("open");
        // streamOptimized with GD_AT_END: rgd_offset=0, returns false
        assert!(
            !reader.validate_rgd().expect("validate_rgd flat"),
            "streamOptimized with no RGD must return false"
        );
    }

    // ── VMFS flat / ZERO extent descriptor parsing ───────────────────────────

    #[test]
    fn vmfs_flat_extent_descriptor_opens_via_open_path() {
        // A vmfs descriptor with VMFS extent type (not FLAT) must open.
        // Currently returns Err(UnsupportedDiskType) because VMFS extent type is unrecognised.
        use std::io::Write as _;
        let dir = tempfile::tempdir().unwrap();
        let raw_path = dir.path().join("disk.vmdk");
        std::fs::File::create(&raw_path)
            .unwrap()
            .write_all(&vec![0u8; 512])
            .unwrap();
        let desc = format!(
            "# Disk DescriptorFile\nversion=1\nCID=ffffffff\nparentCID=ffffffff\ncreateType=\"vmfs\"\nRW 1 VMFS \"{}\"\n",
            raw_path.file_name().unwrap().to_string_lossy()
        );
        let desc_path = dir.path().join("disk_desc.vmdk");
        std::fs::write(&desc_path, desc.as_bytes()).unwrap();
        let result = VmdkFileReader::open_path(&desc_path);
        assert!(
            result.is_ok(),
            "vmfs descriptor with VMFS extent must open, got: {:?}",
            result.err()
        );
    }

    #[test]
    fn vmfssparse_extent_descriptor_opens_as_cowd() {
        // vmfsSparse descriptor with VMFSSPARSE extent type referencing a COWD file.
        use std::io::Write as _;
        let dir = tempfile::tempdir().unwrap();
        let cowd_bytes = testutil::test_cowd_vmdk(&[0u8; 512]);
        let cowd_path = dir.path().join("disk-delta.vmdk");
        std::fs::File::create(&cowd_path)
            .unwrap()
            .write_all(&cowd_bytes)
            .unwrap();
        let desc = format!(
            "# Disk DescriptorFile\nversion=1\nCID=ffffffff\nparentCID=ffffffff\ncreateType=\"vmfsSparse\"\nRW 8 VMFSSPARSE \"{}\"\n",
            cowd_path.file_name().unwrap().to_string_lossy()
        );
        let desc_path = dir.path().join("desc.vmdk");
        std::fs::write(&desc_path, desc.as_bytes()).unwrap();
        let result = VmdkFileReader::open_path(&desc_path);
        assert!(
            result.is_ok(),
            "vmfsSparse/VMFSSPARSE descriptor must open, got: {:?}",
            result.err()
        );
    }

    // ── seSparse format (vSphere 6.5+ VMFS6) ─────────────────────────────────

    #[test]
    fn sesparse_vmdk_opens_successfully() {
        let se = test_sesparse_vmdk(&[0u8; 512]);
        let reader = VmdkReader::open(Cursor::new(se));
        assert!(
            reader.is_ok(),
            "seSparse VMDK must open, got: {:?}",
            reader.err()
        );
    }

    #[test]
    fn sesparse_vmdk_disk_type_is_sesparse() {
        let se = test_sesparse_vmdk(&[0u8; 512]);
        let reader = VmdkReader::open(Cursor::new(se)).expect("open");
        assert_eq!(reader.disk_type(), "seSparse");
    }

    // ── qemu-img cross-validation (independent oracle) ───────────────────────
    //
    // COWD and seSparse cannot be generated by qemu-img (ESXi-only write formats),
    // but qemu-img *reads* them. These tests build a synthetic extent + descriptor,
    // then assert that `qemu-img convert -O raw` and our reader produce byte-identical
    // output. This is genuine independent validation: two unrelated parsers agreeing
    // on the same bytes confirms the fixture is format-correct and the reader is right.
    // Skipped automatically when qemu-img is not installed.

    fn qemu_img_available() -> bool {
        std::process::Command::new("qemu-img")
            .arg("--version")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }

    /// Write `extent_bytes` + a descriptor of `create_type`/`extent_kw`, then compare
    /// `qemu-img convert -O raw` against `VmdkReader::open_path` byte-for-byte.
    fn assert_reader_matches_qemu(
        extent_bytes: &[u8],
        create_type: &str,
        extent_kw: &str,
        capacity_sectors: u64,
    ) {
        use std::io::Write as _;
        let dir = tempfile::tempdir().unwrap();
        let extent_path = dir.path().join("disk-extent.vmdk");
        std::fs::File::create(&extent_path)
            .unwrap()
            .write_all(extent_bytes)
            .unwrap();
        let desc = format!(
            "# Disk DescriptorFile\nversion=1\nCID=12345678\nparentCID=ffffffff\n\
             createType=\"{create_type}\"\nRW {capacity_sectors} {extent_kw} \"disk-extent.vmdk\"\n"
        );
        let desc_path = dir.path().join("disk.vmdk");
        std::fs::write(&desc_path, desc.as_bytes()).unwrap();

        // qemu-img reference.
        let qemu_raw = dir.path().join("qemu.raw");
        let status = std::process::Command::new("qemu-img")
            .args(["convert", "-O", "raw"])
            .arg(&desc_path)
            .arg(&qemu_raw)
            .status()
            .expect("run qemu-img convert");
        assert!(
            status.success(),
            "qemu-img convert failed for {create_type}"
        );
        let qemu_bytes = std::fs::read(&qemu_raw).unwrap();

        // Our reader.
        let mut reader = VmdkFileReader::open_path(&desc_path).expect("open_path");
        reader.seek(SeekFrom::Start(0)).unwrap();
        let mut mine = Vec::new();
        reader.read_to_end(&mut mine).unwrap();

        assert_eq!(
            mine.len(),
            qemu_bytes.len(),
            "{create_type}: size mismatch (mine {} vs qemu {})",
            mine.len(),
            qemu_bytes.len()
        );
        assert!(
            mine == qemu_bytes,
            "{create_type}: byte mismatch vs qemu-img — reader disagrees with the independent oracle"
        );
    }

    #[test]
    fn cowd_reader_matches_qemu_img() {
        if !qemu_img_available() {
            eprintln!("skipping: qemu-img not installed");
            return;
        }
        let pattern: Vec<u8> = (0..4096).map(|i| (i % 251) as u8).collect();
        let cowd = test_cowd_vmdk(&pattern);
        assert_reader_matches_qemu(&cowd, "vmfsSparse", "VMFSSPARSE", 8);
    }

    #[test]
    fn sesparse_reader_matches_qemu_img() {
        if !qemu_img_available() {
            eprintln!("skipping: qemu-img not installed");
            return;
        }
        let pattern: Vec<u8> = (0..4096).map(|i| (i % 251) as u8).collect();
        let se = test_sesparse_vmdk(&pattern);
        assert_reader_matches_qemu(&se, "seSparse", "SESPARSE", 8);
    }

    #[test]
    fn sesparse_vmdk_reads_grain_data() {
        let mut data = vec![0u8; 512];
        data[0] = 0x5E;
        data[1] = 0xA5;
        let se = test_sesparse_vmdk(&data);
        let mut reader = VmdkReader::open(Cursor::new(se)).expect("open seSparse");
        let mut buf = [0u8; 512];
        reader.read_exact(&mut buf).expect("read");
        assert_eq!(buf[0], 0x5E);
        assert_eq!(buf[1], 0xA5);
    }

    #[test]
    fn sesparse_extent_descriptor_opens_via_open_path() {
        // seSparse descriptor (createType="seSparse", SESPARSE extent) must route
        // through open_path to the binary extent. This path was a gap until qemu-img
        // cross-validation exposed it (the bare-binary magic path worked, the
        // descriptor path did not).
        use std::io::Write as _;
        let dir = tempfile::tempdir().unwrap();
        let mut data = vec![0u8; 512];
        data[0] = 0x7E;
        let se_bytes = test_sesparse_vmdk(&data);
        let se_path = dir.path().join("disk-sesparse.vmdk");
        std::fs::File::create(&se_path)
            .unwrap()
            .write_all(&se_bytes)
            .unwrap();
        let desc = format!(
            "# Disk DescriptorFile\nversion=1\nCID=abcdef01\nparentCID=ffffffff\ncreateType=\"seSparse\"\nRW 8 SESPARSE \"{}\"\n",
            se_path.file_name().unwrap().to_string_lossy()
        );
        let desc_path = dir.path().join("disk.vmdk");
        std::fs::write(&desc_path, desc.as_bytes()).unwrap();
        let mut reader = VmdkFileReader::open_path(&desc_path)
            .expect("seSparse descriptor must open via open_path");
        assert_eq!(reader.disk_type(), "seSparse");
        let mut buf = [0u8; 1];
        reader.read_exact(&mut buf).expect("read grain 0");
        assert_eq!(
            buf[0], 0x7E,
            "must read seSparse grain data through the descriptor"
        );
    }

    // ── COWD format (vmfsSparse / vmfsThin) ──────────────────────────────────

    #[test]
    fn cowd_vmdk_opens_without_bad_magic_error() {
        let cowd = test_cowd_vmdk(&[0u8; 512]);
        let reader = VmdkReader::open(Cursor::new(cowd));
        assert!(
            reader.is_ok(),
            "COWD VMDK must open successfully, got: {:?}",
            reader.err()
        );
    }

    #[test]
    fn cowd_vmdk_reads_grain_data() {
        let mut data = vec![0u8; 512];
        data[0] = 0xC0;
        data[1] = 0xBE;
        let cowd = test_cowd_vmdk(&data);
        let mut reader = VmdkReader::open(Cursor::new(cowd)).expect("open COWD");
        let mut buf = [0u8; 512];
        reader.read_exact(&mut buf).expect("read");
        assert_eq!(buf[0], 0xC0, "COWD grain data byte 0");
        assert_eq!(buf[1], 0xBE, "COWD grain data byte 1");
    }

    #[test]
    fn cowd_vmdk_virtual_disk_size() {
        let cowd = test_cowd_vmdk(&[0u8; 512]);
        let reader = VmdkReader::open(Cursor::new(cowd)).expect("open");
        // test_cowd_vmdk capacity = grain_size = 8 sectors = 4096 bytes
        assert_eq!(reader.virtual_disk_size(), 8 * 512);
    }

    // ── VmdkHasher ───────────────────────────────────────────────────────────

    #[test]
    fn hash_all_zeros_disk_produces_known_sha256() {
        // All-sparse VMDK reads as all zeros — SHA-256 of 1 MiB of zeros is a known constant.
        use std::io::Cursor;
        let vmdk = gd_at_end_stream_opt_vmdk();
        let mut reader = VmdkReader::open(Cursor::new(vmdk)).expect("open");
        reader.seek(SeekFrom::Start(0)).expect("seek");
        let digest = reader.hash().expect("hash");
        // SHA-256 of 1 MiB (1_048_576) zero bytes (computed independently):
        // echo -n | dd bs=1 count=0 | ... — computed via sha256sum
        assert_eq!(
            digest.sha256, "30e14955ebf1352266dc2ff8067e68104607e750abb9d3b36582b8af909fcb58",
            "SHA-256 of 1 MiB all-zeros"
        );
        assert_eq!(
            digest.md5, "b6d81b360a5672d80c27430f39153e2c",
            "MD5 of 1 MiB all-zeros (matches qemu-img reference)"
        );
    }

    #[test]
    fn hash_produces_hex_strings_of_correct_length() {
        let vmdk = test_sparse_vmdk(&[0u8; 512]);
        let mut reader = VmdkReader::open(Cursor::new(vmdk)).expect("open");
        reader.seek(SeekFrom::Start(0)).expect("seek");
        let digest = reader.hash().expect("hash");
        assert_eq!(digest.sha256.len(), 64, "SHA-256 hex must be 64 chars");
        assert_eq!(digest.md5.len(), 32, "MD5 hex must be 32 chars");
    }

    // ── serde feature ────────────────────────────────────────────────────────

    #[cfg(feature = "serde")]
    #[test]
    fn vmdk_info_serializes_to_json() {
        let vmdk = test_sparse_vmdk(&[0u8; 512]);
        let reader = VmdkReader::open(Cursor::new(vmdk)).expect("open");
        let info = reader.info();
        let json = serde_json::to_string(&info).expect("serialize VmdkInfo to JSON");
        assert!(
            json.contains("\"disk_type\""),
            "JSON must contain disk_type field"
        );
        assert!(
            json.contains("monolithicSparse"),
            "JSON must contain createType value"
        );
        let info2: VmdkInfo = serde_json::from_str(&json).expect("deserialize VmdkInfo from JSON");
        assert_eq!(info2.disk_type, info.disk_type);
        assert_eq!(info2.virtual_disk_size, info.virtual_disk_size);
    }

    #[cfg(feature = "serde")]
    #[test]
    fn allocated_grain_serializes_to_json() {
        let grain = AllocatedGrain {
            start_lba: 128,
            sector_count: 8,
        };
        let json = serde_json::to_string(&grain).expect("serialize AllocatedGrain");
        assert!(json.contains("\"start_lba\""));
        assert!(json.contains("128"));
        let grain2: AllocatedGrain = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(grain2, grain);
    }

    // ── GT cache ─────────────────────────────────────────────────────────────

    #[test]
    fn gt_cache_grows_on_grain_read() {
        let vmdk = test_sparse_vmdk(&[0u8; 512]);
        let mut reader = VmdkReader::open(Cursor::new(vmdk)).expect("open");
        assert_eq!(reader.gt_cache_size(), 0, "cache starts empty");
        let mut buf = [0u8; 512];
        reader.read_exact(&mut buf).expect("read");
        assert_eq!(
            reader.gt_cache_size(),
            1,
            "one GT loaded after first grain read"
        );
    }

    #[test]
    fn gt_cache_no_double_load_on_second_read_same_grain() {
        let vmdk = test_sparse_vmdk(&[0xABu8; 512]);
        let mut reader = VmdkReader::open(Cursor::new(vmdk)).expect("open");
        let mut buf = [0u8; 512];
        reader.read_exact(&mut buf).expect("first read");
        let after_first = reader.gt_cache_size();
        reader.seek(SeekFrom::Start(0)).expect("seek back");
        reader.read_exact(&mut buf).expect("second read");
        assert_eq!(
            reader.gt_cache_size(),
            after_first,
            "cache must not grow on second read of same GT"
        );
        assert_eq!(buf[0], 0xAB, "data must still be correct");
    }

    // ── is_allocated / iter_allocated_grains ─────────────────────────────────

    #[test]
    fn sparse_grain_is_not_allocated() {
        // test_sparse_vmdk has grain 0 allocated (sector data) and all other grains sparse.
        // Sectors beyond grain 0 should report not-allocated.
        let vmdk = test_sparse_vmdk(&[0u8; 512]);
        let mut reader = VmdkReader::open(Cursor::new(vmdk)).expect("open");
        // Grain 0 is allocated (GTE != 0).
        assert!(
            reader.is_allocated(0).expect("is_allocated lba=0"),
            "grain 0 must be allocated"
        );
        // Grain 1 and beyond: GTE == 0 (sparse).
        let grain_sectors = GRAIN_SIZE_BYTES as u64 / 512;
        assert!(
            !reader
                .is_allocated(grain_sectors)
                .expect("is_allocated lba=grain_sectors"),
            "grain 1 must be sparse"
        );
    }

    #[test]
    fn lba_beyond_disk_is_not_allocated() {
        let vmdk = test_sparse_vmdk(&[0u8; 512]);
        let mut reader = VmdkReader::open(Cursor::new(vmdk)).expect("open");
        let beyond = reader.sector_count() + 1;
        assert!(
            !reader
                .is_allocated(beyond)
                .expect("is_allocated beyond end"),
            "LBA beyond virtual disk must be not-allocated"
        );
    }

    #[test]
    fn iter_allocated_grains_yields_grain_zero() {
        let vmdk = test_sparse_vmdk(&[0u8; 512]);
        let mut reader = VmdkReader::open(Cursor::new(vmdk)).expect("open");
        let grains = reader
            .iter_allocated_grains()
            .expect("iter_allocated_grains");
        assert_eq!(grains.len(), 1, "only grain 0 is allocated");
        assert_eq!(grains[0].start_lba, 0);
        assert_eq!(grains[0].sector_count, GRAIN_SIZE_BYTES as u64 / 512);
    }

    #[test]
    fn iter_allocated_grains_all_sparse_returns_empty() {
        let vmdk = gd_at_end_stream_opt_vmdk(); // all-sparse streamOptimized
        let mut reader = VmdkReader::open(Cursor::new(vmdk)).expect("open");
        let grains = reader
            .iter_allocated_grains()
            .expect("iter_allocated_grains");
        assert!(
            grains.is_empty(),
            "all-sparse VMDK must yield no allocated grains"
        );
    }

    // ── VmdkInfo / metadata API ───────────────────────────────────────────────

    #[test]
    fn sector_count_is_virtual_size_over_512() {
        let vmdk = test_sparse_vmdk(&[0u8; 512]);
        let reader = VmdkReader::open(Cursor::new(vmdk)).expect("open");
        assert_eq!(reader.sector_count() * 512, reader.virtual_disk_size());
    }

    #[test]
    fn descriptor_text_contains_create_type() {
        let vmdk = test_sparse_vmdk(&[0u8; 512]);
        let reader = VmdkReader::open(Cursor::new(vmdk)).expect("open");
        let text = reader.descriptor_text();
        assert!(
            text.contains("monolithicSparse"),
            "descriptor_text must contain createType; got: {text:?}"
        );
    }

    #[test]
    fn info_disk_type_matches_disk_type_method() {
        let vmdk = test_sparse_vmdk(&[0u8; 512]);
        let reader = VmdkReader::open(Cursor::new(vmdk)).expect("open");
        let info = reader.info();
        assert_eq!(info.disk_type, reader.disk_type());
    }

    #[test]
    fn info_virtual_disk_size_and_sector_count_consistent() {
        let vmdk = test_sparse_vmdk(&[0u8; 512]);
        let reader = VmdkReader::open(Cursor::new(vmdk)).expect("open");
        let info = reader.info();
        assert_eq!(info.virtual_disk_size, reader.virtual_disk_size());
        assert_eq!(info.sector_count * 512, info.virtual_disk_size);
    }

    #[test]
    fn info_grain_size_bytes_is_sectors_times_512() {
        let vmdk = test_sparse_vmdk(&[0u8; 512]);
        let reader = VmdkReader::open(Cursor::new(vmdk)).expect("open");
        let info = reader.info();
        assert_eq!(info.grain_size_bytes, info.grain_size_sectors * 512);
        assert!(
            info.grain_size_sectors >= 8,
            "grain_size_sectors must meet VDF 1.1 minimum"
        );
    }

    #[test]
    fn info_cid_parsed_from_descriptor() {
        // testutil embeds CID=fffffffe in the descriptor.
        let vmdk = test_sparse_vmdk(&[0u8; 512]);
        let reader = VmdkReader::open(Cursor::new(vmdk)).expect("open");
        let info = reader.info();
        assert_eq!(
            info.cid, 0xffff_fffe,
            "CID must be parsed from embedded descriptor"
        );
        assert_eq!(
            info.parent_cid, 0xffff_ffff,
            "parentCID must be 0xffffffff (no parent) for a base image"
        );
    }

    #[test]
    fn info_version_is_one_for_monolithic_sparse() {
        let vmdk = test_sparse_vmdk(&[0u8; 512]);
        let reader = VmdkReader::open(Cursor::new(vmdk)).expect("open");
        let info = reader.info();
        assert_eq!(info.version, 1);
        assert!(!info.compressed);
    }

    // ── Fuzz / malicious-input defence ───────────────────────────────────────

    #[test]
    fn compressed_grain_oversized_data_size_returns_invaliddata() {
        let vmdk = compressed_vmdk_with_oversized_marker(4 * 1024 * 1024);
        let mut reader = VmdkReader::open(Cursor::new(vmdk))
            .expect("VMDK with oversized marker must open — error only on read");
        let mut buf = [0u8; 512];
        let err = reader
            .read(&mut buf)
            .expect_err("oversized data_size must return Err");
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
