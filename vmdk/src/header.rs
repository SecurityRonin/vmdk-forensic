//! Sparse extent header (VMware Virtual Disk Format 1.1, §4.1).

use crate::error::{Result, VmdkError};

pub const MAGIC: u32 = 0x564D_444B;
pub const VERSION: u32 = 1;
pub const SECTOR_SIZE: u64 = 512;

/// Parsed fields from the 512-byte SparseExtentHeader.
pub struct SparseExtentHeader {
    pub capacity: u64,            // virtual disk size in sectors
    pub grain_size: u64,          // grain size in sectors
    pub descriptor_offset: u64,   // in sectors
    pub descriptor_size: u64,     // in sectors
    pub num_gtes_per_gt: u32,
    pub gd_offset: u64,           // grain directory offset in sectors
}

impl SparseExtentHeader {
    pub fn parse(data: &[u8]) -> Result<Self> {
        if data.len() < 512 {
            return Err(VmdkError::FileTooSmall);
        }

        let magic = u32::from_le_bytes(data[0..4].try_into().expect("4 bytes"));
        if magic != MAGIC {
            return Err(VmdkError::BadMagic);
        }

        let version = u32::from_le_bytes(data[4..8].try_into().expect("4 bytes"));
        if version != VERSION {
            return Err(VmdkError::UnsupportedVersion(version));
        }

        let capacity = u64::from_le_bytes(data[12..20].try_into().expect("8 bytes"));
        let grain_size = u64::from_le_bytes(data[20..28].try_into().expect("8 bytes"));
        let descriptor_offset = u64::from_le_bytes(data[28..36].try_into().expect("8 bytes"));
        let descriptor_size = u64::from_le_bytes(data[36..44].try_into().expect("8 bytes"));
        let num_gtes_per_gt = u32::from_le_bytes(data[44..48].try_into().expect("4 bytes"));
        let gd_offset = u64::from_le_bytes(data[56..64].try_into().expect("8 bytes"));
        let compress_algorithm = u16::from_le_bytes(data[77..79].try_into().expect("2 bytes"));

        if compress_algorithm != 0 {
            return Err(VmdkError::CompressedNotSupported);
        }

        // Validate geometry before these values feed division arithmetic in the reader.
        if grain_size == 0 {
            return Err(VmdkError::InvalidGeometry("grain_size must be > 0".into()));
        }
        if num_gtes_per_gt == 0 {
            return Err(VmdkError::InvalidGeometry("num_gtes_per_gt must be > 0".into()));
        }

        Ok(SparseExtentHeader {
            capacity,
            grain_size,
            descriptor_offset,
            descriptor_size,
            num_gtes_per_gt,
            gd_offset,
        })
    }
}
