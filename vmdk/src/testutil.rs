//! Minimal valid sparse VMDK builder for use in tests and downstream crates.

use super::header::{MAGIC, SECTOR_SIZE, VERSION};

// Layout constants (all in sectors unless noted):
const DESCRIPTOR_OFFSET: u64 = 1;
const DESCRIPTOR_SECTORS: u64 = 20;
const GD_SECTOR: u64 = DESCRIPTOR_OFFSET + DESCRIPTOR_SECTORS; // 21
const RGD_SECTOR: u64 = GD_SECTOR + 1;                         // 22
const GT_SECTOR: u64 = RGD_SECTOR + 1;                         // 23
const GT_SECTORS: u64 = 4;                                      // 512 GTEs × 4 B = 2048 B
const GRAIN_SECTOR: u64 = GT_SECTOR + GT_SECTORS;               // 27

pub const GRAIN_SIZE_SECTORS: u64 = 8;
pub const GRAIN_SIZE_BYTES: usize = GRAIN_SIZE_SECTORS as usize * SECTOR_SIZE as usize;
const NUM_GTES_PER_GT: u32 = 512;

/// Build a minimal valid monolithic sparse VMDK containing `sector_data` in grain 0.
///
/// `sector_data` is zero-padded or truncated to [`GRAIN_SIZE_BYTES`].
#[cfg_attr(not(any(test, feature = "test-helpers")), allow(dead_code))]
pub fn test_sparse_vmdk(sector_data: &[u8]) -> Vec<u8> {
    // ── Grain data ────────────────────────────────────────────────────────────
    let mut grain = vec![0u8; GRAIN_SIZE_BYTES];
    let copy_len = sector_data.len().min(GRAIN_SIZE_BYTES);
    grain[..copy_len].copy_from_slice(&sector_data[..copy_len]);

    // ── Header (512 bytes) ────────────────────────────────────────────────────
    let mut hdr = vec![0u8; 512];
    hdr[0..4].copy_from_slice(&MAGIC.to_le_bytes());
    hdr[4..8].copy_from_slice(&VERSION.to_le_bytes());
    hdr[8..12].copy_from_slice(&0u32.to_le_bytes()); // flags
    hdr[12..20].copy_from_slice(&GRAIN_SIZE_SECTORS.to_le_bytes()); // capacity = 1 grain
    hdr[20..28].copy_from_slice(&GRAIN_SIZE_SECTORS.to_le_bytes()); // grainSize
    hdr[28..36].copy_from_slice(&DESCRIPTOR_OFFSET.to_le_bytes());
    hdr[36..44].copy_from_slice(&DESCRIPTOR_SECTORS.to_le_bytes());
    hdr[44..48].copy_from_slice(&NUM_GTES_PER_GT.to_le_bytes());
    hdr[48..56].copy_from_slice(&RGD_SECTOR.to_le_bytes()); // rgdOffset
    hdr[56..64].copy_from_slice(&GD_SECTOR.to_le_bytes());  // gdOffset
    hdr[64..72].copy_from_slice(&GRAIN_SECTOR.to_le_bytes()); // overHead
    hdr[72] = 0; // uncleanShutdown
    hdr[73] = b'\n';
    hdr[74] = b' ';
    hdr[75] = b'\r';
    hdr[76] = b'\n';
    hdr[77..79].copy_from_slice(&0u16.to_le_bytes()); // compressAlgorithm = 0

    // ── Descriptor (20 sectors) ───────────────────────────────────────────────
    let mut desc = vec![0u8; DESCRIPTOR_SECTORS as usize * SECTOR_SIZE as usize];
    let s = "# Disk DescriptorFile\nversion=1\nCID=fffffffe\nparentCID=ffffffff\ncreateType=\"monolithicSparse\"\n";
    let n = s.len().min(desc.len());
    desc[..n].copy_from_slice(&s.as_bytes()[..n]);

    // ── Grain Directory (1 sector, first entry → GT) ──────────────────────────
    let mut gd = vec![0u8; SECTOR_SIZE as usize];
    gd[0..4].copy_from_slice(&(GT_SECTOR as u32).to_le_bytes());
    let rgd = gd.clone(); // redundant GD

    // ── Grain Table (4 sectors, first GTE → grain data) ──────────────────────
    let mut gt = vec![0u8; GT_SECTORS as usize * SECTOR_SIZE as usize];
    gt[0..4].copy_from_slice(&(GRAIN_SECTOR as u32).to_le_bytes());

    // ── Assemble ──────────────────────────────────────────────────────────────
    let mut vmdk = Vec::new();
    vmdk.extend_from_slice(&hdr);
    vmdk.extend_from_slice(&desc);
    vmdk.extend_from_slice(&gd);
    vmdk.extend_from_slice(&rgd);
    vmdk.extend_from_slice(&gt);
    vmdk.extend_from_slice(&grain);
    vmdk
}
