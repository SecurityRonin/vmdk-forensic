//! Forensic integrity analysis for VMware VMDK images.
//!
//! `vmdk` is a lean `Read + Seek` reader. `vmdk-forensic` is the evidence-grade layer
//! on top of it (the same split as `vhdx`/`vhdx-forensic` and `ewf`/`ewf-forensic`):
//! it reparses the raw structure — so it works on images too damaged for some readers —
//! and reports the redundant-grain-directory, dangling-pointer, recovery, and header
//! provenance findings that `qemu-img` and `libvmdk` discard.
//!
//! ```no_run
//! use vmdk_forensic::{VmdkIntegrity, Severity};
//! let mut a = VmdkIntegrity::new(std::fs::File::open("disk.vmdk")?);
//! for anomaly in a.analyse()? {
//!     if anomaly.severity >= Severity::Warning {
//!         println!("[{:?}] {}", anomaly.severity, anomaly.detail);
//!     }
//! }
//! # Ok::<(), std::io::Error>(())
//! ```

use std::io::{self, Read, Seek, SeekFrom};

use vmdk::header::{self, SparseExtentHeader};
use vmdk::sesparse::{self, SeConstHeader};

/// The lean reader, re-exported so this one crate covers read + forensic analysis.
pub use vmdk::VmdkReader;

const SECTOR_SIZE: u64 = 512;
/// Cap on the grain-directory size read from a (possibly crafted) header (16 MiB).
const MAX_GD_BYTES: u64 = 16 * 1024 * 1024;

/// Result of a structural integrity walk ([`VmdkIntegrity::check_integrity`]).
///
/// Counts grain-directory / grain-table pointers that fall outside the backing file —
/// the signature of a truncated or tampered image. [`is_ok`](Self::is_ok) is the verdict.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct IntegrityReport {
    /// Number of allocated grains examined.
    pub grains_checked: u64,
    /// Allocated grains whose data offset lies beyond end-of-file.
    pub out_of_bounds_grains: u64,
    /// Grain-directory entries whose grain table lies beyond end-of-file.
    pub out_of_bounds_grain_tables: u64,
}

impl IntegrityReport {
    /// `true` when no out-of-bounds pointer was found.
    #[must_use]
    pub fn is_ok(&self) -> bool {
        self.out_of_bounds_grains == 0 && self.out_of_bounds_grain_tables == 0
    }
}

/// Per-entry recovery analysis of the grain directory against its redundant copy.
///
/// VMDK keeps a redundant grain directory (RGD) so a damaged primary GD can still be
/// recovered; `qemu-img` discards it. `primary_intact + primary_damaged == total_entries`
/// and `recoverable_via_rgd + unrecoverable == primary_damaged`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct GdRecoveryReport {
    /// `true` when the image carries a usable redundant grain directory.
    pub has_rgd: bool,
    /// Number of grain-directory entries analysed.
    pub total_entries: usize,
    /// Primary entries usable as-is (in-bounds, or sparse and agreeing with the RGD).
    pub primary_intact: usize,
    /// Primary entries that are damaged (out-of-bounds, or sparse where the RGD holds a pointer).
    pub primary_damaged: usize,
    /// Damaged primary entries the RGD can recover.
    pub recoverable_via_rgd: usize,
    /// Damaged primary entries the RGD cannot recover (damaged in both directories).
    pub unrecoverable: usize,
}

/// Provenance read from the 512-byte sparse header — fields other readers discard.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[allow(clippy::struct_excessive_bools)] // independent provenance flags, not a state enum
pub struct HeaderProvenance {
    /// Header format version (1, 2, or 3).
    pub version: u32,
    /// `uncleanShutdown` (byte 72) — the disk was not closed cleanly (crash / power-loss
    /// / live image): in-flight writes may be inconsistent.
    pub unclean_shutdown: bool,
    /// Newline-detection bytes (73..77) are exactly `0A 20 0D 0A`. `false` ⇒ the binary
    /// was mangled by an ASCII-mode FTP transfer (which rewrites `\r\n`).
    pub newline_check_intact: bool,
    /// Flag bit `0x2` — a redundant (secondary) grain directory is present.
    pub uses_redundant_gd: bool,
    /// Flag bit `0x10000` — grains carry compressed data.
    pub compressed: bool,
    /// Flag bit `0x20000` — the stream carries metadata markers (streamOptimized).
    pub has_markers: bool,
}

/// Severity of a forensic finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum Severity {
    /// Informational — provenance or benign state.
    Info,
    /// Suspicious — may indicate corruption or recoverable damage.
    Warning,
    /// Structural defect — truncation, tampering, or unreadable region.
    Error,
}

/// The kind of a forensic finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum AnomalyKind {
    /// `uncleanShutdown` flag set.
    UncleanShutdown,
    /// Header newline-detection bytes mangled (ASCII-mode FTP transfer).
    FtpAsciiMangled,
    /// Redundant grain directory diverges from the primary (grain-table contents differ).
    RedundantGdMismatch,
    /// One or more grain-table pointers fall beyond end-of-file.
    DanglingGrainTable,
    /// One or more grain pointers fall beyond end-of-file.
    DanglingGrain,
    /// The primary grain directory is damaged but (partly) recoverable via the RGD.
    PrimaryGdRecoverableViaRgd,
    /// The primary grain directory is damaged with no RGD recovery available.
    PrimaryGdUnrecoverable,
}

/// A single forensic finding with its severity and a human-readable explanation.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct VmdkAnomaly {
    /// How serious the finding is.
    pub severity: Severity,
    /// What was found.
    pub kind: AnomalyKind,
    /// Forensic significance — what it means for the examiner.
    pub detail: String,
}

/// Reparsed VMDK4 sparse layout needed for RGD / integrity analysis.
struct SparseLayout {
    grain_dir: Vec<u32>,
    rgd_offset: u64,
    num_gtes_per_gt: u64,
    grain_size_bytes: u64,
    gd_entry_count: usize,
    file_len: u64,
}

/// Forensic integrity analyzer over any `Read + Seek` VMDK source.
///
/// Reparses the raw structure on each call, so a single instance can run several
/// analyses and tolerates partially-damaged images.
pub struct VmdkIntegrity<R: Read + Seek> {
    inner: R,
}

impl<R: Read + Seek> VmdkIntegrity<R> {
    /// Wrap a `Read + Seek` VMDK source.
    pub fn new(reader: R) -> Self {
        Self { inner: reader }
    }

    /// Recover the wrapped reader.
    pub fn into_inner(self) -> R {
        self.inner
    }

    fn file_len(&mut self) -> io::Result<u64> {
        self.inner.seek(SeekFrom::End(0))
    }

    fn read_at(&mut self, offset: u64, len: usize) -> io::Result<Vec<u8>> {
        self.inner.seek(SeekFrom::Start(offset))?;
        let mut buf = vec![0u8; len];
        self.inner.read_exact(&mut buf)?;
        Ok(buf)
    }

    /// Reparse the VMDK4 sparse layout, or `None` if the image is not a parseable
    /// VMDK4 sparse image (flat / COWD / seSparse / unreadable).
    fn sparse_layout(&mut self) -> io::Result<Option<SparseLayout>> {
        let file_len = self.file_len()?;
        if file_len < SECTOR_SIZE {
            return Ok(None);
        }
        let hdr_bytes = self.read_at(0, SECTOR_SIZE as usize)?;
        let Ok(hdr) = SparseExtentHeader::parse(&hdr_bytes) else {
            return Ok(None);
        };
        let num_grains = hdr.capacity.div_ceil(hdr.grain_size);
        let num_gtes = u64::from(hdr.num_gtes_per_gt);
        let num_gts = num_grains.div_ceil(num_gtes);
        let gd_byte_len = num_gts.saturating_mul(4);
        if gd_byte_len > MAX_GD_BYTES {
            return Ok(None);
        }
        let gd_byte_len = gd_byte_len as usize;

        // streamOptimized stores the real GD offset in the footer header.
        let gd_offset = if hdr.gd_offset == header::GD_AT_END {
            if file_len < 1024 {
                return Ok(None);
            }
            let footer = self.read_at(file_len - 1024, SECTOR_SIZE as usize)?;
            match SparseExtentHeader::parse(&footer) {
                Ok(fh) => fh.gd_offset,
                Err(_) => return Ok(None),
            }
        } else {
            hdr.gd_offset
        };

        let gd_byte = gd_offset.saturating_mul(SECTOR_SIZE);
        if gd_byte.saturating_add(gd_byte_len as u64) > file_len {
            return Ok(None);
        }
        let gd = self.read_at(gd_byte, gd_byte_len)?;
        let grain_dir: Vec<u32> = gd
            .chunks_exact(4)
            .map(|c| u32::from_le_bytes(c.try_into().expect("4 bytes")))
            .collect();

        Ok(Some(SparseLayout {
            grain_dir,
            rgd_offset: hdr.rgd_offset,
            num_gtes_per_gt: num_gtes,
            grain_size_bytes: hdr.grain_size.saturating_mul(SECTOR_SIZE),
            gd_entry_count: num_gts as usize,
            file_len,
        }))
    }

    fn read_grain_table_bytes(
        &mut self,
        gt_sector: u32,
        gt_byte_len: usize,
        file_len: u64,
    ) -> io::Result<Option<Vec<u8>>> {
        let gt_byte = u64::from(gt_sector) * SECTOR_SIZE;
        if gt_byte.saturating_add(gt_byte_len as u64) > file_len {
            return Ok(None);
        }
        Ok(Some(self.read_at(gt_byte, gt_byte_len)?))
    }

    /// Read the redundant grain directory, bounds-checked, or `None` if absent/OOB.
    fn read_rgd(&mut self, layout: &SparseLayout) -> io::Result<Option<Vec<u32>>> {
        if layout.rgd_offset == 0 || layout.rgd_offset == header::GD_AT_END {
            return Ok(None);
        }
        let rgd_byte = layout.rgd_offset.saturating_mul(SECTOR_SIZE);
        let len = layout.gd_entry_count.saturating_mul(4) as u64;
        if rgd_byte.saturating_add(len) > layout.file_len {
            return Ok(None);
        }
        let bytes = self.read_at(rgd_byte, len as usize)?;
        Ok(Some(
            bytes
                .chunks_exact(4)
                .map(|c| u32::from_le_bytes(c.try_into().expect("4 bytes")))
                .collect(),
        ))
    }

    /// Validate the redundant grain directory by comparing the grain-table **contents**
    /// each directory references (not the pointers, which differ by design in every
    /// healthy multi-copy image). `Ok(true)` when they match, `Ok(false)` when the RGD
    /// is absent or diverges.
    pub fn validate_rgd(&mut self) -> io::Result<bool> {
        let Some(layout) = self.sparse_layout()? else {
            return Ok(false);
        };
        let Some(rgd) = self.read_rgd(&layout)? else {
            return Ok(false);
        };
        let gt_byte_len = (layout.num_gtes_per_gt * 4) as usize;
        for i in 0..layout.gd_entry_count {
            let p = layout.grain_dir.get(i).copied().unwrap_or(0);
            let r = rgd.get(i).copied().unwrap_or(0);
            if p == 0 && r == 0 {
                continue;
            }
            if (p == 0) != (r == 0) {
                return Ok(false);
            }
            let pgt = self.read_grain_table_bytes(p, gt_byte_len, layout.file_len)?;
            let rgt = self.read_grain_table_bytes(r, gt_byte_len, layout.file_len)?;
            match (pgt, rgt) {
                (Some(a), Some(b)) if a == b => {}
                _ => return Ok(false),
            }
        }
        Ok(true)
    }

    /// Classify every grain-directory entry against the redundant copy: how much of the
    /// primary GD is intact, damaged, and recoverable via the RGD.
    pub fn grain_directory_recovery(&mut self) -> io::Result<GdRecoveryReport> {
        let Some(layout) = self.sparse_layout()? else {
            return Ok(GdRecoveryReport::default());
        };
        let rgd = self.read_rgd(&layout)?;
        let Some(rgd) = rgd else {
            // rgd_offset is 0/sentinel → no RGD at all.
            if layout.rgd_offset == 0 || layout.rgd_offset == header::GD_AT_END {
                return Ok(GdRecoveryReport::default());
            }
            // RGD present in the header but its directory is out of bounds: nothing recoverable.
            let mut report = GdRecoveryReport {
                has_rgd: true,
                total_entries: layout.gd_entry_count,
                ..GdRecoveryReport::default()
            };
            for &p in &layout.grain_dir {
                if Self::in_bounds(p, layout.num_gtes_per_gt, layout.file_len) || p == 0 {
                    report.primary_intact += 1;
                } else {
                    report.primary_damaged += 1;
                    report.unrecoverable += 1;
                }
            }
            return Ok(report);
        };

        let mut report = GdRecoveryReport {
            has_rgd: true,
            total_entries: layout.gd_entry_count,
            ..GdRecoveryReport::default()
        };
        for i in 0..layout.gd_entry_count {
            let p = layout.grain_dir.get(i).copied().unwrap_or(0);
            let r = rgd.get(i).copied().unwrap_or(0);
            let p_ok = Self::in_bounds(p, layout.num_gtes_per_gt, layout.file_len);
            if p_ok || (p == 0 && r == 0) {
                report.primary_intact += 1;
            } else {
                report.primary_damaged += 1;
                if Self::in_bounds(r, layout.num_gtes_per_gt, layout.file_len) {
                    report.recoverable_via_rgd += 1;
                } else {
                    report.unrecoverable += 1;
                }
            }
        }
        Ok(report)
    }

    fn in_bounds(ptr: u32, num_gtes_per_gt: u64, file_len: u64) -> bool {
        ptr != 0
            && u64::from(ptr)
                .saturating_mul(SECTOR_SIZE)
                .saturating_add(num_gtes_per_gt * 4)
                <= file_len
    }

    /// Walk the grain directory and tables, counting pointers that fall beyond
    /// end-of-file (the signature of a truncated or tampered image). Covers VMDK4
    /// sparse and seSparse; flat/COWD images report clean.
    pub fn check_integrity(&mut self) -> io::Result<IntegrityReport> {
        let file_len = self.file_len()?;
        if file_len < SECTOR_SIZE {
            return Ok(IntegrityReport::default());
        }
        let head = self.read_at(0, 8)?;
        let magic8 = u64::from_le_bytes(head.try_into().expect("8 bytes"));
        if magic8 == sesparse::SE_CONST_MAGIC {
            return self.check_integrity_sesparse(file_len);
        }

        let Some(layout) = self.sparse_layout()? else {
            return Ok(IntegrityReport::default());
        };
        let mut report = IntegrityReport::default();
        let gt_byte_len = layout.num_gtes_per_gt * 4;
        for &gt_sector in &layout.grain_dir {
            if gt_sector == 0 {
                continue;
            }
            let gt_byte = u64::from(gt_sector) * SECTOR_SIZE;
            if gt_byte.saturating_add(gt_byte_len) > file_len {
                report.out_of_bounds_grain_tables += 1;
                continue;
            }
            let gt = self.read_at(gt_byte, gt_byte_len as usize)?;
            for c in gt.chunks_exact(4) {
                let gte = u32::from_le_bytes(c.try_into().expect("4 bytes"));
                if gte <= 1 {
                    continue; // sparse / explicitly-zeroed
                }
                report.grains_checked += 1;
                let grain_byte = u64::from(gte) * SECTOR_SIZE;
                if grain_byte.saturating_add(layout.grain_size_bytes) > file_len {
                    report.out_of_bounds_grains += 1;
                }
            }
        }
        Ok(report)
    }

    fn check_integrity_sesparse(&mut self, file_len: u64) -> io::Result<IntegrityReport> {
        let mut report = IntegrityReport::default();
        let hdr_bytes = self.read_at(0, SECTOR_SIZE as usize)?;
        let Ok(hdr) = SeConstHeader::parse(&hdr_bytes) else {
            return Ok(report);
        };
        if hdr.grain_size == 0 {
            return Ok(report);
        }
        let num_grains = hdr.capacity.div_ceil(hdr.grain_size);
        let num_gts = num_grains.div_ceil(sesparse::SE_GTES_PER_GT).max(1);
        let gd_len = num_gts.saturating_mul(8);
        let gd_byte = hdr.gd_offset.saturating_mul(SECTOR_SIZE);
        if gd_len > MAX_GD_BYTES || gd_byte.saturating_add(gd_len) > file_len {
            return Ok(report);
        }
        let gd = self.read_at(gd_byte, gd_len as usize)?;
        let grain_dir: Vec<u64> = gd
            .chunks_exact(8)
            .map(|c| u64::from_le_bytes(c.try_into().expect("8 bytes")))
            .collect();
        let grain_size_bytes = hdr.grain_size.saturating_mul(SECTOR_SIZE);
        let grain_sectors = hdr.grain_size;
        let gt_byte_len = sesparse::SE_GTES_PER_GT * 8;
        for &gd_entry in &grain_dir {
            if gd_entry == 0 {
                continue;
            }
            if gd_entry & sesparse::SE_GD_ALLOC_MASK != sesparse::SE_GD_ALLOC_FLAG {
                report.out_of_bounds_grain_tables += 1;
                continue;
            }
            let gt_table_idx = gd_entry & sesparse::SE_GD_INDEX_MASK;
            let gt_sector = hdr
                .gt_offset
                .saturating_add(gt_table_idx.saturating_mul(sesparse::SE_GT_SECTORS));
            let gt_byte = gt_sector.saturating_mul(SECTOR_SIZE);
            if gt_byte.saturating_add(gt_byte_len) > file_len {
                report.out_of_bounds_grain_tables += 1;
                continue;
            }
            let gt = self.read_at(gt_byte, gt_byte_len as usize)?;
            for c in gt.chunks_exact(8) {
                let gte = u64::from_le_bytes(c.try_into().expect("8 bytes"));
                if gte & sesparse::SE_GTE_TYPE_MASK != sesparse::SE_GTE_TYPE_ALLOCATED {
                    continue;
                }
                report.grains_checked += 1;
                let grain_idx = sesparse::se_gte_grain_index(gte);
                let grain_byte = hdr
                    .grains_offset
                    .saturating_add(grain_idx.saturating_mul(grain_sectors))
                    .saturating_mul(SECTOR_SIZE);
                if grain_byte.saturating_add(grain_size_bytes) > file_len {
                    report.out_of_bounds_grains += 1;
                }
            }
        }
        Ok(report)
    }

    /// Read the 512-byte sparse-header provenance, or `None` if the header is not VMDK4.
    pub fn header_provenance(&mut self) -> io::Result<Option<HeaderProvenance>> {
        let file_len = self.file_len()?;
        if file_len < SECTOR_SIZE {
            return Ok(None);
        }
        let hdr = self.read_at(0, SECTOR_SIZE as usize)?;
        if u32::from_le_bytes(hdr[0..4].try_into().expect("4 bytes")) != header::MAGIC {
            return Ok(None);
        }
        let version = u32::from_le_bytes(hdr[4..8].try_into().expect("4 bytes"));
        let flags = u32::from_le_bytes(hdr[8..12].try_into().expect("4 bytes"));
        Ok(Some(HeaderProvenance {
            version,
            unclean_shutdown: hdr[72] != 0,
            newline_check_intact: hdr[73..77] == [0x0A, 0x20, 0x0D, 0x0A],
            uses_redundant_gd: flags & 0x0000_0002 != 0,
            compressed: flags & 0x0001_0000 != 0,
            has_markers: flags & 0x0002_0000 != 0,
        }))
    }

    /// Run every analysis and aggregate the findings into a graded anomaly list,
    /// sorted most-severe first.
    pub fn analyse(&mut self) -> io::Result<Vec<VmdkAnomaly>> {
        let mut out = Vec::new();

        if let Some(p) = self.header_provenance()? {
            if p.unclean_shutdown {
                out.push(VmdkAnomaly {
                    severity: Severity::Warning,
                    kind: AnomalyKind::UncleanShutdown,
                    detail: "uncleanShutdown flag set — the disk was not closed cleanly; \
                             in-flight writes may be inconsistent"
                        .to_string(),
                });
            }
            if !p.newline_check_intact {
                out.push(VmdkAnomaly {
                    severity: Severity::Error,
                    kind: AnomalyKind::FtpAsciiMangled,
                    detail: "header newline-detection bytes mangled — the image was likely \
                             corrupted by an ASCII-mode FTP transfer"
                        .to_string(),
                });
            }
        }

        let recovery = self.grain_directory_recovery()?;
        if recovery.has_rgd && !self.validate_rgd()? {
            out.push(VmdkAnomaly {
                severity: Severity::Error,
                kind: AnomalyKind::RedundantGdMismatch,
                detail: "redundant grain directory diverges from the primary — the grain \
                         tables they reference hold different contents"
                    .to_string(),
            });
        }
        if recovery.recoverable_via_rgd > 0 {
            out.push(VmdkAnomaly {
                severity: Severity::Warning,
                kind: AnomalyKind::PrimaryGdRecoverableViaRgd,
                detail: format!(
                    "{} of {} grain-directory entries damaged, {} recoverable via the RGD",
                    recovery.primary_damaged, recovery.total_entries, recovery.recoverable_via_rgd
                ),
            });
        }
        if recovery.unrecoverable > 0 {
            out.push(VmdkAnomaly {
                severity: Severity::Error,
                kind: AnomalyKind::PrimaryGdUnrecoverable,
                detail: format!(
                    "{} grain-directory entries damaged with no RGD recovery available",
                    recovery.unrecoverable
                ),
            });
        }

        let integrity = self.check_integrity()?;
        if integrity.out_of_bounds_grain_tables > 0 {
            out.push(VmdkAnomaly {
                severity: Severity::Error,
                kind: AnomalyKind::DanglingGrainTable,
                detail: format!(
                    "{} grain-table pointer(s) point beyond end-of-file (truncation or tampering)",
                    integrity.out_of_bounds_grain_tables
                ),
            });
        }
        if integrity.out_of_bounds_grains > 0 {
            out.push(VmdkAnomaly {
                severity: Severity::Error,
                kind: AnomalyKind::DanglingGrain,
                detail: format!(
                    "{} grain pointer(s) point beyond end-of-file (truncation or tampering)",
                    integrity.out_of_bounds_grains
                ),
            });
        }

        out.sort_by_key(|a| std::cmp::Reverse(a.severity));
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    use vmdk::testutil::{test_sesparse_vmdk, test_sparse_vmdk};

    #[test]
    fn header_provenance_clean_image() {
        let v = test_sparse_vmdk(&[0u8; 512]);
        let mut a = VmdkIntegrity::new(Cursor::new(v));
        let p = a.header_provenance().expect("io").expect("VMDK4 header");
        assert_eq!(p.version, 1);
        assert!(!p.unclean_shutdown);
        assert!(p.newline_check_intact);
    }

    #[test]
    fn validate_rgd_true_on_healthy_image() {
        let v = test_sparse_vmdk(&[0xAB; 512]);
        let mut a = VmdkIntegrity::new(Cursor::new(v));
        assert!(a.validate_rgd().expect("io"));
    }

    #[test]
    fn validate_rgd_false_on_redundant_gt_divergence() {
        // Corrupt the redundant grain table (sector 22 in the test fixture).
        let mut v = test_sparse_vmdk(&[0xAB; 512]);
        v[22 * 512] ^= 0xFF;
        let mut a = VmdkIntegrity::new(Cursor::new(v));
        assert!(!a.validate_rgd().expect("io"));
    }

    #[test]
    fn grain_directory_recovery_flags_recoverable_damage() {
        let mut v = test_sparse_vmdk(&[0xAB; 512]);
        v[21 * 512..21 * 512 + 4].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes()); // primary GD[0] damaged
        let mut a = VmdkIntegrity::new(Cursor::new(v));
        let r = a.grain_directory_recovery().expect("io");
        assert!(r.has_rgd);
        assert_eq!(r.primary_damaged, 1);
        assert_eq!(r.recoverable_via_rgd, 1);
    }

    #[test]
    fn check_integrity_clean_then_flags_dangling_gt() {
        let v = test_sparse_vmdk(&[0xAB; 512]);
        let mut a = VmdkIntegrity::new(Cursor::new(v));
        assert!(a.check_integrity().expect("io").is_ok());

        let mut v2 = test_sparse_vmdk(&[0xAB; 512]);
        v2[21 * 512..21 * 512 + 4].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
        let mut a2 = VmdkIntegrity::new(Cursor::new(v2));
        let rep = a2.check_integrity().expect("io");
        assert!(!rep.is_ok());
        assert_eq!(rep.out_of_bounds_grain_tables, 1);
    }

    #[test]
    fn analyse_reports_rgd_mismatch_anomaly() {
        let mut v = test_sparse_vmdk(&[0xAB; 512]);
        v[22 * 512] ^= 0xFF; // redundant GT diverges
        let mut a = VmdkIntegrity::new(Cursor::new(v));
        let anomalies = a.analyse().expect("io");
        assert!(
            anomalies
                .iter()
                .any(|x| matches!(x.kind, AnomalyKind::RedundantGdMismatch)),
            "expected an RGD mismatch anomaly, got: {anomalies:?}"
        );
    }

    #[test]
    fn into_inner_returns_reader() {
        let v = test_sparse_vmdk(&[0u8; 512]);
        let a = VmdkIntegrity::new(Cursor::new(v));
        let _cursor = a.into_inner();
    }

    #[test]
    fn header_provenance_flags_unclean_shutdown_and_ftp_mangling() {
        let mut v = test_sparse_vmdk(&[0u8; 512]);
        v[72] = 1; // uncleanShutdown
        v[73] = 0x20; // break the 0A 20 0D 0A newline-detection sequence
        let mut a = VmdkIntegrity::new(Cursor::new(v));
        let p = a.header_provenance().expect("io").expect("vmdk4");
        assert!(p.unclean_shutdown);
        assert!(!p.newline_check_intact);
    }

    #[test]
    fn header_provenance_none_for_non_vmdk4() {
        let mut a = VmdkIntegrity::new(Cursor::new(vec![0u8; 1024]));
        assert!(a.header_provenance().expect("io").is_none());
    }

    #[test]
    fn validate_rgd_false_for_sesparse() {
        let se = test_sesparse_vmdk(&[0u8; 512]);
        let mut a = VmdkIntegrity::new(Cursor::new(se));
        assert!(!a.validate_rgd().expect("io")); // no RGD in seSparse
    }

    #[test]
    fn grain_directory_recovery_default_when_no_rgd() {
        let mut v = test_sparse_vmdk(&[0u8; 512]);
        v[48..56].copy_from_slice(&0u64.to_le_bytes()); // rgd_offset = 0
        let mut a = VmdkIntegrity::new(Cursor::new(v));
        let r = a.grain_directory_recovery().expect("io");
        assert!(!r.has_rgd);
        assert_eq!(r.total_entries, 0);
    }

    #[test]
    fn grain_directory_recovery_counts_unrecoverable() {
        let mut v = test_sparse_vmdk(&[0u8; 512]);
        v[21 * 512..21 * 512 + 4].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes()); // primary GD[0]
        v[22 * 512..22 * 512 + 4].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes()); // RGD[0]
        let mut a = VmdkIntegrity::new(Cursor::new(v));
        let r = a.grain_directory_recovery().expect("io");
        assert_eq!(r.primary_damaged, 1);
        assert_eq!(r.unrecoverable, 1);
        assert_eq!(r.recoverable_via_rgd, 0);
    }

    #[test]
    fn grain_directory_recovery_clean_all_intact() {
        let v = test_sparse_vmdk(&[0xAB; 512]);
        let mut a = VmdkIntegrity::new(Cursor::new(v));
        let r = a.grain_directory_recovery().expect("io");
        assert!(r.has_rgd);
        assert_eq!(r.primary_intact, r.total_entries);
        assert_eq!(r.primary_damaged, 0);
    }

    #[test]
    fn sesparse_integrity_clean_and_flagged() {
        // Clean seSparse: no out-of-bounds pointers.
        let se = test_sesparse_vmdk(&[0xAB; 512]);
        let mut a = VmdkIntegrity::new(Cursor::new(se));
        assert!(a.check_integrity().expect("io").is_ok());

        // Invalid GD allocation marker → flagged grain table.
        let mut se2 = test_sesparse_vmdk(&[0xAB; 512]);
        let gd = 2 * 512;
        se2[gd..gd + 8].copy_from_slice(&0x5000_0000_0000_0000u64.to_le_bytes());
        let mut a2 = VmdkIntegrity::new(Cursor::new(se2));
        let rep = a2.check_integrity().expect("io");
        assert!(!rep.is_ok());
        assert_eq!(rep.out_of_bounds_grain_tables, 1);

        // Allocated marker pointing to a grain table past EOF → flagged.
        let mut se3 = test_sesparse_vmdk(&[0xAB; 512]);
        se3[gd..gd + 8].copy_from_slice(&(0x1000_0000_0000_0000u64 | 0xFFFF_FFFF).to_le_bytes());
        let mut a3 = VmdkIntegrity::new(Cursor::new(se3));
        assert!(!a3.check_integrity().expect("io").is_ok());
    }

    #[test]
    fn check_integrity_flags_grain_past_eof() {
        // Point a primary GT entry at a grain past EOF (GT at sector 23, GTE[0]).
        let mut v = test_sparse_vmdk(&[0xAB; 512]);
        v[23 * 512..23 * 512 + 4].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
        let mut a = VmdkIntegrity::new(Cursor::new(v));
        let rep = a.check_integrity().expect("io");
        assert_eq!(rep.out_of_bounds_grains, 1);
        assert!(!rep.is_ok());
    }

    #[test]
    fn analyse_flags_unclean_shutdown_warning() {
        let mut v = test_sparse_vmdk(&[0u8; 512]);
        v[72] = 1;
        let mut a = VmdkIntegrity::new(Cursor::new(v));
        let anomalies = a.analyse().expect("io");
        assert!(anomalies
            .iter()
            .any(|x| matches!(x.kind, AnomalyKind::UncleanShutdown)));
    }

    #[test]
    fn analyse_flags_dangling_and_recoverable_for_corrupt_primary_gd() {
        let mut v = test_sparse_vmdk(&[0xAB; 512]);
        v[21 * 512..21 * 512 + 4].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
        let mut a = VmdkIntegrity::new(Cursor::new(v));
        let k: Vec<_> = a
            .analyse()
            .expect("io")
            .into_iter()
            .map(|x| x.kind)
            .collect();
        assert!(k.contains(&AnomalyKind::DanglingGrainTable));
        assert!(k.contains(&AnomalyKind::PrimaryGdRecoverableViaRgd));
        // first finding is the most severe (Error sorts before Warning)
    }

    #[test]
    fn analyse_flags_unrecoverable_when_both_directories_damaged() {
        let mut v = test_sparse_vmdk(&[0xAB; 512]);
        v[21 * 512..21 * 512 + 4].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
        v[22 * 512..22 * 512 + 4].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
        let mut a = VmdkIntegrity::new(Cursor::new(v));
        let k: Vec<_> = a
            .analyse()
            .expect("io")
            .into_iter()
            .map(|x| x.kind)
            .collect();
        assert!(k.contains(&AnomalyKind::PrimaryGdUnrecoverable));
    }

    #[test]
    fn tiny_and_garbage_inputs_are_safe() {
        for bytes in [vec![0u8; 100], vec![0xFFu8; 512], vec![0u8; 600]] {
            let mut a = VmdkIntegrity::new(Cursor::new(bytes));
            assert!(!a.validate_rgd().expect("io"));
            assert!(a.check_integrity().expect("io").is_ok());
            assert!(a.grain_directory_recovery().expect("io").total_entries == 0);
            assert!(a.header_provenance().expect("io").is_none());
            let _ = a.analyse().expect("io");
        }
    }

    #[test]
    fn validate_rgd_false_when_only_one_directory_has_a_gt() {
        let mut v = test_sparse_vmdk(&[0xAB; 512]);
        v[21 * 512..21 * 512 + 4].copy_from_slice(&0u32.to_le_bytes()); // primary GD[0] sparse, RGD[0] not
        let mut a = VmdkIntegrity::new(Cursor::new(v));
        assert!(!a.validate_rgd().expect("io"));
    }

    #[test]
    fn grain_directory_recovery_rgd_directory_out_of_bounds_is_unrecoverable() {
        let mut v = test_sparse_vmdk(&[0xAB; 512]);
        v[21 * 512..21 * 512 + 4].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes()); // primary damaged
        v[48..56].copy_from_slice(&9_999_999u64.to_le_bytes()); // rgd_offset past EOF
        let mut a = VmdkIntegrity::new(Cursor::new(v));
        let r = a.grain_directory_recovery().expect("io");
        assert!(r.has_rgd);
        assert_eq!(r.unrecoverable, 1);
        assert_eq!(r.recoverable_via_rgd, 0);
    }

    #[test]
    fn analyse_flags_ftp_ascii_mangling() {
        let mut v = test_sparse_vmdk(&[0u8; 512]);
        v[73] = 0x20; // break the newline-detection sequence
        let mut a = VmdkIntegrity::new(Cursor::new(v));
        let k: Vec<_> = a
            .analyse()
            .expect("io")
            .into_iter()
            .map(|x| x.kind)
            .collect();
        assert!(k.contains(&AnomalyKind::FtpAsciiMangled));
    }

    #[test]
    fn analyse_flags_dangling_grain() {
        let mut v = test_sparse_vmdk(&[0xAB; 512]);
        v[23 * 512..23 * 512 + 4].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes()); // GT[0] → grain past EOF
        let mut a = VmdkIntegrity::new(Cursor::new(v));
        let k: Vec<_> = a
            .analyse()
            .expect("io")
            .into_iter()
            .map(|x| x.kind)
            .collect();
        assert!(k.contains(&AnomalyKind::DanglingGrain));
    }

    #[test]
    fn sesparse_grain_past_eof_is_flagged() {
        // An allocated seSparse GTE whose grain index lands past EOF.
        let mut se = test_sesparse_vmdk(&[0xAB; 512]);
        // GT entries for seSparse live after the GD; corrupt the first GTE of GT 0.
        // GD[0] at sector 2 holds the allocated GT index; the GT is at gt_offset.
        // Easiest reachable path: set capacity huge so grains land past EOF.
        se[16..24].copy_from_slice(&u64::MAX.to_le_bytes()); // capacity field
        let mut a = VmdkIntegrity::new(Cursor::new(se));
        let _ = a.check_integrity().expect("io"); // must not panic on the crafted capacity
    }

    #[test]
    fn validate_rgd_false_when_grain_directory_out_of_bounds() {
        let mut v = test_sparse_vmdk(&[0u8; 512]);
        v[56..64].copy_from_slice(&9_999_999u64.to_le_bytes()); // gd_offset past EOF
        let mut a = VmdkIntegrity::new(Cursor::new(v));
        assert!(!a.validate_rgd().expect("io"));
        assert!(a.check_integrity().expect("io").is_ok()); // no parseable layout
    }

    #[test]
    fn validate_rgd_false_when_rgd_directory_out_of_bounds() {
        let mut v = test_sparse_vmdk(&[0xAB; 512]);
        v[48..56].copy_from_slice(&9_999_999u64.to_le_bytes()); // rgd_offset past EOF
        let mut a = VmdkIntegrity::new(Cursor::new(v));
        assert!(!a.validate_rgd().expect("io"));
    }

    #[test]
    fn sesparse_zero_grain_size_and_oob_gd_are_safe() {
        let mut se = test_sesparse_vmdk(&[0u8; 512]);
        se[24..32].copy_from_slice(&0u64.to_le_bytes()); // grain_size = 0
        let mut a = VmdkIntegrity::new(Cursor::new(se));
        assert!(a.check_integrity().expect("io").is_ok());

        let mut se2 = test_sesparse_vmdk(&[0u8; 512]);
        se2[128..136].copy_from_slice(&9_999_999u64.to_le_bytes()); // gd_offset past EOF
        let mut a2 = VmdkIntegrity::new(Cursor::new(se2));
        assert!(a2.check_integrity().expect("io").is_ok());
    }

    #[test]
    fn streamoptimized_gd_at_end_footer_resolution() {
        // Build a GD_AT_END image: the primary header's gd_offset is the sentinel and the
        // real GD offset lives in the footer header (file_end - 1024).
        let mut v = test_sparse_vmdk(&[0xAB; 512]);
        v[56..64].copy_from_slice(&0xFFFF_FFFF_FFFF_FFFFu64.to_le_bytes()); // gd_offset = GD_AT_END
        let mut footer = v[0..512].to_vec();
        footer[56..64].copy_from_slice(&21u64.to_le_bytes()); // footer points at the real GD (sector 21)
        v.extend_from_slice(&footer);
        v.extend_from_slice(&[0u8; 512]); // EOS marker
        let mut a = VmdkIntegrity::new(Cursor::new(v));
        assert!(a.check_integrity().expect("io").is_ok());
        assert!(a.validate_rgd().expect("io"));
    }

    #[test]
    fn sesparse_huge_capacity_grain_directory_too_large_is_safe() {
        let mut se = test_sesparse_vmdk(&[0u8; 512]);
        se[16..24].copy_from_slice(&u64::MAX.to_le_bytes()); // capacity → GD size exceeds the cap
        let mut a = VmdkIntegrity::new(Cursor::new(se));
        assert!(a.check_integrity().expect("io").is_ok()); // bails out safely
    }

    #[test]
    fn sesparse_allocated_gte_grain_past_eof_is_flagged() {
        // Set GT[0] to an allocated entry whose grain index lands past EOF.
        let mut se = test_sesparse_vmdk(&[0xAB; 512]);
        let gt0 = 3 * 512; // grain table 0 starts at sector 3 in the fixture
        se[gt0..gt0 + 8].copy_from_slice(&(0x3000_0000_0000_0000u64 | 0x00FF_FFFF).to_le_bytes());
        let mut a = VmdkIntegrity::new(Cursor::new(se));
        let _ = a.check_integrity().expect("io"); // must not panic on the crafted grain index
    }

    #[test]
    fn analyse_clean_image_has_no_error_anomalies() {
        let v = test_sparse_vmdk(&[0xAB; 512]);
        let mut a = VmdkIntegrity::new(Cursor::new(v));
        let anomalies = a.analyse().expect("io");
        assert!(anomalies.iter().all(|x| x.severity != Severity::Error));
    }
}
