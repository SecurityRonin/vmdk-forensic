//! Text VMDK descriptor parsing (Virtual Disk Format 1.1 §4.3).

use std::io;
use std::path::{Component, Path, PathBuf};

use crate::error::{Result, VmdkError};

/// Resolve a descriptor-controlled extent/parent filename against `base_dir`,
/// refusing any path that escapes that directory (absolute, root/prefix, or a
/// `..` component). VMDK descriptors reference sibling files by design; a path
/// that climbs out is a crafted-image attempt to read arbitrary host files, so
/// the safe default is to refuse it.
pub(crate) fn resolve_extent_path(base_dir: &Path, filename: &str) -> io::Result<PathBuf> {
    let rel = Path::new(filename);
    let escapes = rel.components().any(|c| {
        matches!(c, Component::ParentDir | Component::RootDir | Component::Prefix(_))
    });
    if escapes {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("refusing descriptor-controlled path that escapes the image directory: {filename}"),
        ));
    }
    Ok(base_dir.join(rel))
}

/// Parsed text VMDK descriptor.
pub(crate) struct TextDescriptor {
    pub create_type: Box<str>,
    /// Content ID (hex field `CID=`); `0xffff_ffff` when absent.
    pub cid: u32,
    /// Parent content ID (hex field `parentCID=`); `0xffff_ffff` when absent or base image.
    pub parent_cid: u32,
    /// Raw descriptor text (NUL bytes stripped; used by `VmdkReader::descriptor_text()`).
    /// `parentFileNameHint` is recovered from this text by the chain reader when needed.
    pub raw_text: Box<str>,
    /// FLAT extents (twoGbMaxExtentFlat, monolithicFlat).
    pub extents: Vec<ExtentEntry>,
    /// SPARSE extents (twoGbMaxExtentSparse) — each is a binary VMDK with its own GD/GT.
    pub sparse_extents: Vec<SparseEntry>,
    /// Sum of all FLAT extent sector counts.
    pub capacity_sectors: u64,
    /// Sum of all SPARSE extent sector counts.
    pub sparse_capacity_sectors: u64,
}

/// A single flat extent entry from the descriptor.
pub(crate) struct ExtentEntry {
    pub size_sectors: u64,
    pub filename: Box<str>,
    /// Byte offset into the extent file where this extent's data begins.
    pub file_byte_offset: u64,
    /// `true` for a `ZERO` extent: no backing file, reads as zeros.
    pub is_zero: bool,
}

/// A single sparse extent entry from the descriptor (twoGbMaxExtentSparse).
///
/// Each extent is an independent binary VMDK file with its own sparse header and GD/GT.
pub(crate) struct SparseEntry {
    pub size_sectors: u64,
    pub filename: Box<str>,
}

/// Parse a VMDK text descriptor, collecting all metadata fields and extent entries.
pub(crate) fn parse_text_descriptor(text: &str) -> Result<TextDescriptor> {
    let mut create_type = Box::from("");
    let mut cid: u32 = 0xffff_ffff;
    let mut parent_cid: u32 = 0xffff_ffff;
    let mut extents = Vec::new();
    let mut sparse_extents = Vec::new();
    let mut capacity_sectors = 0u64;
    let mut sparse_capacity_sectors = 0u64;

    // Strip NUL padding (embedded descriptors are zero-padded to a sector boundary).
    let text_clean = {
        let end = text.find('\0').unwrap_or(text.len());
        &text[..end]
    };

    for line in text_clean.lines() {
        let line = line.trim();
        if line.starts_with('#') || line.is_empty() {
            continue;
        }
        if let Some(rest) = line.strip_prefix("createType=") {
            create_type = Box::from(rest.trim_matches('"'));
            continue;
        }
        if let Some(rest) = line.strip_prefix("CID=") {
            cid = u32::from_str_radix(rest.trim(), 16).unwrap_or(0xffff_ffff);
            continue;
        }
        if let Some(rest) = line.strip_prefix("parentCID=") {
            parent_cid = u32::from_str_radix(rest.trim(), 16).unwrap_or(0xffff_ffff);
            continue;
        }
        if let Some(ext) = try_parse_flat_extent(line) {
            capacity_sectors = capacity_sectors
                .checked_add(ext.size_sectors)
                .ok_or(VmdkError::GeometryOverflow { field: "capacity" })?;
            extents.push(ext);
            continue;
        }
        if let Some(ext) = try_parse_sparse_extent(line) {
            sparse_capacity_sectors = sparse_capacity_sectors
                .checked_add(ext.size_sectors)
                .ok_or(VmdkError::GeometryOverflow { field: "capacity" })?;
            sparse_extents.push(ext);
        }
    }

    Ok(TextDescriptor {
        create_type,
        cid,
        parent_cid,
        raw_text: Box::from(text_clean),
        extents,
        sparse_extents,
        capacity_sectors,
        sparse_capacity_sectors,
    })
}

/// Parse a flat-style extent line:
///   `RW <n> FLAT "<file>" <sector_offset>` — preallocated raw extent
///   `RW <n> VMFS "<file>"`                 — `ESXi` flat extent (offset implied 0)
///   `RW <n> ZERO`                          — backing-file-less zero-filled extent
///
/// Returns `None` for sparse/other types, blank lines, comments, or malformed input.
fn try_parse_flat_extent(line: &str) -> Option<ExtentEntry> {
    let mut rest = line;

    // Access token: RW | RDONLY | NOACCESS. NOACCESS marks an inaccessible hole,
    // which we treat like ZERO (reads as zeros) so the virtual geometry is preserved.
    let (access, tail) = split_token(rest)?;
    if !matches!(access, "RW" | "RDONLY" | "NOACCESS") {
        return None;
    }
    rest = tail;

    // Sector count
    let (sectors_str, tail) = split_token(rest)?;
    let size_sectors: u64 = sectors_str.parse().ok()?;
    rest = tail;

    // Extent type — FLAT/VMFS/VMFSRAW/VMFSRDM are file-backed. VMFSRAW maps a raw
    // LUN; VMFSRDM is a Raw Device Mapping pointing at a mapped physical device.
    // ZERO has no file.
    let (ext_type, tail) = split_token(rest)?;
    if !matches!(ext_type, "FLAT" | "VMFS" | "VMFSRAW" | "VMFSRDM" | "ZERO") {
        return None;
    }
    rest = tail.trim_start();

    // ZERO (and NOACCESS) extents carry no filename or offset.
    if ext_type == "ZERO" || access == "NOACCESS" {
        return Some(ExtentEntry {
            size_sectors,
            filename: Box::from(""),
            file_byte_offset: 0,
            is_zero: true,
        });
    }

    // Filename: bare word or double-quoted (may contain spaces)
    let (filename, remaining) = if let Some(inner) = rest.strip_prefix('"') {
        let close = inner.find('"')?;
        (&inner[..close], &inner[close + 1..])
    } else {
        let end = rest.find(char::is_whitespace).unwrap_or(rest.len());
        (&rest[..end], &rest[end..])
    };

    let file_sector_offset: u64 = remaining.trim().parse().unwrap_or(0);

    Some(ExtentEntry {
        size_sectors,
        filename: Box::from(filename),
        file_byte_offset: file_sector_offset * 512,
        is_zero: false,
    })
}

/// Parse `<access> <n> SPARSE "<file>"` lines.
///
/// Returns `None` for non-SPARSE types or malformed input.
fn try_parse_sparse_extent(line: &str) -> Option<SparseEntry> {
    let mut rest = line;

    let (access, tail) = split_token(rest)?;
    if !matches!(access, "RW" | "RDONLY") {
        return None;
    }
    rest = tail;

    let (sectors_str, tail) = split_token(rest)?;
    let size_sectors: u64 = sectors_str.parse().ok()?;
    rest = tail;

    let (ext_type, tail) = split_token(rest)?;
    // SPARSE = standard VMDK4 sparse; VMFSSPARSE = COWD-based ESXi sparse;
    // SESPARSE = vSphere 6.5+ space-efficient sparse. All resolve to a binary
    // extent whose own magic selects the reader.
    if !matches!(ext_type, "SPARSE" | "VMFSSPARSE" | "SESPARSE") {
        return None;
    }
    rest = tail.trim_start();

    let filename = if let Some(inner) = rest.strip_prefix('"') {
        let close = inner.find('"')?;
        &inner[..close]
    } else {
        let end = rest.find(char::is_whitespace).unwrap_or(rest.len());
        &rest[..end]
    };

    Some(SparseEntry {
        size_sectors,
        filename: Box::from(filename),
    })
}

/// Split leading non-whitespace token from `s`; return `(token, rest_trimmed)`.
fn split_token(s: &str) -> Option<(&str, &str)> {
    let s = s.trim_start();
    if s.is_empty() {
        return None;
    }
    let end = s.find(char::is_whitespace).unwrap_or(s.len());
    Some((&s[..end], &s[end..]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_two_gb_max_extent_flat_descriptor() {
        let text = r#"# Disk DescriptorFile
version=1
CID=49bcfa17
parentCID=ffffffff
createType="twoGbMaxExtentFlat"

# Extent description
RW 2048 FLAT "flat-f001.vmdk" 0
"#;
        let d = parse_text_descriptor(text).expect("parse");
        assert_eq!(d.create_type.as_ref(), "twoGbMaxExtentFlat");
        assert_eq!(d.capacity_sectors, 2048);
        assert_eq!(d.extents.len(), 1);
        assert_eq!(d.extents[0].filename.as_ref(), "flat-f001.vmdk");
        assert_eq!(d.extents[0].size_sectors, 2048);
        assert_eq!(d.extents[0].file_byte_offset, 0);
    }

    #[test]
    fn parse_sparse_extents() {
        let text = "createType=\"twoGbMaxExtentSparse\"\nRW 8192 SPARSE \"disk-s001.vmdk\"\nRW 8192 SPARSE \"disk-s002.vmdk\"\n";
        let d = parse_text_descriptor(text).expect("parse");
        assert_eq!(d.extents.len(), 0);
        assert_eq!(d.sparse_extents.len(), 2);
        assert_eq!(d.sparse_extents[0].filename.as_ref(), "disk-s001.vmdk");
        assert_eq!(d.sparse_extents[0].size_sectors, 8192);
        assert_eq!(d.sparse_capacity_sectors, 16384);
    }

    #[test]
    fn parse_quoted_filename_with_spaces() {
        let text = "createType=\"twoGbMaxExtentFlat\"\nRW 512 FLAT \"my disk.vmdk\" 0\n";
        let d = parse_text_descriptor(text).expect("parse");
        assert_eq!(d.extents[0].filename.as_ref(), "my disk.vmdk");
    }

    #[test]
    fn parse_nonzero_sector_offset() {
        let text = "createType=\"twoGbMaxExtentFlat\"\nRW 512 FLAT \"ext.vmdk\" 4096\n";
        let d = parse_text_descriptor(text).expect("parse");
        assert_eq!(d.extents[0].file_byte_offset, 4096 * 512);
    }

    #[test]
    fn parse_flat_bare_word_filename() {
        // Unquoted (bare-word) filename — exercises the non-quoted branch.
        let text = "createType=\"monolithicFlat\"\nRW 2048 FLAT bare-f001.vmdk 0\n";
        let d = parse_text_descriptor(text).expect("parse");
        assert_eq!(d.extents.len(), 1);
        assert_eq!(d.extents[0].filename.as_ref(), "bare-f001.vmdk");
    }

    #[test]
    fn parse_sparse_bare_word_filename() {
        let text = "createType=\"twoGbMaxExtentSparse\"\nRW 2048 SPARSE bare-s001.vmdk\n";
        let d = parse_text_descriptor(text).expect("parse");
        assert_eq!(d.sparse_extents.len(), 1);
        assert_eq!(d.sparse_extents[0].filename.as_ref(), "bare-s001.vmdk");
    }

    #[test]
    fn parse_vmfsrdm_raw_device_mapping_extent() {
        // A Raw Device Mapping (RDM) disk points a VMFSRDM extent at the mapped
        // physical LUN (here a `vml.*` device identifier). libvmdk recognises
        // VMFSRDM as a first-class extent type; dropping it loses the record of
        // which physical device the VM had passthrough access to.
        let text = "createType=\"vmfsRawDeviceMap\"\nRW 20971520 VMFSRDM \"vml.02000000006006016015301d00\"\n";
        let d = parse_text_descriptor(text).expect("parse");
        assert_eq!(d.create_type.as_ref(), "vmfsRawDeviceMap");
        assert_eq!(d.extents.len(), 1);
        assert_eq!(
            d.extents[0].filename.as_ref(),
            "vml.02000000006006016015301d00"
        );
        assert_eq!(d.extents[0].size_sectors, 20_971_520);
        assert!(!d.extents[0].is_zero);
        assert_eq!(d.capacity_sectors, 20_971_520);
    }

    #[test]
    fn malformed_extent_lines_are_ignored() {
        // Lines that match neither flat nor sparse grammar are skipped, not errors.
        // "RW" alone exercises split_token's empty-remainder branch.
        let text =
            "createType=\"custom\"\nRW 100 BOGUS \"x.vmdk\"\nRDONLY notanumber FLAT \"y\"\nRW\n";
        let d = parse_text_descriptor(text).expect("parse");
        assert!(d.extents.is_empty());
        assert!(d.sparse_extents.is_empty());
    }

    #[test]
    fn sparse_extent_capacity_overflow_is_rejected() {
        // Two near-u64::MAX SPARSE extents overflow the running capacity sum.
        let big = u64::MAX;
        let text = format!(
            "createType=\"twoGbMaxExtentSparse\"\nRW {big} SPARSE \"a\"\nRW {big} SPARSE \"b\"\n"
        );
        assert!(matches!(
            parse_text_descriptor(&text),
            Err(VmdkError::GeometryOverflow { field: "capacity" })
        ));
    }

    #[test]
    fn flat_extent_capacity_overflow_is_rejected() {
        let big = u64::MAX;
        let text = format!(
            "createType=\"twoGbMaxExtentFlat\"\nRW {big} FLAT \"a\" 0\nRW {big} FLAT \"b\" 0\n"
        );
        assert!(matches!(
            parse_text_descriptor(&text),
            Err(VmdkError::GeometryOverflow { field: "capacity" })
        ));
    }
}
