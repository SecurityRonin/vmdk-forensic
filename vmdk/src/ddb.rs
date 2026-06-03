//! VMDK disk database (`ddb.*`) — the descriptor's metadata namespace.
//!
//! VMware writes a `# The Disk Data Base` section of `ddb.<key> = "<value>"` pairs
//! at the end of the descriptor: virtual geometry, controller type, VM hardware /
//! tools versions, disk UUID, long content ID, thin-provisioning, and the
//! descriptor text encoding. Both `qemu-img` and libvmdk parse the descriptor but
//! **discard every `ddb.*` value**; surfacing them is high-value forensic metadata
//! (image dating, controller provenance, cross-snapshot disk identity).
//!
//! Source: libvmdk VMDK format spec — "The disk database"
//!   https://github.com/libyal/libvmdk/blob/main/documentation/VMware%20Virtual%20Disk%20Format%20(VMDK).asciidoc

// (implementation added in the GREEN commit)

#[cfg(test)]
mod tests {
    use super::*;

    const FULL: &str = "# Disk DescriptorFile\nversion=1\nCID=12345678\nparentCID=ffffffff\ncreateType=\"monolithicSparse\"\n\nddb.adapterType = \"lsilogic\"\nddb.geometry.cylinders = \"16383\"\nddb.geometry.heads = \"16\"\nddb.geometry.sectors = \"63\"\nddb.virtualHWVersion = \"7\"\nddb.toolsVersion = \"10338\"\nddb.uuid = \"60 00 C2 97 1a 2b 3c 4d-5e 6f 70 81 92 a3 b4 c5\"\nddb.longContentID = \"deadbeefcafef00d1122334455667788\"\nddb.thinProvisioned = \"1\"\nddb.encoding = \"UTF-8\"\n";

    #[test]
    fn parses_adapter_type_and_versions() {
        let db = DiskDatabase::parse(FULL);
        assert_eq!(db.adapter_type.as_deref(), Some("lsilogic"));
        assert_eq!(db.virtual_hw_version.as_deref(), Some("7"));
        assert_eq!(db.tools_version.as_deref(), Some("10338"));
        assert_eq!(db.encoding.as_deref(), Some("UTF-8"));
    }

    #[test]
    fn parses_geometry() {
        let db = DiskDatabase::parse(FULL);
        let g = db.geometry.expect("geometry present");
        assert_eq!(g.cylinders, 16383);
        assert_eq!(g.heads, 16);
        assert_eq!(g.sectors, 63);
        // CHS-reported sector count.
        assert_eq!(g.chs_sectors(), 16383 * 16 * 63);
    }

    #[test]
    fn parses_uuid_thin_and_long_content_id() {
        let db = DiskDatabase::parse(FULL);
        assert_eq!(
            db.uuid.as_deref(),
            Some("60 00 C2 97 1a 2b 3c 4d-5e 6f 70 81 92 a3 b4 c5")
        );
        assert_eq!(db.long_content_id.as_deref(), Some("deadbeefcafef00d1122334455667788"));
        assert_eq!(db.thin_provisioned, Some(true));
    }

    #[test]
    fn empty_when_no_ddb_section() {
        let db = DiskDatabase::parse("# Disk DescriptorFile\nversion=1\ncreateType=\"monolithicFlat\"\n");
        assert!(db.is_empty());
        assert_eq!(db.adapter_type, None);
        assert_eq!(db.geometry, None);
        assert_eq!(db.thin_provisioned, None);
    }

    #[test]
    fn unknown_ddb_keys_are_retained() {
        let db = DiskDatabase::parse("ddb.somethingNew = \"42\"\nddb.adapterType = \"ide\"\n");
        assert_eq!(db.adapter_type.as_deref(), Some("ide"));
        assert_eq!(db.get("ddb.somethingNew"), Some("42"));
        assert!(!db.is_empty());
    }

    #[test]
    fn thin_provisioned_zero_is_false() {
        let db = DiskDatabase::parse("ddb.thinProvisioned = \"0\"\n");
        assert_eq!(db.thin_provisioned, Some(false));
    }

    #[test]
    fn partial_geometry_is_ignored() {
        // Geometry requires all three of cylinders/heads/sectors.
        let db = DiskDatabase::parse("ddb.geometry.cylinders = \"100\"\nddb.geometry.heads = \"4\"\n");
        assert_eq!(db.geometry, None);
    }
}
