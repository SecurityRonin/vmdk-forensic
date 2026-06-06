//! Integrity analysis against the real committed VMDK images (in the sibling
//! `vmdk` crate's test corpus).

use std::io::Cursor;
use vmdk_forensic::VmdkIntegrity;

fn fixture(name: &str) -> Vec<u8> {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../vmdk/tests/data")
        .join(name);
    std::fs::read(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
}

#[test]
fn real_images_pass_integrity() {
    for name in [
        "minimal.vmdk",
        "dfvfs_ext2.vmdk",
        "plaso_image.vmdk",
        "stream_opt.vmdk",
    ] {
        let mut a = VmdkIntegrity::new(Cursor::new(fixture(name)));
        let report = a.check_integrity().expect("check_integrity");
        assert!(report.is_ok(), "{name} must pass integrity: {report:?}");
    }
}

#[test]
fn truncated_image_fails_integrity() {
    let mut data = fixture("dfvfs_ext2.vmdk");
    data.truncate(data.len() / 2); // chop the grain data → dangling pointers
    let mut a = VmdkIntegrity::new(Cursor::new(data));
    let report = a.check_integrity().expect("check_integrity");
    assert!(
        !report.is_ok(),
        "truncated image must fail integrity: {report:?}"
    );
}

#[test]
fn streamoptimized_image_analyses_via_footer_gd() {
    // stream_opt.vmdk uses GD_AT_END — exercises the footer grain-directory resolution.
    let mut a = VmdkIntegrity::new(Cursor::new(fixture("stream_opt.vmdk")));
    let _ = a.check_integrity().expect("check_integrity");
    let _ = a.validate_rgd().expect("validate_rgd");
    let _ = a.analyse().expect("analyse");
}
