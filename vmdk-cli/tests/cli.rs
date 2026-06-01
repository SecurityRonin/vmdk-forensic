use std::process::Command;

fn vmdk_bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_vmdk"))
}

fn data_path(name: &str) -> String {
    // CARGO_MANIFEST_DIR is vmdk-cli/ → workspace root is one level up
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("workspace root")
        .join("vmdk/tests/data")
        .join(name)
        .to_string_lossy()
        .into_owned()
}

#[test]
fn info_shows_virtual_disk_size_minimal() {
    let out = vmdk_bin()
        .args(["info", &data_path("minimal.vmdk")])
        .output()
        .expect("vmdk binary must run");
    assert!(out.status.success(), "exit status: {}", out.status);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("1,048,576") || stdout.contains("1 MiB"),
        "expected virtual disk size in output, got: {stdout}"
    );
}

#[test]
fn info_shows_format_monolithic_sparse() {
    let out = vmdk_bin()
        .args(["info", &data_path("minimal.vmdk")])
        .output()
        .expect("vmdk binary must run");
    assert!(out.status.success(), "exit status: {}", out.status);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("monolithicSparse"),
        "expected monolithicSparse in format line, got: {stdout}"
    );
}

#[test]
fn info_shows_sector_size() {
    let out = vmdk_bin()
        .args(["info", &data_path("minimal.vmdk")])
        .output()
        .expect("vmdk binary must run");
    assert!(out.status.success(), "exit status: {}", out.status);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("512"),
        "expected sector size 512 in output, got: {stdout}"
    );
}

#[test]
fn info_dfvfs_ext2_virtual_disk_size() {
    let out = vmdk_bin()
        .args(["info", &data_path("dfvfs_ext2.vmdk")])
        .output()
        .expect("vmdk binary must run");
    assert!(out.status.success(), "exit status: {}", out.status);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("4,194,304") || stdout.contains("4 MiB"),
        "expected 4 MiB virtual disk size, got: {stdout}"
    );
}

#[test]
fn info_errors_on_missing_file() {
    let out = vmdk_bin()
        .args(["info", "nonexistent.vmdk"])
        .output()
        .expect("vmdk binary must run");
    assert!(
        !out.status.success(),
        "should exit non-zero for missing file"
    );
}

#[test]
fn info_shows_stream_optimized_disk_type() {
    let out = vmdk_bin()
        .args(["info", &data_path("stream_opt.vmdk")])
        .output()
        .expect("vmdk binary must run");
    assert!(
        out.status.success(),
        "stream_opt.vmdk info must succeed after v3 support, exit: {}",
        out.status
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("streamOptimized"),
        "expected streamOptimized in output, got: {stdout}"
    );
}

#[test]
fn info_shows_flat_vmdk_disk_type() {
    let out = vmdk_bin()
        .args(["info", &data_path("flat.vmdk")])
        .output()
        .expect("vmdk binary must run");
    assert!(
        out.status.success(),
        "flat.vmdk info must succeed after open_path support, exit: {}",
        out.status
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("twoGbMaxExtentFlat"),
        "expected twoGbMaxExtentFlat in output, got: {stdout}"
    );
}
