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

// ── info ──────────────────────────────────────────────────────────────────────

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
    assert!(out.status.success(), "exit: {}", out.status);
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
    assert!(out.status.success(), "exit: {}", out.status);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("twoGbMaxExtentFlat"),
        "expected twoGbMaxExtentFlat in output, got: {stdout}"
    );
}

#[test]
fn info_lists_companion_extent_files() {
    // A multi-file VMDK's info must name the companion file(s) to collect.
    let out = vmdk_bin()
        .args(["info", &data_path("flat.vmdk")])
        .output()
        .expect("vmdk binary must run");
    assert!(out.status.success(), "exit: {}", out.status);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("flat-f001.vmdk"),
        "info must list the companion extent file, got: {stdout}"
    );
}

#[test]
fn info_omits_dependencies_for_self_contained() {
    // A self-contained binary VMDK must not print a dependencies section.
    let out = vmdk_bin()
        .args(["info", &data_path("dfvfs_ext2.vmdk")])
        .output()
        .expect("vmdk binary must run");
    assert!(out.status.success(), "exit: {}", out.status);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        !stdout.to_lowercase().contains("companion") && !stdout.to_lowercase().contains("depends"),
        "self-contained VMDK must omit the dependencies section, got: {stdout}"
    );
}

// ── info --descriptor (folds in old `descriptor` command) ─────────────────────

#[test]
fn info_descriptor_flag_shows_create_type() {
    let out = vmdk_bin()
        .args(["info", "--descriptor", &data_path("minimal.vmdk")])
        .output()
        .expect("vmdk info --descriptor must run");
    assert!(out.status.success(), "exit: {}", out.status);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("createType") || stdout.contains("monolithicSparse"),
        "expected raw descriptor text, got: {stdout}"
    );
}

// ── info --chain (folds in old `snapshot-chain` command) ──────────────────────

#[test]
fn info_chain_flag_base_image_shows_depth_one() {
    let out = vmdk_bin()
        .args(["info", "--chain", &data_path("minimal.vmdk")])
        .output()
        .expect("vmdk info --chain must run");
    assert!(out.status.success(), "exit: {}", out.status);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("1 layer") || stdout.contains("depth: 1"),
        "expected chain depth 1, got: {stdout}"
    );
}

// ── map (renamed from `sectors`) ──────────────────────────────────────────────

#[test]
fn map_all_sparse_shows_no_allocated() {
    let out = vmdk_bin()
        .args(["map", &data_path("minimal.vmdk")])
        .output()
        .expect("vmdk map must run");
    assert!(out.status.success(), "exit: {}", out.status);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("start_lba")
            || stdout.contains("No allocated")
            || stdout.contains("sparse"),
        "got: {stdout}"
    );
}

#[test]
fn map_dfvfs_shows_allocated_grains() {
    let out = vmdk_bin()
        .args(["map", &data_path("dfvfs_ext2.vmdk")])
        .output()
        .expect("vmdk map must run");
    assert!(out.status.success(), "exit: {}", out.status);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains(',') || stdout.contains("allocated grain"),
        "expected allocated grain ranges, got: {stdout}"
    );
}

// ── dump (folds in cat + extract + hexdump) ───────────────────────────────────

#[test]
fn dump_to_stdout_outputs_disk_bytes() {
    // Default dump (no -o, no --hex) writes raw bytes to stdout (was: cat).
    let out = vmdk_bin()
        .args(["dump", &data_path("minimal.vmdk")])
        .output()
        .expect("vmdk dump must run");
    assert!(out.status.success(), "exit: {}", out.status);
    // minimal.vmdk is 1 MiB all-zeros → stdout should be 1,048,576 zero bytes
    assert_eq!(
        out.stdout.len(),
        1_048_576,
        "dump must emit full virtual disk to stdout"
    );
    assert!(
        out.stdout.iter().all(|&b| b == 0),
        "all-sparse disk must dump as zeros"
    );
}

#[test]
fn dump_hex_flag_outputs_hex() {
    let out = vmdk_bin()
        .args([
            "dump",
            "--hex",
            "--offset",
            "0",
            "--length",
            "32",
            &data_path("dfvfs_ext2.vmdk"),
        ])
        .output()
        .expect("vmdk dump --hex must run");
    assert!(out.status.success(), "exit: {}", out.status);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("00000000"),
        "expected hex offset column, got: {stdout}"
    );
}

#[test]
fn dump_output_file_produces_raw_of_correct_size() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let out_path = tmp.path().join("out.raw");
    let status = vmdk_bin()
        .args([
            "dump",
            "-o",
            out_path.to_str().unwrap(),
            &data_path("minimal.vmdk"),
        ])
        .status()
        .expect("vmdk dump -o must run");
    assert!(status.success(), "exit: {status}");
    let meta = std::fs::metadata(&out_path).expect("output file must exist");
    assert_eq!(meta.len(), 1_048_576, "raw file must be 1 MiB");
}

#[test]
fn dump_offset_length_reads_subrange() {
    // Dump 16 bytes at offset 1024 of dfvfs_ext2 (has real data there) to a file.
    let tmp = tempfile::tempdir().expect("tempdir");
    let out_path = tmp.path().join("range.raw");
    let status = vmdk_bin()
        .args([
            "dump",
            "--offset",
            "1024",
            "--length",
            "16",
            "-o",
            out_path.to_str().unwrap(),
            &data_path("dfvfs_ext2.vmdk"),
        ])
        .status()
        .expect("vmdk dump range must run");
    assert!(status.success(), "exit: {status}");
    let meta = std::fs::metadata(&out_path).expect("output file");
    assert_eq!(meta.len(), 16, "range dump must be exactly 16 bytes");
}

// ── hash ──────────────────────────────────────────────────────────────────────

#[test]
fn hash_produces_sha256_and_md5() {
    let out = vmdk_bin()
        .args(["hash", &data_path("minimal.vmdk")])
        .output()
        .expect("vmdk hash must run");
    assert!(out.status.success(), "exit: {}", out.status);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("SHA-256"),
        "expected SHA-256 line, got: {stdout}"
    );
    assert!(stdout.contains("MD5"), "expected MD5 line, got: {stdout}");
}

#[test]
fn hash_minimal_vmdk_matches_known_md5() {
    let out = vmdk_bin()
        .args(["hash", &data_path("minimal.vmdk")])
        .output()
        .expect("vmdk hash must run");
    assert!(out.status.success(), "exit: {}", out.status);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("b6d81b360a5672d80c27430f39153e2c"),
        "MD5 mismatch, got: {stdout}"
    );
}

// ── verify ────────────────────────────────────────────────────────────────────

#[test]
fn verify_minimal_vmdk_exits_ok() {
    let out = vmdk_bin()
        .args(["verify", &data_path("minimal.vmdk")])
        .output()
        .expect("vmdk verify must run");
    assert!(out.status.success(), "exit: {}", out.status);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("OK"),
        "expected OK in verify output, got: {stdout}"
    );
}

#[test]
fn verify_reports_integrity_for_clean_image() {
    let out = vmdk_bin()
        .args(["verify", &data_path("dfvfs_ext2.vmdk")])
        .output()
        .expect("vmdk verify must run");
    assert!(out.status.success(), "exit: {}", out.status);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("Integrity"),
        "verify must report an integrity line, got: {stdout}"
    );
}

#[test]
fn verify_detects_corruption_and_exits_nonzero() {
    // Truncate a real allocated-grain image so its grain pointers dangle.
    let tmp = tempfile::tempdir().expect("tempdir");
    let mut data = std::fs::read(data_path("dfvfs_ext2.vmdk")).expect("read corpus");
    data.truncate(data.len() / 2);
    let p = tmp.path().join("truncated.vmdk");
    std::fs::write(&p, &data).expect("write truncated");
    let out = vmdk_bin()
        .args(["verify", p.to_str().unwrap()])
        .output()
        .expect("vmdk verify must run");
    assert!(
        !out.status.success(),
        "verify must exit non-zero on a corrupted image"
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.to_uppercase().contains("FAIL") || stdout.contains("out-of-bounds"),
        "verify must flag the corruption, got: {stdout}"
    );
}

// ── diff ──────────────────────────────────────────────────────────────────────

#[test]
fn diff_identical_vmdk_reports_identical() {
    let path = data_path("minimal.vmdk");
    let out = vmdk_bin()
        .args(["diff", &path, &path])
        .output()
        .expect("vmdk diff must run");
    assert!(out.status.success(), "exit: {}", out.status);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("IDENTICAL"),
        "expected IDENTICAL, got: {stdout}"
    );
}

#[test]
fn diff_different_vmdks_exits_nonzero() {
    let out = vmdk_bin()
        .args([
            "diff",
            &data_path("minimal.vmdk"),
            &data_path("dfvfs_ext2.vmdk"),
        ])
        .output()
        .expect("vmdk diff must run");
    assert!(
        !out.status.success(),
        "diff of different VMDKs (different sizes) must exit non-zero"
    );
}
