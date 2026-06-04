use std::io::{self, BufWriter, Read, Seek, SeekFrom, Write};
use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use vmdk::{VmdkChainReader, VmdkFileReader};

fn fmt_commas(n: u64) -> String {
    let s = n.to_string();
    let mut out = String::with_capacity(s.len() + s.len() / 3);
    for (i, c) in s.chars().rev().enumerate() {
        if i > 0 && i % 3 == 0 {
            out.push(',');
        }
        out.push(c);
    }
    out.chars().rev().collect()
}

/// Open a VMDK, mapping any error to a printable message.
///
/// Returning `Result` (rather than calling `process::exit`) keeps every error
/// path a normal return, so coverage counters flush and the code is exercisable.
fn open(path: &std::path::Path) -> Result<VmdkFileReader, String> {
    VmdkFileReader::open_path(path).map_err(|e| format!("error: {e}"))
}

#[derive(Parser)]
#[command(
    name = "vmdk",
    version,
    about = "Comprehensive read-only CLI for VMware VMDK disk images",
    long_about = "Read-only VMDK inspector supporting monolithicSparse, streamOptimized, \
                  twoGbMaxExtentFlat/Sparse, monolithicFlat, COWD (vmfsSparse/vmfsThin), \
                  seSparse (VMFS6), and snapshot chains.\n\n\
                  VMDK is a block container — it stores raw disk sectors, not files. \
                  To extract individual files, pipe `dump` output (or VmdkReader) into a \
                  filesystem tool that understands the guest filesystem (NTFS, ext4, …)."
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Show image metadata; --descriptor dumps the raw descriptor, --chain walks the snapshot chain
    Info {
        path: PathBuf,
        /// Print the raw embedded text descriptor instead of the summary
        #[arg(long)]
        descriptor: bool,
        /// Show the snapshot/delta chain (parentFileNameHint traversal)
        #[arg(long)]
        chain: bool,
    },

    /// List allocated (non-sparse) grain ranges as `start_lba,sector_count`
    Map { path: PathBuf },

    /// Output virtual disk bytes — to stdout, a file (-o), or as a hex dump (--hex)
    Dump {
        path: PathBuf,
        /// Write to this file instead of stdout (raw flat image extraction)
        #[arg(short, long)]
        output: Option<PathBuf>,
        /// Start byte offset within the virtual disk
        #[arg(long, default_value_t = 0)]
        offset: u64,
        /// Number of bytes to output (default: to end of disk)
        #[arg(long)]
        length: Option<u64>,
        /// Render as a hex dump (offset | hex bytes | ASCII) instead of raw bytes
        #[arg(long)]
        hex: bool,
        /// Recover via the redundant grain directory when the primary GD is damaged
        #[arg(long)]
        recover: bool,
    },

    /// Compute SHA-256 and MD5 of the full virtual disk (one streaming pass)
    Hash {
        path: PathBuf,
        /// Recover via the redundant grain directory when the primary GD is damaged
        #[arg(long)]
        recover: bool,
    },

    /// Verify structural integrity: RGD validation + allocation scan
    Verify { path: PathBuf },

    /// Byte-by-byte comparison of two VMDK virtual disks
    Diff {
        /// First VMDK file
        a: PathBuf,
        /// Second VMDK file
        b: PathBuf,
    },
}

/// Print an error message to stderr and yield a failure exit code.
fn fail(msg: impl std::fmt::Display) -> ExitCode {
    eprintln!("{msg}");
    ExitCode::FAILURE
}

// ── info ──────────────────────────────────────────────────────────────────────

fn cmd_info(path: &std::path::Path, descriptor: bool, chain: bool) -> ExitCode {
    if descriptor {
        return print_descriptor(path);
    }
    if chain {
        return print_chain(path);
    }

    let reader = match open(path) {
        Ok(r) => r,
        Err(m) => return fail(m),
    };
    let info = reader.info();
    let mib = info.virtual_disk_size as f64 / (1024.0 * 1024.0);
    let file_name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();

    println!("File:              {file_name}");
    println!(
        "Format:            VMDK v{} ({})",
        info.version, info.disk_type
    );
    println!(
        "Virtual disk size: {} bytes ({mib:.2} MiB)",
        fmt_commas(info.virtual_disk_size)
    );
    println!("Sector size:       512 bytes");
    println!("Sectors:           {}", fmt_commas(info.sector_count));
    if info.grain_size_sectors > 0 {
        println!(
            "Grain size:        {} sectors ({} KiB)",
            info.grain_size_sectors,
            info.grain_size_bytes / 1024
        );
    }
    println!(
        "Compressed:        {}",
        if info.compressed { "yes" } else { "no" }
    );
    if info.cid != 0xffff_ffff {
        println!("CID:               {:08x}", info.cid);
    }
    if info.parent_cid != 0xffff_ffff {
        println!("Parent CID:        {:08x}", info.parent_cid);
    }
    if !info.descriptor_text.is_empty() {
        let line_count = info.descriptor_text.lines().count();
        println!("Descriptor:        {line_count} lines (see --descriptor)");
    }

    // Companion extent files an examiner must collect alongside this descriptor.
    if let Ok(deps) = VmdkFileReader::extent_dependencies(path) {
        if !deps.is_empty() {
            println!("Companion files:   {} extent(s) required:", deps.len());
            for d in &deps {
                let name = d.file_name().map_or_else(
                    || d.to_string_lossy().into_owned(),
                    |n| n.to_string_lossy().into_owned(),
                );
                let present = if d.exists() { "" } else { "  (MISSING)" };
                println!("                   - {name}{present}");
            }
        }
    }
    ExitCode::SUCCESS
}

fn print_descriptor(path: &std::path::Path) -> ExitCode {
    let reader = match open(path) {
        Ok(r) => r,
        Err(m) => return fail(m),
    };
    let text = reader.descriptor_text();
    if text.is_empty() {
        return fail(format!("No embedded descriptor in {}", path.display()));
    }
    print!("{text}");
    ExitCode::SUCCESS
}

fn print_chain(path: &std::path::Path) -> ExitCode {
    match VmdkChainReader::open(path) {
        Ok(chain) => {
            println!("Chain depth:  {} layer(s)", chain.depth());
            println!(
                "Virtual size: {} bytes",
                fmt_commas(chain.virtual_disk_size())
            );
            ExitCode::SUCCESS
        }
        Err(e) => {
            // Fall back to single-image view, reporting parentCID if present.
            match open(path) {
                Ok(r) => {
                    let info = r.info();
                    println!("Chain depth:  1 layer");
                    println!("Virtual size: {} bytes", fmt_commas(info.virtual_disk_size));
                    if info.parent_cid == 0xffff_ffff {
                        println!("No parent (base image)");
                    } else {
                        println!(
                            "Parent CID:   {:08x} (parent file not found: {e})",
                            info.parent_cid
                        );
                    }
                    ExitCode::SUCCESS
                }
                Err(m) => fail(m),
            }
        }
    }
}

// ── map ───────────────────────────────────────────────────────────────────────

fn cmd_map(path: &std::path::Path) -> ExitCode {
    let mut reader = match open(path) {
        Ok(r) => r,
        Err(m) => return fail(m),
    };
    let grains = match reader.iter_allocated_grains() {
        Ok(g) => g,
        Err(e) => return fail(format!("error: {e}")),
    };
    if grains.is_empty() {
        println!("# No allocated grains (all-sparse)");
        return ExitCode::SUCCESS;
    }
    println!("# start_lba,sector_count");
    for g in &grains {
        println!("{},{}", g.start_lba, g.sector_count);
    }
    eprintln!("{} allocated grain(s)", grains.len());
    ExitCode::SUCCESS
}

// ── dump ──────────────────────────────────────────────────────────────────────

fn cmd_dump(
    path: &std::path::Path,
    output: Option<&std::path::Path>,
    offset: u64,
    length: Option<u64>,
    hex: bool,
    recover: bool,
) -> ExitCode {
    let mut reader = match open(path) {
        Ok(r) => r,
        Err(m) => return fail(m),
    };
    if recover {
        // Resolve grains through the redundant grain directory when the primary GD
        // entry is damaged — recovers data qemu-img would fail on.
        reader.enable_rgd_fallback();
    }
    let disk_size = reader.virtual_disk_size();
    let end = length.map_or(disk_size, |len| offset.saturating_add(len).min(disk_size));
    let to_output = end.saturating_sub(offset);

    if let Err(e) = reader.seek(SeekFrom::Start(offset)) {
        return fail(format!("seek error: {e}"));
    }

    if hex {
        return match dump_hex(&mut reader, offset, to_output) {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => fail(format!("read error: {e}")),
        };
    }

    // Raw byte output to file or stdout.
    if let Some(out_path) = output {
        let file = match std::fs::File::create(out_path) {
            Ok(f) => f,
            Err(e) => return fail(format!("cannot create {}: {e}", out_path.display())),
        };
        let mut w = BufWriter::new(file);
        if let Err(e) = copy_n(&mut reader, &mut w, to_output) {
            return fail(format!("write error: {e}"));
        }
        w.flush().ok();
        eprintln!(
            "Wrote {} bytes to {}",
            fmt_commas(to_output),
            out_path.display()
        );
    } else {
        let stdout = io::stdout();
        let mut w = BufWriter::new(stdout.lock());
        if let Err(e) = copy_n(&mut reader, &mut w, to_output) {
            return fail(format!("write error: {e}"));
        }
        w.flush().ok();
    }
    ExitCode::SUCCESS
}

/// Copy exactly `n` bytes from `reader` to `w`.
fn copy_n<R: Read, W: Write>(reader: &mut R, w: &mut W, n: u64) -> io::Result<()> {
    let mut remaining = n;
    let mut buf = vec![0u8; 65536];
    while remaining > 0 {
        let want = (buf.len() as u64).min(remaining) as usize;
        let got = reader.read(&mut buf[..want])?;
        if got == 0 {
            break;
        }
        w.write_all(&buf[..got])?;
        remaining -= got as u64;
    }
    Ok(())
}

fn dump_hex<R: Read>(reader: &mut R, start_offset: u64, length: u64) -> io::Result<()> {
    let stdout = io::stdout();
    let mut w = BufWriter::new(stdout.lock());
    let mut remaining = length;
    let mut pos = start_offset;
    let mut buf = [0u8; 16];
    while remaining > 0 {
        let want = (16u64.min(remaining)) as usize;
        let n = reader.read(&mut buf[..want])?;
        if n == 0 {
            break;
        }
        let _ = write!(w, "{pos:08x}  ");
        for (i, &byte) in buf.iter().enumerate() {
            if i < n {
                let _ = write!(w, "{byte:02x} ");
            } else {
                let _ = write!(w, "   ");
            }
            if i == 7 {
                let _ = write!(w, " ");
            }
        }
        let _ = write!(w, " |");
        for &c in &buf[..n] {
            let ch = if c.is_ascii_graphic() || c == b' ' {
                c as char
            } else {
                '.'
            };
            let _ = write!(w, "{ch}");
        }
        let _ = writeln!(w, "|");
        pos += n as u64;
        remaining = remaining.saturating_sub(n as u64);
    }
    w.flush().ok();
    Ok(())
}

// ── hash ──────────────────────────────────────────────────────────────────────

fn cmd_hash(path: &std::path::Path, recover: bool) -> ExitCode {
    let mut reader = match open(path) {
        Ok(r) => r,
        Err(m) => return fail(m),
    };
    if recover {
        reader.enable_rgd_fallback();
    }
    reader.seek(SeekFrom::Start(0)).ok();
    let digest = match reader.hash() {
        Ok(d) => d,
        Err(e) => return fail(format!("error: {e}")),
    };
    println!("SHA-256: {}", digest.sha256);
    println!("MD5:     {}", digest.md5);
    println!("File:    {}", path.display());
    ExitCode::SUCCESS
}

// ── verify ────────────────────────────────────────────────────────────────────

/// Build the `RGD:` status line for `verify` from the redundant-GD recovery report.
///
/// `matches` is [`vmdk::VmdkReader::validate_rgd`]'s verdict; `rec` is the
/// per-entry recovery analysis. Distinguishes a truly absent RGD from one that is
/// present but diverges — and, when the primary GD is damaged, reports how much of
/// it the RGD can recover (information qemu-img cannot provide).
fn rgd_status_line(matches: bool, rec: &vmdk::GdRecoveryReport) -> String {
    if !rec.has_rgd {
        "RGD:     absent or not applicable".to_string()
    } else if matches {
        "RGD:     OK (matches primary GD)".to_string()
    } else if rec.primary_damaged == 0 {
        "RGD:     present; differs from primary GD (primary intact)".to_string()
    } else {
        format!(
            "RGD:     primary GD damaged — {} of {} entries damaged, {} recoverable via RGD",
            rec.primary_damaged, rec.total_entries, rec.recoverable_via_rgd
        )
    }
}

fn cmd_verify(path: &std::path::Path) -> ExitCode {
    let mut reader = match open(path) {
        Ok(r) => r,
        Err(m) => return fail(m),
    };
    let info = reader.info();
    println!("File:    {}", path.display());
    println!("Format:  {} v{}", info.disk_type, info.version);
    println!("Size:    {} bytes", fmt_commas(info.virtual_disk_size));

    match reader.validate_rgd() {
        Ok(matches) => {
            let recovery = reader.grain_directory_recovery().unwrap_or_default();
            println!("{}", rgd_status_line(matches, &recovery));
        }
        Err(e) => println!("RGD:     ERROR — {e}"),
    }

    match reader.iter_allocated_grains() {
        Ok(grains) => {
            let allocated_bytes: u64 = grains.iter().map(|g| g.sector_count * 512).sum();
            println!(
                "Allocated grains: {} ({} bytes)",
                grains.len(),
                fmt_commas(allocated_bytes)
            );
        }
        Err(e) => println!("Allocation scan: ERROR — {e}"),
    }

    // Structural integrity: dangling GD/GT pointers signal truncation or tampering.
    let mut failed = false;
    match reader.check_integrity() {
        Ok(report) if report.is_ok() => {
            println!(
                "Integrity: OK ({} grains checked, no out-of-bounds pointers)",
                fmt_commas(report.grains_checked)
            );
        }
        Ok(report) => {
            failed = true;
            println!(
                "Integrity: FAIL — {} out-of-bounds grain(s), {} out-of-bounds grain table(s) \
                 of {} checked",
                report.out_of_bounds_grains,
                report.out_of_bounds_grain_tables,
                fmt_commas(report.grains_checked)
            );
        }
        Err(e) => {
            failed = true;
            println!("Integrity: ERROR — {e}");
        }
    }

    if failed {
        println!("Status:  FAILED");
        return ExitCode::FAILURE;
    }
    println!("Status:  OK");
    ExitCode::SUCCESS
}

// ── diff ──────────────────────────────────────────────────────────────────────

fn cmd_diff(a: &std::path::Path, b: &std::path::Path) -> ExitCode {
    let mut ra = match open(a) {
        Ok(r) => r,
        Err(m) => return fail(m),
    };
    let mut rb = match open(b) {
        Ok(r) => r,
        Err(m) => return fail(m),
    };
    ra.seek(SeekFrom::Start(0)).ok();
    rb.seek(SeekFrom::Start(0)).ok();

    let size_a = ra.virtual_disk_size();
    let size_b = rb.virtual_disk_size();
    if size_a != size_b {
        println!("DIFFER: virtual disk sizes differ ({size_a} vs {size_b} bytes)");
        return ExitCode::FAILURE;
    }

    let mut buf_a = vec![0u8; 65536];
    let mut buf_b = vec![0u8; 65536];
    let mut offset = 0u64;
    let mut diff_count = 0u64;
    loop {
        let na = ra.read(&mut buf_a).unwrap_or(0);
        let nb = rb.read(&mut buf_b).unwrap_or(0);
        if na == 0 && nb == 0 {
            break;
        }
        let n = na.min(nb);
        for i in 0..n {
            if buf_a[i] != buf_b[i] {
                if diff_count < 10 {
                    println!(
                        "DIFFER at offset {}: {:02x} vs {:02x}",
                        offset + i as u64,
                        buf_a[i],
                        buf_b[i]
                    );
                }
                diff_count += 1;
            }
        }
        offset += n as u64;
    }
    if diff_count == 0 {
        println!("IDENTICAL ({} bytes compared)", fmt_commas(size_a));
        ExitCode::SUCCESS
    } else {
        println!("DIFFER: {diff_count} byte(s) differ");
        ExitCode::FAILURE
    }
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match &cli.command {
        Command::Info {
            path,
            descriptor,
            chain,
        } => cmd_info(path, *descriptor, *chain),
        Command::Map { path } => cmd_map(path),
        Command::Dump {
            path,
            output,
            offset,
            length,
            hex,
            recover,
        } => cmd_dump(path, output.as_deref(), *offset, *length, *hex, *recover),
        Command::Hash { path, recover } => cmd_hash(path, *recover),
        Command::Verify { path } => cmd_verify(path),
        Command::Diff { a, b } => cmd_diff(a, b),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    fn data(name: &str) -> std::path::PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .join("vmdk/tests/data")
            .join(name)
    }

    fn is_success(code: ExitCode) -> bool {
        format!("{code:?}") == format!("{:?}", ExitCode::SUCCESS)
    }

    #[test]
    fn rgd_status_absent_when_no_rgd() {
        let rec = vmdk::GdRecoveryReport::default(); // has_rgd = false
        assert!(rgd_status_line(false, &rec).contains("absent or not applicable"));
    }

    #[test]
    fn rgd_status_ok_when_matches() {
        let rec = vmdk::GdRecoveryReport {
            has_rgd: true,
            total_entries: 4,
            primary_intact: 4,
            ..Default::default()
        };
        assert!(rgd_status_line(true, &rec).contains("OK (matches primary GD)"));
    }

    #[test]
    fn rgd_status_reports_recoverable_damage() {
        // Primary GD damaged but the RGD can recover it — the examiner must see this,
        // not a misleading "absent".
        let rec = vmdk::GdRecoveryReport {
            has_rgd: true,
            total_entries: 5,
            primary_intact: 3,
            primary_damaged: 2,
            recoverable_via_rgd: 2,
            unrecoverable: 0,
        };
        let line = rgd_status_line(false, &rec);
        assert!(line.contains("2 of 5"), "reports damaged count: {line}");
        assert!(
            line.contains("2 recoverable"),
            "reports recoverable count: {line}"
        );
    }

    #[test]
    fn rgd_status_benign_divergence_when_primary_intact() {
        // RGD present and differs, but every primary entry is usable — benign.
        let rec = vmdk::GdRecoveryReport {
            has_rgd: true,
            total_entries: 4,
            primary_intact: 4,
            ..Default::default()
        };
        let line = rgd_status_line(false, &rec);
        assert!(line.contains("primary intact"), "benign divergence: {line}");
    }

    #[test]
    fn fmt_commas_groups_thousands() {
        assert_eq!(fmt_commas(0), "0");
        assert_eq!(fmt_commas(1024), "1,024");
        assert_eq!(fmt_commas(1_048_576), "1,048,576");
    }

    #[test]
    fn each_command_succeeds_on_a_real_image() {
        let p = data("dfvfs_ext2.vmdk");
        assert!(is_success(cmd_info(&p, false, false)));
        assert!(is_success(cmd_info(&p, true, false))); // --descriptor
        assert!(is_success(cmd_info(&p, false, true))); // --chain
        assert!(is_success(cmd_map(&p)));
        assert!(is_success(cmd_hash(&p, false)));
        assert!(is_success(cmd_verify(&p)));
        assert!(is_success(cmd_dump(&p, None, 0, Some(64), false, false))); // stdout range
        assert!(is_success(cmd_dump(&p, None, 1024, Some(20), true, false))); // hex partial row
        assert!(is_success(cmd_diff(&p, &p))); // identical
    }

    #[test]
    fn map_all_sparse_succeeds() {
        assert!(is_success(cmd_map(&data("minimal.vmdk"))));
    }

    #[test]
    fn info_prints_companion_files_for_multifile_vmdk() {
        // flat.vmdk references flat-f001.vmdk → exercises the companion-files block.
        assert!(is_success(cmd_info(&data("flat.vmdk"), false, false)));
    }

    #[test]
    fn commands_fail_on_missing_or_garbage_paths() {
        let dir = tempfile::tempdir().unwrap();
        let garbage = dir.path().join("g.bin");
        std::fs::write(&garbage, b"not a vmdk").unwrap();
        for code in [
            cmd_info(&garbage, false, false),
            cmd_info(&garbage, true, false), // print_descriptor open error
            cmd_info(&garbage, false, true), // chain fallback open error
            cmd_map(&garbage),
            cmd_hash(&garbage, false),
            cmd_verify(&garbage),
            cmd_dump(&garbage, None, 0, None, false, false),
            cmd_diff(&garbage, &garbage),
        ] {
            assert!(!is_success(code), "garbage input must fail");
        }
    }

    #[test]
    fn dump_to_file_and_unwritable_path() {
        let dir = tempfile::tempdir().unwrap();
        let ok = dir.path().join("out.raw");
        assert!(is_success(cmd_dump(
            &data("minimal.vmdk"),
            Some(&ok),
            0,
            None,
            false,
            false
        )));
        assert_eq!(std::fs::metadata(&ok).unwrap().len(), 1_048_576);
        // Uncreatable output path → failure.
        let bad = Path::new("/no_such_dir_zzz/out.raw");
        assert!(!is_success(cmd_dump(
            &data("minimal.vmdk"),
            Some(bad),
            0,
            None,
            false,
            false
        )));
    }

    #[test]
    fn descriptor_absent_fails() {
        // Binary VMDK with descriptor_offset/size = 0 → empty descriptor → fail.
        let dir = tempfile::tempdir().unwrap();
        let mut b = vmdk::testutil::test_sparse_vmdk(&[0u8; 512]);
        b[28..36].copy_from_slice(&0u64.to_le_bytes());
        b[36..44].copy_from_slice(&0u64.to_le_bytes());
        let p = dir.path().join("nodesc.vmdk");
        std::fs::write(&p, &b).unwrap();
        assert!(!is_success(print_descriptor(&p)));
    }

    #[test]
    fn verify_fails_on_truncated_image() {
        let dir = tempfile::tempdir().unwrap();
        let mut d = std::fs::read(data("dfvfs_ext2.vmdk")).unwrap();
        d.truncate(d.len() / 2);
        let p = dir.path().join("trunc.vmdk");
        std::fs::write(&p, &d).unwrap();
        assert!(
            !is_success(cmd_verify(&p)),
            "truncated image fails integrity"
        );
    }

    #[test]
    fn hash_recover_succeeds_on_damaged_primary_gd() {
        // Hashing streams the whole disk through the read path, so a damaged primary GD
        // makes `hash` fail by default; with recovery it reads through the RGD and
        // completes — letting an examiner fingerprint a recovered image.
        let dir = tempfile::tempdir().unwrap();
        let mut vmdk = vmdk::testutil::test_sparse_vmdk(&[0xAB; 512]);
        let gd = 21 * 512;
        vmdk[gd..gd + 4].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
        let p = dir.path().join("corrupt.vmdk");
        std::fs::write(&p, &vmdk).unwrap();
        assert!(
            !is_success(cmd_hash(&p, false)),
            "hash without --recover must fail on the damaged primary GD"
        );
        assert!(
            is_success(cmd_hash(&p, true)),
            "hash --recover must complete via the redundant GD"
        );
    }

    #[test]
    fn dump_recover_reads_through_damaged_primary_gd() {
        // A VMDK whose primary GD entry is corrupted (out of bounds) but whose RGD and
        // grain table are intact: `dump` fails by default, but `--recover` resolves the
        // grain via the redundant grain directory and extracts the data.
        let dir = tempfile::tempdir().unwrap();
        let mut vmdk = vmdk::testutil::test_sparse_vmdk(&[0xAB; 512]);
        let gd = 21 * 512; // primary GD sector
        vmdk[gd..gd + 4].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
        let p = dir.path().join("corrupt.vmdk");
        std::fs::write(&p, &vmdk).unwrap();
        let out = dir.path().join("recovered.raw");

        // Without recovery the dangling primary pointer makes the read fail.
        assert!(
            !is_success(cmd_dump(&p, Some(&out), 0, Some(512), false, false)),
            "dump without --recover must fail on the damaged primary GD"
        );

        // With recovery the grain is read through the RGD.
        assert!(
            is_success(cmd_dump(&p, Some(&out), 0, Some(512), false, true)),
            "dump --recover must extract via the redundant GD"
        );
        let data = std::fs::read(&out).unwrap();
        assert_eq!(&data[..512], &[0xAB; 512], "recovered grain bytes");
    }

    #[test]
    fn diff_reports_size_and_content_differences() {
        let dir = tempfile::tempdir().unwrap();
        // Different virtual sizes.
        let a = dir.path().join("a.vmdk");
        let b = dir.path().join("b.vmdk");
        std::fs::write(&a, vmdk::testutil::test_sparse_vmdk(&[0u8; 512])).unwrap();
        std::fs::write(&b, std::fs::read(data("minimal.vmdk")).unwrap()).unwrap();
        assert!(!is_success(cmd_diff(&a, &b)), "differing sizes → DIFFER");
        // Same size, different content.
        let mut da = vec![0u8; 512];
        da[0] = 0xAA;
        let mut db = vec![0u8; 512];
        db[0] = 0xBB;
        let c = dir.path().join("c.vmdk");
        let e = dir.path().join("e.vmdk");
        std::fs::write(&c, vmdk::testutil::test_sparse_vmdk(&da)).unwrap();
        std::fs::write(&e, vmdk::testutil::test_sparse_vmdk(&db)).unwrap();
        assert!(!is_success(cmd_diff(&c, &e)), "differing content → DIFFER");
    }

    #[test]
    fn chain_command_on_base_and_delta() {
        let dir = tempfile::tempdir().unwrap();
        let (base, delta) = vmdk::testutil::write_chain_to_dir(dir.path(), &[0u8; 512]);
        assert!(is_success(print_chain(&base)));
        assert!(is_success(print_chain(&delta)));
    }

    /// A sparse VMDK that opens (header + GD are in bounds) but whose grain table
    /// and RGD point past EOF, so `iter_allocated_grains` and `validate_rgd` fail.
    fn opens_but_gt_and_rgd_dangle() -> Vec<u8> {
        let mut v = vec![0u8; 1024]; // header (sector 0) + GD (sector 1)
        v[0..4].copy_from_slice(&0x564D_444Bu32.to_le_bytes());
        v[4..8].copy_from_slice(&1u32.to_le_bytes());
        v[12..20].copy_from_slice(&8u64.to_le_bytes()); // capacity 8 sectors
        v[20..28].copy_from_slice(&8u64.to_le_bytes()); // grain_size 8
        v[44..48].copy_from_slice(&512u32.to_le_bytes()); // num_gtes_per_gt
        v[48..56].copy_from_slice(&9999u64.to_le_bytes()); // rgd_offset past EOF
        v[56..64].copy_from_slice(&1u64.to_le_bytes()); // gd_offset = sector 1
                                                        // GD[0] points to a grain table sector far past EOF.
        v[512..516].copy_from_slice(&9999u32.to_le_bytes());
        v
    }

    #[test]
    fn map_and_verify_fail_when_metadata_dangles() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("dangling.vmdk");
        std::fs::write(&p, opens_but_gt_and_rgd_dangle()).unwrap();
        // open succeeds, but the GT read fails → map errors.
        assert!(!is_success(cmd_map(&p)), "dangling GT → map error");
        // validate_rgd + allocation scan both error → verify fails.
        assert!(
            !is_success(cmd_verify(&p)),
            "dangling RGD/GT → verify error"
        );
    }

    #[test]
    fn diff_second_open_failure() {
        let dir = tempfile::tempdir().unwrap();
        let garbage = dir.path().join("g.bin");
        std::fs::write(&garbage, b"nope").unwrap();
        // First opens, second fails → exercises the second-open error arm.
        assert!(!is_success(cmd_diff(&data("minimal.vmdk"), &garbage)));
    }

    #[test]
    fn copy_n_and_dump_hex_stop_at_short_read() {
        // A reader shorter than the requested count → early break (read returns 0).
        let mut src = std::io::Cursor::new(vec![1u8, 2, 3, 4]);
        let mut sink: Vec<u8> = Vec::new();
        copy_n(&mut src, &mut sink, 10).expect("copy_n");
        assert_eq!(sink, vec![1, 2, 3, 4]);

        let mut src2 = std::io::Cursor::new(vec![9u8, 8, 7]);
        dump_hex(&mut src2, 0, 10).expect("dump_hex stops at short read");
    }

    #[test]
    fn copy_n_propagates_writer_error() {
        struct FailWriter;
        impl std::io::Write for FailWriter {
            fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
                Err(std::io::Error::other("boom"))
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let mut src = std::io::Cursor::new(vec![0u8; 16]);
        assert!(copy_n(&mut src, &mut FailWriter, 16).is_err());
    }
}
