use std::io::{self, BufWriter, Read, Seek, SeekFrom, Write};
use std::path::PathBuf;
use std::process;

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

fn open_or_die(path: &std::path::Path) -> VmdkFileReader {
    match VmdkFileReader::open_path(path) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("error: {e}");
            process::exit(1);
        }
    }
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

    /// List allocated (non-sparse) grain ranges as start_lba,sector_count
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
    },

    /// Compute SHA-256 and MD5 of the full virtual disk (one streaming pass)
    Hash { path: PathBuf },

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

// ── info ──────────────────────────────────────────────────────────────────────

fn cmd_info(path: &std::path::Path, descriptor: bool, chain: bool) {
    if descriptor {
        print_descriptor(path);
        return;
    }
    if chain {
        print_chain(path);
        return;
    }

    let reader = open_or_die(path);
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
                let name = d
                    .file_name()
                    .map(|n| n.to_string_lossy().into_owned())
                    .unwrap_or_else(|| d.to_string_lossy().into_owned());
                let present = if d.exists() { "" } else { "  (MISSING)" };
                println!("                   - {name}{present}");
            }
        }
    }
}

fn print_descriptor(path: &std::path::Path) {
    let reader = open_or_die(path);
    let text = reader.descriptor_text();
    if text.is_empty() {
        eprintln!("No embedded descriptor in {}", path.display());
        process::exit(1);
    }
    print!("{text}");
}

fn print_chain(path: &std::path::Path) {
    match VmdkChainReader::open(path) {
        Ok(chain) => {
            println!("Chain depth:  {} layer(s)", chain.depth());
            println!(
                "Virtual size: {} bytes",
                fmt_commas(chain.virtual_disk_size())
            );
        }
        Err(e) => {
            // Fall back to single-image view, reporting parentCID if present.
            match VmdkFileReader::open_path(path) {
                Ok(r) => {
                    let info = r.info();
                    println!("Chain depth:  1 layer");
                    println!("Virtual size: {} bytes", fmt_commas(info.virtual_disk_size));
                    if info.parent_cid != 0xffff_ffff {
                        println!(
                            "Parent CID:   {:08x} (parent file not found: {e})",
                            info.parent_cid
                        );
                    } else {
                        println!("No parent (base image)");
                    }
                }
                Err(e2) => {
                    eprintln!("error: {e2}");
                    process::exit(1);
                }
            }
        }
    }
}

// ── map ───────────────────────────────────────────────────────────────────────

fn cmd_map(path: &std::path::Path) {
    let mut reader = open_or_die(path);
    let grains = reader.iter_allocated_grains().unwrap_or_else(|e| {
        eprintln!("error: {e}");
        process::exit(1);
    });
    if grains.is_empty() {
        println!("# No allocated grains (all-sparse)");
        return;
    }
    println!("# start_lba,sector_count");
    for g in &grains {
        println!("{},{}", g.start_lba, g.sector_count);
    }
    eprintln!("{} allocated grain(s)", grains.len());
}

// ── dump ──────────────────────────────────────────────────────────────────────

fn cmd_dump(
    path: &std::path::Path,
    output: Option<&std::path::Path>,
    offset: u64,
    length: Option<u64>,
    hex: bool,
) {
    let mut reader = open_or_die(path);
    let disk_size = reader.virtual_disk_size();
    let end = length.map_or(disk_size, |len| offset.saturating_add(len).min(disk_size));
    let to_output = end.saturating_sub(offset);

    reader.seek(SeekFrom::Start(offset)).unwrap_or_else(|e| {
        eprintln!("seek error: {e}");
        process::exit(1);
    });

    if hex {
        dump_hex(&mut reader, offset, to_output);
        return;
    }

    // Raw byte output to file or stdout.
    if let Some(out_path) = output {
        let file = std::fs::File::create(out_path).unwrap_or_else(|e| {
            eprintln!("cannot create {}: {e}", out_path.display());
            process::exit(1);
        });
        let mut w = BufWriter::new(file);
        copy_n(&mut reader, &mut w, to_output);
        w.flush().ok();
        eprintln!(
            "Wrote {} bytes to {}",
            fmt_commas(to_output),
            out_path.display()
        );
    } else {
        let stdout = io::stdout();
        let mut w = BufWriter::new(stdout.lock());
        copy_n(&mut reader, &mut w, to_output);
        w.flush().ok();
    }
}

/// Copy exactly `n` bytes from `reader` to `w`.
fn copy_n<R: Read, W: Write>(reader: &mut R, w: &mut W, n: u64) {
    let mut remaining = n;
    let mut buf = vec![0u8; 65536];
    while remaining > 0 {
        let want = (buf.len() as u64).min(remaining) as usize;
        let got = reader.read(&mut buf[..want]).unwrap_or_else(|e| {
            eprintln!("read error: {e}");
            process::exit(1);
        });
        if got == 0 {
            break;
        }
        w.write_all(&buf[..got]).unwrap_or_else(|e| {
            eprintln!("write error: {e}");
            process::exit(1);
        });
        remaining -= got as u64;
    }
}

fn dump_hex<R: Read>(reader: &mut R, start_offset: u64, length: u64) {
    let stdout = io::stdout();
    let mut w = BufWriter::new(stdout.lock());
    let mut remaining = length;
    let mut pos = start_offset;
    let mut buf = [0u8; 16];
    while remaining > 0 {
        let want = (16u64.min(remaining)) as usize;
        let n = reader.read(&mut buf[..want]).unwrap_or_else(|e| {
            eprintln!("read error: {e}");
            process::exit(1);
        });
        if n == 0 {
            break;
        }
        let _ = write!(w, "{pos:08x}  ");
        for i in 0..16 {
            if i < n {
                let _ = write!(w, "{:02x} ", buf[i]);
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
}

// ── hash ──────────────────────────────────────────────────────────────────────

fn cmd_hash(path: &std::path::Path) {
    let mut reader = open_or_die(path);
    reader.seek(SeekFrom::Start(0)).ok();
    let digest = reader.hash().unwrap_or_else(|e| {
        eprintln!("error: {e}");
        process::exit(1);
    });
    println!("SHA-256: {}", digest.sha256);
    println!("MD5:     {}", digest.md5);
    println!("File:    {}", path.display());
}

// ── verify ────────────────────────────────────────────────────────────────────

fn cmd_verify(path: &std::path::Path) {
    let mut reader = open_or_die(path);
    let info = reader.info();
    println!("File:    {}", path.display());
    println!("Format:  {} v{}", info.disk_type, info.version);
    println!("Size:    {} bytes", fmt_commas(info.virtual_disk_size));

    match reader.validate_rgd() {
        Ok(true) => println!("RGD:     OK (matches primary GD)"),
        Ok(false) => println!("RGD:     absent or not applicable"),
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
        process::exit(1);
    }
    println!("Status:  OK");
}

// ── diff ──────────────────────────────────────────────────────────────────────

fn cmd_diff(a: &std::path::Path, b: &std::path::Path) {
    let mut ra = open_or_die(a);
    let mut rb = open_or_die(b);
    ra.seek(SeekFrom::Start(0)).ok();
    rb.seek(SeekFrom::Start(0)).ok();

    let size_a = ra.virtual_disk_size();
    let size_b = rb.virtual_disk_size();
    if size_a != size_b {
        println!("DIFFER: virtual disk sizes differ ({size_a} vs {size_b} bytes)");
        process::exit(1);
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
    } else {
        println!("DIFFER: {diff_count} byte(s) differ");
        process::exit(1);
    }
}

fn main() {
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
        } => {
            cmd_dump(path, output.as_deref(), *offset, *length, *hex);
        }
        Command::Hash { path } => cmd_hash(path),
        Command::Verify { path } => cmd_verify(path),
        Command::Diff { a, b } => cmd_diff(a, b),
    }
}
