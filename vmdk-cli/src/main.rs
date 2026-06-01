use std::fs::File;
use std::path::PathBuf;
use std::process;

use clap::{Parser, Subcommand};
use vmdk::VmdkReader;

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

#[derive(Parser)]
#[command(name = "vmdk", version, about = "CLI tool for VMDK disk images")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Display image metadata
    Info { path: PathBuf },
}

fn main() {
    let cli = Cli::parse();
    match cli.command {
        Command::Info { path } => {
            let file = match File::open(&path) {
                Ok(f) => f,
                Err(e) => {
                    eprintln!("error: {e}");
                    process::exit(1);
                }
            };
            let reader = match VmdkReader::open(file) {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("error: {e}");
                    process::exit(1);
                }
            };

            let size = reader.virtual_disk_size();
            let disk_type = reader.disk_type().to_owned();
            let mib = size as f64 / (1024.0 * 1024.0);

            let file_name = path
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default();

            println!("File:              {file_name}");
            println!("Format:            VMDK v1 ({disk_type})");
            println!(
                "Virtual disk size: {} bytes ({mib:.2} MiB)",
                fmt_commas(size)
            );
            println!("Sector size:       512 bytes");
        }
    }
}
