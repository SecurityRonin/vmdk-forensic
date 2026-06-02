[![Crates.io](https://img.shields.io/crates/v/vmdk.svg)](https://crates.io/crates/vmdk)
[![docs.rs](https://img.shields.io/docsrs/vmdk)](https://docs.rs/vmdk)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![CI](https://github.com/SecurityRonin/vmdk/actions/workflows/ci.yml/badge.svg)](https://github.com/SecurityRonin/vmdk/actions)
[![Sponsor](https://img.shields.io/badge/sponsor-h4x0r-ea4aaa?logo=github-sponsors)](https://github.com/sponsors/h4x0r)

**Pure-Rust read-only VMware VMDK disk image reader — `Read + Seek` over the virtual sector stream.**

## Install

### CLI

```bash
cargo install vmdk-cli
```

### Rust library

```toml
[dependencies]
vmdk = "0.1"
```

## CLI usage

```bash
vmdk info disk.vmdk          # Format, virtual disk size, sector size
```

## Library quick start

```rust
use vmdk::VmdkReader;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};

// Single-file VMDKs (monolithicSparse, streamOptimized)
let file = File::open("disk.vmdk")?;
let mut reader = VmdkReader::open(file)?;

println!("Disk type:         {}", reader.disk_type());         // "monolithicSparse"
println!("Virtual disk size: {}", reader.virtual_disk_size()); // bytes

// Read the first sector
let mut sector = [0u8; 512];
reader.read_exact(&mut sector)?;

// Seek anywhere — O(1) via two-level grain table
reader.seek(SeekFrom::Start(1_048_576))?;
```

`VmdkReader<R>` is generic over any `R: Read + Seek`, so it works with `File`,
`Cursor<Vec<u8>>`, network streams, or any custom reader:

```rust
// In-memory (tests, embedded use)
use std::io::Cursor;
let reader = VmdkReader::open(Cursor::new(bytes))?;
```

Multi-file VMDKs (flat extents) require a filesystem path:

```rust
// twoGbMaxExtentFlat — descriptor + companion extent files
let reader = VmdkReader::open_path(std::path::Path::new("disk.vmdk"))?;
```

`VmdkReader` implements `Read + Seek`, so it plugs directly into filesystem crates:

```rust
// e.g. ext4::Filesystem::open(reader)?;
// e.g. ntfs::Ntfs::new(&mut reader)?;
```

## Library features

- **monolithicSparse** — VMware Workstation / Fusion / ESXi sparse images; two-level GD/GT grain lookup
- **streamOptimized** — sparse and compressed (zlib / RFC 1950) grains; `GrainMarker` decoded at read time
- **twoGbMaxExtentFlat / monolithicFlat** — multi-file flat extent descriptors; opens via `open_path`
- **twoGbMaxExtentSparse** — multi-file sparse extent descriptors; each extent is an independent binary VMDK with its own GD/GT
- **O(1) virtual offset resolution** — GD loaded at open, one GT read + one seek per grain access
- **Graceful rejection** — unknown formats and bad magic return `Err`, never panic
- **Fuzz-hardened** — proptest + cargo-fuzz; all corpus inputs verified not to panic
- **Zero unsafe code** — `#![forbid(unsafe_code)]`
- **MIT licensed** — no GPL, safe for proprietary DFIR tooling

## Format support

| Format | Status |
|--------|:------:|
| `monolithicSparse` (v1) | ✓ |
| `streamOptimized` (v3, all-sparse) | ✓ |
| `streamOptimized` (v3, compressed grains) | ✓ |
| `twoGbMaxExtentFlat` | ✓ (`open_path` only) |
| `monolithicFlat` | ✓ (`open_path` only) |
| `twoGbMaxExtentSparse` | ✓ (`open_path` only) |

`VmdkReader::open` and `open_path` return `Err` (never panic) on unrecognised inputs.

## Format overview

```
byte 0        SparseExtentHeader (512 bytes) — magic, version, geometry, GD offset
sector 1–20   embedded text descriptor — createType, CID, extent map
sector 21–25  redundant grain directory (ignored)
sector 26     primary grain directory — one u32 per grain table
sector 27+    grain tables — one u32 (file sector offset) per grain
sector 128+   grain data — raw 64 KiB blocks
```

Virtual offset resolution is O(1): one GD lookup (in-memory `Vec<u32>`) + one GT read
(4 bytes from file) + one grain data seek.

## Testing

- **59 tests** across unit, integration real-images, and integration synthetic suites
- Validated against real VMware-generated images from the [dfvfs](https://github.com/log2timeline/dfvfs)
  and [plaso](https://github.com/log2timeline/plaso) forensics test corpora
- External validation against pWnOS v2.0 (VulnHub, VMware Workstation 7, 40 GiB sparse image)
  and Metasploitable3 Windows 2008 (Rapid7, VMware Workstation 13, `twoGbMaxExtentSparse`)

See [docs/validation.md](docs/validation.md) for detailed results and reproduction steps.

## Related crates

### Container readers

| Crate | Format | Notes |
|-------|--------|-------|
| [`ewf`](https://github.com/SecurityRonin/ewf) | E01 / EWF / Ex01 | Dominant professional forensic acquisition format |
| [`aff4`](https://github.com/SecurityRonin/aff4) | AFF4 v1 | Evimetry / aff4-imager forensic disk images with Map streams |
| [`vhdx`](https://github.com/SecurityRonin/vhdx) | Microsoft VHDX | Hyper-V, Windows 8+, WSL2, Azure disk container |
| [`vhd`](https://github.com/SecurityRonin/vhd) | Legacy VHD | Virtual PC / Hyper-V Generation-1 fixed and dynamic disk images |
| [`qcow2`](https://github.com/SecurityRonin/qcow2) | QCOW2 v2/v3 | QEMU / KVM / libvirt disk images |
| [`ufed`](https://github.com/SecurityRonin/ufed) | Cellebrite UFED | Physical mobile device dumps with UFD XML segment mapping |
| [`dd`](https://github.com/SecurityRonin/dd) | Raw / flat / gz | dd, dcfldd, and gzip-wrapped raw images |
| [`iso9660-forensic`](https://github.com/SecurityRonin/iso9660-forensic) | ISO 9660 | Optical disc images: multi-session, UDF bridge, Rock Ridge, Joliet, El Torito |
| [`dmg`](https://github.com/SecurityRonin/dmg) | Apple DMG / UDIF | macOS disk images with koly trailer, mish block tables, zlib decompression |
| [`dar`](https://github.com/SecurityRonin/dar) | DAR archive | Disk ARchiver archives with catalog index and CRC32 validation |

### Forensic analysers

| Crate | Format | Notes |
|-------|--------|-------|
| [`ewf-forensic`](https://github.com/SecurityRonin/ewf-forensic) | E01 | Structural integrity audit, Adler-32 / MD5 hash verification, and in-memory repair |
| [`vhdx-forensic`](https://github.com/SecurityRonin/vhdx-forensic) | VHDX | Forensic integrity analyser and in-memory repair tool for VHDX containers |

---

[Privacy Policy](https://securityronin.github.io/vmdk/privacy/) · [Terms of Service](https://securityronin.github.io/vmdk/terms/) · © 2026 Security Ronin Ltd
