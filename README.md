[![Crates.io](https://img.shields.io/crates/v/vmdk.svg)](https://crates.io/crates/vmdk)
[![Docs.rs](https://img.shields.io/docsrs/vmdk)](https://docs.rs/vmdk)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![CI](https://github.com/SecurityRonin/vmdk/actions/workflows/ci.yml/badge.svg)](https://github.com/SecurityRonin/vmdk/actions/workflows/ci.yml)
[![Sponsor](https://img.shields.io/badge/sponsor-h4x0r-ea4aaa?logo=github-sponsors)](https://github.com/sponsors/h4x0r)

**Pure-Rust read-only VMware VMDK sparse disk image reader.**

Decodes monolithic sparse VMDK containers (VMware Workstation, Fusion, and ESXi exported images) and exposes a `Read + Seek` interface over the virtual sector stream. Navigates the two-level grain directory / grain table structure to resolve virtual offsets to raw grain data. Zero unsafe code, no C bindings.

```toml
[dependencies]
vmdk = "0.1"
```

---

## Usage

### Open a VMDK and read sectors

```rust
use vmdk::VmdkReader;
use std::io::{Read, Seek, SeekFrom};

let mut reader = VmdkReader::open("disk.vmdk")?;

println!("Virtual disk size: {} bytes", reader.virtual_disk_size());

// Read the first sector
let mut sector = [0u8; 512];
reader.read_exact(&mut sector)?;

// Seek anywhere — O(1) via two-level grain table
reader.seek(SeekFrom::Start(1_048_576))?;
```

### Pass to a filesystem crate

`VmdkReader` implements `Read + Seek`, so it drops directly into any crate that accepts a reader:

```rust
use vmdk::VmdkReader;

let reader = VmdkReader::open("disk.vmdk")?;
// e.g. ext4fs_forensic::Filesystem::open(reader)?;
```

---

## Supported formats

| Format | Supported |
|--------|:---------:|
| Monolithic sparse (`monolithicSparse`) | ✓ |
| VMware Workstation / Fusion native | ✓ |
| ESXi-exported sparse | ✓ |
| Flat extent (`monolithicFlat`) | planned |
| Stream-optimised (`streamOptimized`) | planned |

Read-only. Flat extents and stream-optimised VMDKs are not yet supported.

---

## Related crates

| Crate | Format | Notes |
|-------|--------|-------|
| [`ewf`](https://github.com/SecurityRonin/ewf) | E01 / EWF / Ex01 | Dominant professional forensic acquisition format |
| [`aff4`](https://github.com/SecurityRonin/aff4) | AFF4 v1 | Evimetry / aff4-imager forensic disk images |
| [`vhdx`](https://github.com/SecurityRonin/vhdx) | Microsoft VHDX | Hyper-V, Windows 8+, WSL2, Azure disk container |
| [`vhd`](https://github.com/SecurityRonin/vhd) | Legacy VHD | Virtual PC / Hyper-V Generation-1 format |
| [`qcow2`](https://github.com/SecurityRonin/qcow2) | QCOW2 v2/v3 | QEMU / KVM / libvirt disk images |
| [`dd`](https://github.com/SecurityRonin/dd) | Raw / flat | dd, dcfldd, dc3dd, and FTK Imager raw output |
| [`ewf-forensic`](https://github.com/SecurityRonin/ewf-forensic) | E01 analyser | Structural integrity audit and repair for E01 images |
| [`vhdx-forensic`](https://github.com/SecurityRonin/vhdx-forensic) | VHDX analyser | Forensic integrity analyser for VHDX containers |

---

[Privacy Policy](https://securityronin.github.io/vmdk/privacy/) · [Terms of Service](https://securityronin.github.io/vmdk/terms/) · © 2026 Security Ronin Ltd
