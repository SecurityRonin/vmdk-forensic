# vmdk-forensic

**Read VMware VMDK disk images others give up on, then audit them for tampering.** Two crates in one workspace: the [`vmdk-core`](https://crates.io/crates/vmdk-core) reader (imported as `vmdk`) presents the virtual disk as a plain `Read + Seek` byte stream — and **recovers data from a damaged disk through the redundant grain directory that `qemu-img` and `libvmdk` throw away** — while the [`vmdk-forensic`](https://crates.io/crates/vmdk-forensic) analyzer turns the structure into severity-graded, evidence-grade findings.

## The two crates

| Crate | Role | Import | `cargo add` |
|---|---|---|---|
| [`vmdk-core`](https://crates.io/crates/vmdk-core) | Read-only VMDK reader: decoded virtual-sector `Read + Seek`, RGD-fallback recovery, `ddb` provenance | `use vmdk::…` | `cargo add vmdk-core` |
| [`vmdk-forensic`](https://crates.io/crates/vmdk-forensic) | Integrity analyzer → canonical `forensicnomicon::report::Finding` (re-exports the reader) | `use vmdk_forensic::…` | `cargo add vmdk-forensic` |

## Quick start

```rust
use vmdk::VmdkReader;
use std::io::{Read, Seek, SeekFrom};

// Open any `Read + Seek` source — a File, a Cursor, another container reader.
let mut disk = VmdkReader::open(std::fs::File::open("disk.vmdk")?)?;

println!("virtual size: {} bytes", disk.virtual_disk_size());

// Read decoded virtual sectors like any byte stream — sparse/compressed grains
// are decompressed and zero-filled transparently.
let mut first_mib = vec![0u8; 1 << 20];
disk.seek(SeekFrom::Start(0))?;
disk.read_exact(&mut first_mib)?;
# Ok::<(), Box<dyn std::error::Error>>(())
```

## What makes this different from `qemu-img` and `libvmdk`

Most VMDK readers answer one question: "give me the bytes." `vmdk` answers the questions a digital forensics examiner actually needs — and reads disks the others give up on: redundant-GD fallback recovery behind a damaged primary grain directory, redundant-GD content validation, structural integrity scans for dangling GD/GT/grain pointers, full `ddb.*` disk-database provenance (adapter, geometry, UUID, tools/HW version), header provenance (unclean-shutdown flag, FTP-ASCII-mangling check), Change Block Tracking reference, `longContentID` resolution, Raw Device Mapping extent enumeration, streaming SHA-256 + MD5 of the virtual disk — all in pure Rust with zero `unsafe` and no C library.

## Forensic recovery

VMware writes the grain tables **twice** — the grain directory (GD) and a redundant copy (RGD) point to separate physical copies. `qemu-img` and `libvmdk` read only the primary and fail when it is damaged. `vmdk` uses the redundant copy to keep reading:

```rust
use vmdk::VmdkReader;
use std::io::Read;

let mut disk = VmdkReader::open(std::fs::File::open("damaged.vmdk")?)?;

// Opt in to recovery, then read normally — damaged pointers resolve through the RGD.
disk.enable_rgd_fallback();
let mut buf = vec![0u8; 1 << 20];
let _ = disk.read(&mut buf);
println!("recovered {} grain(s) via the RGD", disk.rgd_recovery_count());
# Ok::<(), Box<dyn std::error::Error>>(())
```

Recovery is opt-in and never changes a healthy read; without it a dangling pointer simply errors (the safe default).

## Security

`vmdk` is built to run on untrusted, potentially crafted disk images: no panics on malicious input (bounds-checked header-derived allocations, clamped reads, capped compressed-grain sizes), allocation-amplification hardened (`numGTEsPerGT` capped at the spec value of 512), zero `unsafe` (`unsafe_code = "forbid"` workspace-wide), and four `cargo fuzz` targets covering the open path, full read surface, RGD recovery, and the forensic pipeline. COWD and seSparse output is cross-validated **byte-for-byte against `qemu-img convert -O raw`**.

See [Validation](validation.md) and [Implementation Notes](implementation-notes.md) for the detailed evidence, and the project [README](https://github.com/SecurityRonin/vmdk-forensic) for the full CLI, format matrix, and API reference.

---

[Privacy Policy](privacy.md) · [Terms of Service](terms.md) · © 2026 Security Ronin Ltd
