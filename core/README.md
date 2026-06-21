# vmdk-core

[![vmdk-core](https://img.shields.io/crates/v/vmdk-core.svg?label=vmdk-core)](https://crates.io/crates/vmdk-core)
[![vmdk-forensic](https://img.shields.io/crates/v/vmdk-forensic.svg?label=vmdk-forensic)](https://crates.io/crates/vmdk-forensic)
[![docs.rs](https://img.shields.io/docsrs/vmdk-core)](https://docs.rs/vmdk-core)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache--2.0-blue.svg)](LICENSE)
[![CI](https://github.com/SecurityRonin/vmdk-forensic/actions/workflows/ci.yml/badge.svg)](https://github.com/SecurityRonin/vmdk-forensic/actions)
[![Sponsor](https://img.shields.io/badge/sponsor-h4x0r-ea4aaa?logo=github-sponsors)](https://github.com/sponsors/h4x0r)

**Pure-Rust, read-only VMware VMDK reader — the virtual disk as a plain `Read + Seek` byte stream.** Decodes sparse, stream-optimized, flat, COWD, and seSparse extents transparently, and **recovers data from a damaged disk through the redundant grain directory that `qemu-img` and `libvmdk` throw away**.

The crate is published as `vmdk-core` and imported as `vmdk`.

```bash
cargo add vmdk-core
```

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

For path-based images with companion files — `monolithicFlat`, the
`twoGbMaxExtent*` split sets, raw-device maps — use `VmdkFileReader::open_path`,
which locates and opens the extent files for you. For snapshot/delta trees, use
`VmdkChainReader::open`, which layers a delta on its parent chain.

## Formats

Every VMDK `createType` and extent type in the VMware Virtual Disk Format spec
(cross-checked against QEMU `block/vmdk.c` and `libvmdk`):

| `createType` | Notes |
|---|---|
| `monolithicSparse`, `streamOptimized` | header v1/v2/v3; DEFLATE grains; `GD_AT_END` footer |
| `monolithicFlat`, `vmfs`, `vmfsPreallocated`, `vmfsEagerZeroedThick` | preallocated flat extents |
| `twoGbMaxExtentSparse`, `twoGbMaxExtentFlat` | split 2 GB extent sets |
| `vmfsSparse`, `vmfsThin` | ESXi COWD copy-on-write sparse |
| `seSparse` | vSphere 6.5+ space-efficient sparse (nibble-typed, bit-rotated grains) |
| `vmfsRaw`, `vmfsRawDeviceMap`, `vmfsPassthroughRawDeviceMap`, `fullDevice`, `partitionedDevice` | device / raw-LUN maps |
| `custom` | arbitrary extent mix, routed by extent type |

Extent types: `FLAT`, `VMFS`, `VMFSRAW`, `VMFSRDM`, `ZERO`, `SPARSE`,
`VMFSSPARSE`, `SESPARSE`; access `RW` / `RDONLY` / `NOACCESS`. `ZERO` and
`NOACCESS` regions read as zeros without touching disk.

## Forensic recovery

VMware writes the grain tables **twice** — the grain directory (GD) and a
redundant copy (RGD) point to separate physical copies. `qemu-img` and `libvmdk`
read only the primary and fail when it is damaged. `vmdk` uses the redundant copy
to keep reading:

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

Recovery is opt-in and never changes a healthy read; without it a dangling pointer
simply errors (the safe default). To *audit* a damaged image — how much of the
primary grain directory the RGD can recover, plus tamper/anomaly detection — use
the companion [`vmdk-forensic`](https://crates.io/crates/vmdk-forensic) crate.

## Forensic metadata

The text descriptor carries provenance that other readers parse and then throw
away. `vmdk` surfaces all of it:

```rust
use vmdk::VmdkReader;

let mut disk = VmdkReader::open(std::fs::File::open("disk.vmdk")?)?;

let ddb = disk.disk_database();                 // ddb.* disk database
println!("adapter:   {:?}", ddb.adapter_type);  // ide / lsilogic / pvscsi …
println!("geometry:  {:?}", ddb.geometry);      // CHS cylinders/heads/sectors
println!("disk UUID: {:?}", ddb.uuid);
println!("HW / tools: {:?} / {:?}", ddb.virtual_hw_version, ddb.tools_version);

println!("CBT file:   {:?}", disk.change_track_path());       // -ctk.vmdk reference
println!("content ID: {}",  disk.effective_content_id());     // resolves longContentID
# Ok::<(), Box<dyn std::error::Error>>(())
```

## API highlights

| Method | Purpose |
|---|---|
| `VmdkReader::open(reader)` | open any `Read + Seek` source |
| `VmdkFileReader::open_path(path)` | open path-based images (flat / multi-extent / device maps) |
| `VmdkFileReader::extent_dependencies(path)` | list companion extent files before opening |
| `VmdkChainReader::open(path)` | layer a delta on its parent snapshot chain |
| `read` / `seek` (`std::io`) | decoded virtual-sector byte stream |
| `info()` → `VmdkInfo` | version, CID, geometry, compression, descriptor, disk database |
| `is_allocated(lba)` / `iter_allocated_grains()` | sparse-map queries |
| `hash()` → `VmdkDigest` | streaming SHA-256 + MD5 of the virtual disk |
| `disk_database()` / `change_track_path()` / `effective_content_id()` | forensic metadata |
| `enable_rgd_fallback()` / `rgd_recovery_count()` | opt-in RGD recovery |

`serde` derives on the public report types are available behind the `serde` feature.

## Trust but verify

`vmdk-core` is built to run on untrusted, potentially crafted disk images:

- **Panic-free on malicious input** — every allocation derived from a header
  field is bounds-checked, reads are clamped, and compressed-grain sizes are
  capped. `numGTEsPerGT` is capped at the spec value (512), so a crafted header
  can't drive a multi-gigabyte grain-table allocation.
- **Zero `unsafe`** — `unsafe_code = "forbid"` workspace-wide; no C dependency.
- **Fuzz-tested** — `cargo fuzz` targets cover the open path, the read surface,
  and the RGD recovery paths; run in CI on every change.
- **Validated against real artifacts** — a real VMware-written `monolithicSparse`
  image (`dfvfs_ext2.vmdk`, from log2timeline/dfvfs, Apache-2.0) is read
  **byte-for-byte against `qemu-img convert -O raw`**, and COWD / seSparse output
  is cross-validated against `qemu-img`'s independent reader, so the synthetic
  fixtures and the reader cannot share a blind spot. Oracles, corpora, and
  evidence tiers are documented at
  [securityronin.github.io/vmdk-forensic/validation](https://securityronin.github.io/vmdk-forensic/validation/).

## Reader vs. analyzer

This crate is the reader half of a two-crate workspace (the same split as
`vhdx`/`vhdx-forensic` and `ewf`/`ewf-forensic`):

- **`vmdk-core`** — this crate, imported as `vmdk`. The lean `Read + Seek`
  reader, including the opt-in RGD-fallback recovery read path.
- [`vmdk-forensic`](https://crates.io/crates/vmdk-forensic) — the analyzer. Audit
  an image before trusting it: RGD adjudication, dangling-pointer scan, recovery
  triage, and header provenance, emitted as canonical
  [`forensicnomicon::report::Finding`](https://crates.io/crates/forensicnomicon)s.
  It re-exports `vmdk::VmdkReader`, so one dependency covers read + analysis.

---

[Privacy Policy](https://securityronin.github.io/vmdk-forensic/privacy/) · [Terms of Service](https://securityronin.github.io/vmdk-forensic/terms/) · © 2026 Security Ronin Ltd
