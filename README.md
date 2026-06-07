# vmdk

[![Crates.io](https://img.shields.io/crates/v/vmdk.svg)](https://crates.io/crates/vmdk)
[![docs.rs](https://img.shields.io/docsrs/vmdk)](https://docs.rs/vmdk)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![CI](https://github.com/SecurityRonin/vmdk/actions/workflows/ci.yml/badge.svg)](https://github.com/SecurityRonin/vmdk/actions)
[![Sponsor](https://img.shields.io/badge/sponsor-h4x0r-ea4aaa?logo=github-sponsors)](https://github.com/sponsors/h4x0r)

Pure-Rust, read-only reader for VMware VMDK disk images. Presents the virtual disk as a plain `Read + Seek` byte stream — and, uniquely, **recovers data from a damaged disk through the redundant grain directory that `qemu-img` and `libvmdk` throw away**, while surfacing the forensic metadata they discard.

## Command-line tool

```console
$ cargo run --bin vmdk -- info disk.vmdk
```

```text
File:              disk.vmdk
Format:            VMDK v1 (monolithicSparse)
Virtual disk size: 4,194,304 bytes (4.00 MiB)
Sector size:       512 bytes
Sectors:           8,192
Grain size:        128 sectors (64 KiB)
Compressed:        no
CID:               dc80b6c7
Descriptor:        17 lines (see --descriptor)
```

Six subcommands — `info`, `map`, `dump`, `hash`, `verify`, `diff` — fold the
common `qemu-img` workflows into one binary:

```console
$ vmdk verify disk.vmdk
RGD:     OK (matches primary GD)
Allocated grains: 3 (196,608 bytes)
Integrity: OK (3 grains checked, no out-of-bounds pointers)
Status:  OK
```

`dump`, `hash`, `map`, and `verify` accept `--recover`: when the primary grain
directory is damaged, the read is resolved through the redundant grain directory
instead, so data behind the corruption is still extractable.

```console
$ vmdk verify damaged.vmdk            # primary GD is corrupt
Integrity: FAIL — 1 out-of-bounds grain table(s) … Status: FAILED

$ vmdk verify --recover damaged.vmdk  # resolve through the redundant GD
Integrity: OK (1 grains checked, no out-of-bounds pointers)
Recovered 1 grain(s) via the redundant grain directory
Status:  OK
```

`dump` writes raw virtual-disk bytes to stdout or a file (`-o`), a byte range
(`--offset` / `--length`), or a hex view (`--hex`) — pipe it straight into a
filesystem tool (NTFS, ext4, …) to read the guest's files. `verify` exits `0`
when clean and `1` on corruption, so it drops into a triage pipeline.

## Rust library

```toml
[dependencies]
vmdk = "0.4"
```

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

For path-based images with companion files — `monolithicFlat`, the
`twoGbMaxExtent*` split sets, raw-device maps — use `VmdkFileReader::open_path`,
which locates and opens the extent files for you. For snapshot/delta trees, use
`VmdkChainReader::open`, which layers a delta on its parent chain.

## What makes this different from `qemu-img` and `libvmdk`

Most VMDK readers answer one question: "give me the bytes." `vmdk` answers the
questions a digital forensics examiner actually needs — and reads disks the
others give up on:

| Capability | qemu-img / libvmdk | vmdk |
|---|---|---|
| Sparse / streamOptimized / flat read | ✅ | ✅ |
| COWD (`vmfsSparse`/`vmfsThin`) + seSparse (VMFS6) | partial | ✅ |
| Snapshot / delta chain traversal | ✅ | ✅ |
| **Recover data behind a damaged primary GD** (redundant-GD fallback) | ✗ | ✅ |
| **Recover an individual lost grain-table entry** from the redundant copy | ✗ | ✅ |
| Redundant-GD validation (grain-table *contents*, not pointers) | ✗ | ✅ via `vmdk-forensic` |
| Structural integrity scan (dangling GD/GT/grain pointers) | ✗ | ✅ via `vmdk-forensic` |
| `ddb.*` disk database (adapter, geometry, UUID, tools/HW version) | discarded | ✅ |
| Header provenance — unclean-shutdown flag, FTP-ASCII-mangling check | ✗ | ✅ via `vmdk-forensic` |
| Change Block Tracking (`-ctk`) reference | ✗ | ✅ |
| `longContentID` resolution (the `CID == 0xFFFFFFFE` sentinel) | ✗ | ✅ |
| Raw Device Mapping (`VMFSRDM`) extent enumeration | ✗ | ✅ |
| Streaming SHA-256 + MD5 of the virtual disk | ✗ | ✅ |
| Adversarial-input hardening + fuzz testing | ✗ | ✅ |
| Pure Rust, zero `unsafe`, no C library | ✗ | ✅ |

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
simply errors (the safe default). To *triage* a damaged image first — how much of
the primary grain directory the RGD can recover, plus tamper/anomaly detection — use
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

Header provenance (unclean-shutdown flag, FTP-ASCII-mangling check) and the integrity
/ anomaly analysis live in the [`vmdk-forensic`](https://crates.io/crates/vmdk-forensic)
companion crate — see [Related](#related).

## API highlights

| Method | Purpose |
|---|---|
| `VmdkReader::open(reader)` | open any `Read + Seek` source |
| `VmdkFileReader::open_path(path)` | open path-based images (flat / multi-extent / device maps) |
| `VmdkChainReader::open(path)` | layer a delta on its parent snapshot chain |
| `read` / `seek` (`std::io`) | decoded virtual-sector byte stream |
| `info()` → `VmdkInfo` | version, CID, geometry, compression, descriptor, disk database |
| `is_allocated(lba)` / `iter_allocated_grains()` | sparse-map queries |
| `hash()` → `VmdkDigest` | streaming SHA-256 + MD5 of the virtual disk |
| `validate_rgd()` / `check_integrity()` | redundant-GD + structural integrity |
| `grain_directory_recovery()` / `enable_rgd_fallback()` / `rgd_recovery_count()` | RGD recovery |
| `disk_database()` / `header_provenance()` / `change_track_path()` / `effective_content_id()` | forensic metadata |

`serde` derives on the public report types are available behind the `serde` feature.

## Security

`vmdk` is built to run on untrusted, potentially crafted disk images:

- **No panics on malicious input** — every allocation derived from header fields
  is bounds-checked; reads are clamped; compressed-grain sizes are capped.
- **Allocation-amplification hardened** — `numGTEsPerGT` is capped at the spec
  value (512), matching QEMU, so a crafted header can't drive a multi-gigabyte
  grain-table allocation.
- **Zero `unsafe`** — `unsafe_code = "forbid"` workspace-wide; no C dependency.
- **Fuzz-tested** — three `cargo fuzz` targets cover the open path, the full
  read/scan/integrity surface, and the RGD recovery paths; run in CI on every
  change and deeper on a schedule.

Hardened further in **0.6.0** (all on the untrusted-input path):

- **Descriptor path-traversal sandboxed** — extent and `parentFileNameHint`
  paths are confined to the image directory; an absolute or `..`-climbing path
  is refused, so a crafted descriptor can't read arbitrary host files.
- **Decompression-bomb bounded** — a compressed grain is decoded only up to its
  grain size and refused if it expands further, so a few-KB payload can't
  amplify into a multi-megabyte allocation.
- **Snapshot-chain reads grain-clamped** — a sparse grain can no longer
  zero-mask an allocated grain that follows it within the same read.
- **Mixed-extent descriptors rejected** — a `custom` image listing both flat and
  sparse extents fails loud instead of silently dropping the sparse ones.

```bash
# Requires nightly Rust and cargo-fuzz
rustup install nightly
cargo install cargo-fuzz

cargo +nightly fuzz run fuzz_open
cargo +nightly fuzz run fuzz_read
cargo +nightly fuzz run fuzz_recover
```

## Testing

280+ tests (unit + integration) covering every public API, every format branch,
the recovery paths, and adversarial inputs. COWD and seSparse output is
cross-validated **byte-for-byte against `qemu-img convert -O raw`** — the
synthetic fixtures and the reader cannot share a blind spot. Coverage is enforced
in CI.

```bash
cargo test
cargo +stable llvm-cov --workspace --all-features --summary-only
```

## Related

**vmdk** gives you the virtual disk as bytes. These crates read other container
formats the same way — a pure `Read + Seek` over the decoded sector stream:

| Crate | Format |
|---|---|
| [`ewf`](https://github.com/SecurityRonin/ewf) | E01 / Expert Witness Format (EnCase, FTK Imager) |
| [`vhdx`](https://github.com/SecurityRonin/vhdx) | Microsoft VHDX (Hyper-V, Azure) |
| [`vhd`](https://github.com/SecurityRonin/vhd) | Legacy VHD (Virtual PC / Hyper-V Gen-1) |
| [`qcow2`](https://github.com/SecurityRonin/qcow2) | QEMU / KVM QCOW2 |
| [`dd`](https://github.com/SecurityRonin/dd) | Raw / flat / dd images |

Audit a VMDK for tampering, corruption, and recoverability with its forensic sibling:

| Crate | Role |
|---|---|
| [`vmdk-forensic`](https://github.com/SecurityRonin/vmdk) | VMDK integrity analysis — RGD adjudication, dangling-pointer scan, recovery triage, header provenance, graded anomalies |

Once you have the bytes, these parsers analyse the partition layout inside:

| Crate | Scheme |
|---|---|
| [`mbr-forensic`](https://github.com/SecurityRonin/mbr-forensic) | Master Boot Record — anomalies, slack carving, boot-code ID |
| [`gpt-forensic`](https://github.com/SecurityRonin/gpt-forensic) | GUID Partition Table — backup-header reconciliation, CRC32 |
| [`disk-forensic`](https://github.com/SecurityRonin/disk-forensic) | **Orchestrator** — auto-detects MBR/GPT/APM and dispatches |

Container-format knowledge (magic numbers, header layouts, encoding rules) lives
in [`forensicnomicon`](https://github.com/SecurityRonin/forensicnomicon).

---

[Privacy Policy](https://securityronin.github.io/vmdk/privacy/) · [Terms of Service](https://securityronin.github.io/vmdk/terms/) · © 2026 Security Ronin Ltd
