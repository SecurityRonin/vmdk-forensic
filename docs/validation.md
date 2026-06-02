# VMDK Corpus Validation

Byte-level differential tests comparing `VmdkReader` output against
`qemu-img convert -O raw` (QEMU 11.0.0, macOS/Apple Silicon).

## Test Environment

| Component | Version | Source |
|-----------|---------|--------|
| vmdk crate | 0.1.0 | this repo |
| [QEMU](https://www.qemu.org/) (`qemu-img`) | 11.0.0 | Homebrew (`brew install qemu`) |
| Rust (rustc) | 1.88.0 | [rustup.rs](https://rustup.rs/) |
| Platform | macOS Darwin 24.6.0, arm64 (Apple Silicon) | — |

## Corpus Files

### 1. dfvfs_ext2.vmdk — VMware4-origin, independent validation

| Property | Value |
|----------|-------|
| Source | [log2timeline/dfvfs](https://github.com/log2timeline/dfvfs) `test_data/ext2.vmdk` (Apache-2.0) |
| URL | `https://raw.githubusercontent.com/log2timeline/dfvfs/main/test_data/ext2.vmdk` |
| Subformat | `monolithicSparse`, `virtualHWVersion = "4"` |
| Creator | VMware (confirmed: `file` output `VMware4 disk image`; `ddb.virtualHWVersion = "4"`) |
| Virtual size | 4 MiB (4,194,304 bytes) |
| Filesystem | ext2 |
| SHA-256 | `578b5f75af790030113a92c4227c6e53dad53a17e65cb491781dc75b3cef31f8` |

**Full virtual disk MD5 (qemu-img reference):** `196066add11fb71c4c49cf1bb50d6d24`

This is **not QEMU-generated** — it was created by VMware, providing cross-implementation
validation: a real VMware-format image parsed by our reader.

### 2. plaso_image.vmdk — VMware Workstation 4, real grain data

| Property | Value |
|----------|-------|
| Source | [log2timeline/plaso](https://github.com/log2timeline/plaso) `test_data/image.vmdk` (Apache-2.0) |
| URL | `https://raw.githubusercontent.com/log2timeline/plaso/main/test_data/image.vmdk` |
| Subformat | `monolithicSparse`, `virtualHWVersion = "4"`, `adapterType = "ide"` |
| Creator | VMware Workstation 4 era (confirmed by `ddb.virtualHWVersion = "4"`, `ddb.adapterType = "ide"`) |
| Virtual size | 100 KiB (102,400 bytes, 200 sectors) |
| Grain size | 128 sectors (64 KiB) |
| Content | Real non-zero grain data at virtual offset 1024 |

**Full virtual disk MD5 (qemu-img reference):** `a528fc1bec79f4fef062f2bf1008c045`

Exercises the grain-lookup path against actual filesystem content rather than zeros.

### 3. minimal.vmdk — QEMU-generated reference

| Property | Value |
|----------|-------|
| Source | Generated locally |
| Command | `qemu-img create -f vmdk vmdk/tests/data/minimal.vmdk 1M` |
| Subformat | `monolithicSparse` (v1) |
| Virtual size | 1 MiB (1,048,576 bytes) |
| Content | All-sparse (all grains unmapped → reads return zeros) |

**Full virtual disk MD5 (qemu-img reference):** `b6d81b360a5672d80c27430f39153e2c`

Used for the synthetic differential test (same QEMU for write and verify; validates
GD/GT arithmetic and sparse-grain zero-fill).

### 4. stream_opt.vmdk — streamOptimized v3, all-sparse

| Property | Value |
|----------|-------|
| Source | Generated locally |
| Command | `qemu-img create -f vmdk -o subformat=streamOptimized vmdk/tests/data/stream_opt.vmdk 1M` |
| Subformat | `streamOptimized` (header version 3, `compress_algorithm = 1`) |
| Virtual size | 1 MiB (1,048,576 bytes) |
| Content | All-sparse; GD/GT layout identical to v1 (gd_offset=26, all GTEs=0) |

**Full virtual disk MD5 (qemu-img reference):** `b6d81b360a5672d80c27430f39153e2c`

Validates v3 header parsing and that all-sparse streamOptimized disks read as zeros
without attempting DEFLATE decompression.

### 5. flat.vmdk + flat-f001.vmdk — twoGbMaxExtentFlat

| Property | Value |
|----------|-------|
| Source | Generated locally |
| Command | `qemu-img create -f vmdk -o subformat=twoGbMaxExtentFlat vmdk/tests/data/flat.vmdk 1M` |
| Subformat | `twoGbMaxExtentFlat` |
| Descriptor | `flat.vmdk` (344 bytes, text only) |
| Extent | `flat-f001.vmdk` (1 MiB, raw zeros) |
| Virtual size | 1 MiB (1,048,576 bytes) |

**Full virtual disk MD5 (qemu-img reference):** `b6d81b360a5672d80c27430f39153e2c`

`open_path("flat.vmdk")` reads the text descriptor, resolves `flat-f001.vmdk`
relative to the descriptor path, and streams raw bytes through `MultiExtentReader`.
`open(Cursor::new(...))` on the descriptor alone returns `Err` (no binary header).

### 6. ms3-win.vmdk — twoGbMaxExtentSparse (unsupported, negative test)

| Property | Value |
|----------|-------|
| Source | Rapid7 [Metasploitable3](https://github.com/rapid7/metasploitable3) Windows 2008 VMware Vagrant box |
| Vagrant box | `vagrantcloud.com/rapid7/boxes/metasploitable3-win2k8`, `vmware_desktop` provider |
| Subformat | `twoGbMaxExtentSparse`, `virtualHWVersion = "13"` |
| Creator | VMware Workstation 13 (Packer `vmware-iso` provider — genuine VMware output) |
| File committed | Descriptor only (1 KB); 16 × SPARSE extent files (~60 GB total) not committed |

`open_path("ms3-win.vmdk")` returns `Err(UnsupportedDiskType("twoGbMaxExtentSparse"))`.
Validates that descriptors with only SPARSE extents are loudly rejected rather than
silently succeeding with `virtual_disk_size = 0`.

## Test Results

### `corpus_dfvfs_ext2_vmdk_reads_match_qemu_raw_convert` (independent — VMware4)

Full stride scan (4 KiB step) of `dfvfs_ext2.vmdk` compared byte-for-byte against
`qemu-img convert -O raw`. **PASS.**

Exercises: GD/GT lookup, grain reads, descriptor parsing with VMware-written fields.

### `corpus_minimal_vmdk_reads_match_qemu_raw_convert` (synthetic)

Full byte scan of `minimal.vmdk` at 64 KiB stride + near-end read. **PASS.**

Exercises: sparse grain detection (GTE=0 → zeros), grain data reads, seek arithmetic.

### `reads_match_qemu_raw_convert` (synthetic — round-trip)

1 MiB raw file with pattern `(i ^ (i >> 8)) as u8` written by test helper,
converted to VMDK by qemu-img, read back by `VmdkReader`. **PASS.**

Exercises: non-zero grain data, multi-grain seeks, byte-identical round-trip.

## External Validation (not in CI)

### pWnOS v2.0 (VulnHub, VMware Workstation 7)

| Property | Value |
|----------|-------|
| Source | [VulnHub pWnOS v2.0](https://www.vulnhub.com/entry/pwnos-20-pre-release,34/) |
| Download | `https://download.vulnhub.com/pwnos/pWnOS_v2.0.7z` |
| File | `Ubuntu Server v11.04 64-bit-cl1.vmdk` (1.3 GB) |
| Subformat | `monolithicSparse`, `virtualHWVersion = "7"`, `adapterType = "lsilogic"` |
| Virtual size | 40 GiB (42,949,672,960 bytes) |

`vmdk info` reported correct format and size. GD at sector 5151 (non-trivial placement),
grain at sector 10368 — x86 MBR boot code (`eb 63 90`) confirmed in grain data.

### Metasploitable3 Windows 2008 (Rapid7, VMware Workstation 13)

Descriptor-only test committed as `ms3-win.vmdk` (see corpus file 6 above).

## Validation Coverage

| Feature | Covered | Notes |
|---------|---------|-------|
| `monolithicSparse` v1 | Yes | `minimal.vmdk`, `dfvfs_ext2.vmdk`, `plaso_image.vmdk` |
| VMware Workstation 4 origin | Yes | `dfvfs_ext2.vmdk`, `plaso_image.vmdk` |
| VMware Workstation 7 origin | External | pWnOS v2.0 |
| VMware Workstation 13 origin | External | Metasploitable3 descriptor |
| Sparse grains (GTE=0 → zeros) | Yes | all monolithicSparse images |
| GTE=1 (explicitly zeroed) | Unit test | handled in `grain_location` |
| Allocated grains (real data) | Yes | `dfvfs_ext2.vmdk`, `plaso_image.vmdk` |
| `streamOptimized` v3 (all-sparse) | Yes | `stream_opt.vmdk` |
| `twoGbMaxExtentFlat` | Yes | `flat.vmdk` + `flat-f001.vmdk` |
| `twoGbMaxExtentSparse` | Negative only | `ms3-win.vmdk` → `Err` |
| `adapterType = lsilogic` | External | pWnOS v2.0 |
| GD at non-trivial sector | External | pWnOS (sector 5151), Metasploitable3 (sector 510) |
| Compressed grains (DEFLATE) | No | out of scope |

## Reproducing

```sh
# Regenerate qemu-img corpus files
qemu-img create -f vmdk vmdk/tests/data/minimal.vmdk 1M
qemu-img create -f vmdk -o subformat=streamOptimized vmdk/tests/data/stream_opt.vmdk 1M
qemu-img create -f vmdk -o subformat=twoGbMaxExtentFlat vmdk/tests/data/flat.vmdk 1M

# Compute reference MD5s
for f in dfvfs_ext2 minimal stream_opt plaso_image; do
  qemu-img convert -O raw vmdk/tests/data/$f.vmdk /tmp/ref_$f.raw
  printf "%s  %s\n" "$(md5 -q /tmp/ref_$f.raw)" "$f.vmdk"
  rm /tmp/ref_$f.raw
done

# Run validation tests
cargo test
```
