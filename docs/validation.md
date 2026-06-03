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

### 6. ms3-win.vmdk — twoGbMaxExtentSparse (missing extents, negative test)

| Property | Value |
|----------|-------|
| Source | Rapid7 [Metasploitable3](https://github.com/rapid7/metasploitable3) Windows 2008 VMware Vagrant box |
| Vagrant box | `vagrantcloud.com/rapid7/boxes/metasploitable3-win2k8`, `vmware_desktop` provider |
| Subformat | `twoGbMaxExtentSparse`, `virtualHWVersion = "13"` |
| Creator | VMware Workstation 13 (Packer `vmware-iso` provider — genuine VMware output) |
| File committed | Descriptor only (1 KB); 16 × SPARSE extent files (~60 GB total) not committed |

`open_path("ms3-win.vmdk")` returns `Err(Io(NotFound))` for the first missing extent
file (`disk-s001.vmdk`). Validates that a `twoGbMaxExtentSparse` VMDK with absent
extent files fails loudly rather than silently succeeding with `virtual_disk_size = 0`.

### 7. mono_flat.vmdk + mono_flat-flat.vmdk — monolithicFlat

| Property | Value |
|----------|-------|
| Source | Generated locally |
| Command | `qemu-img create -f vmdk -o subformat=monolithicFlat vmdk/tests/data/mono_flat.vmdk 1M` |
| Subformat | `monolithicFlat` |
| Descriptor | `mono_flat.vmdk` (345 bytes, text only) |
| Extent | `mono_flat-flat.vmdk` (1 MiB, raw zeros) |
| Virtual size | 1 MiB (1,048,576 bytes) |

**Full virtual disk MD5 (qemu-img reference):** `b6d81b360a5672d80c27430f39153e2c`

Same raw content as `minimal.vmdk` — confirms `MultiExtentReader` produces identical
output to the sparse GD/GT path for an all-zero virtual disk.

### 8. tw_sparse.vmdk + tw_sparse-s001.vmdk — twoGbMaxExtentSparse (all-sparse)

| Property | Value |
|----------|-------|
| Source | Generated locally |
| Command | `qemu-img create -f vmdk -o subformat=twoGbMaxExtentSparse vmdk/tests/data/tw_sparse.vmdk 4M` |
| Subformat | `twoGbMaxExtentSparse` |
| Descriptor | `tw_sparse.vmdk` (351 bytes, text only) |
| Extent | `tw_sparse-s001.vmdk` (64 KiB, sparse) |
| Virtual size | 4 MiB (4,194,304 bytes) |

**Full virtual disk MD5 (qemu-img reference):** `b5cfa9d6c8febd618f91ac2843d50a1c`

Validates `MultiSparseReader` opens a `twoGbMaxExtentSparse` VMDK and returns zeros
for all-sparse grains.

### 9. tw_sparse_data.vmdk + tw_sparse_data-s001.vmdk — twoGbMaxExtentSparse (real data)

| Property | Value |
|----------|-------|
| Source | Generated locally |
| Command | See Reproducing section |
| Subformat | `twoGbMaxExtentSparse` |
| Virtual size | 4 MiB (4,194,304 bytes) |
| Content | Pattern `bytes(i % 256 for i in range(4 MiB))`; first 16 bytes = `[0, 1, …, 15]` |

**Full virtual disk MD5 (qemu-img reference):** `631b2c76267e568ccb221193ab23e134`

Exercises the `MultiSparseReader` GD/GT/GTE lookup path with non-zero grain data.

### 10. compressed_stream_opt.vmdk — streamOptimized, compressed grain

| Property | Value |
|----------|-------|
| Source | Generated locally |
| Command | See Reproducing section |
| Subformat | `streamOptimized` (header version 3, `compress_algorithm = 1`) |
| Virtual size | 64 KiB (65,536 bytes) |
| Content | Pattern `bytes(i % 64 for i in range(64 KiB))`; first 16 bytes = `[0, 1, …, 15]` |
| Grain marker | GTE[0]=128 → `GrainMarker` at byte 65536; `dataSize=280` (zlib payload) |

**Full virtual disk MD5 (qemu-img reference):** `6d65b48626512190ba3ff86150cb9bad`

Validates RFC 1950 zlib decompression of a real allocated grain (`ZlibDecoder`).
The 280-byte compressed payload expands to 65,536 bytes matching the source pattern.

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
| Sparse grains (GTE=0 → zeros) | Yes | all monolithicSparse and streamOptimized images |
| GTE=1 (explicitly zeroed) | Unit test | handled in `grain_location` |
| Allocated grains (real data) | Yes | `dfvfs_ext2.vmdk`, `plaso_image.vmdk`, `tw_sparse_data.vmdk` |
| `streamOptimized` v3 (all-sparse) | Yes | `stream_opt.vmdk` |
| `streamOptimized` v3 (compressed grains) | Yes | `compressed_stream_opt.vmdk` |
| `twoGbMaxExtentFlat` | Yes | `flat.vmdk` + `flat-f001.vmdk` |
| `monolithicFlat` | Yes | `mono_flat.vmdk` + `mono_flat-flat.vmdk` |
| `twoGbMaxExtentSparse` (all-sparse) | Yes | `tw_sparse.vmdk` + `tw_sparse-s001.vmdk` |
| `twoGbMaxExtentSparse` (real data) | Yes | `tw_sparse_data.vmdk` + `tw_sparse_data-s001.vmdk` |
| `twoGbMaxExtentSparse` (missing extents) | Yes (Err) | `ms3-win.vmdk` → `Err(Io(NotFound))` |
| GD_AT_END sentinel (footer lookup) | Unit test | `gd_at_end_stream_opt_vmdk()` in testutil |
| Compressed grains (RFC 1950 zlib) | Yes | `compressed_stream_opt.vmdk` |
| `vmfsSparse` / `vmfsThin` (COWD) | Yes (qemu-img) | `cowd_reader_matches_qemu_img` — byte-identical to qemu-img |
| `seSparse` (vSphere 6.5+ VMFS6) | Yes (qemu-img) | `sesparse_reader_matches_qemu_img` — byte-identical to qemu-img |
| `vmfs` / `vmfsPreallocated` flat | Unit test | `open_path` routes VMFS extent type as flat |
| Snapshot / delta chain | Unit test | `VmdkChainReader` over base + delta |
| RGD ↔ primary GD cross-check | Unit test | `validate_rgd()` |
| `adapterType = lsilogic` | External | pWnOS v2.0 |
| GD at non-trivial sector | External | pWnOS (sector 5151), Metasploitable3 (sector 510) |

## COWD / seSparse Cross-Validation (independent oracle)

`vmfsSparse`/`vmfsThin` (COWD) and `seSparse` are **ESXi-only write formats** —
`qemu-img` can *read* them but cannot *create* them, so no qemu-generated corpus
file exists. Instead, the reader is validated against QEMU's independent parser:

1. A synthetic extent (`test_cowd_vmdk` / `test_sesparse_vmdk`) is filled with a
   recognisable 4 KiB pattern and wrapped in a `vmfsSparse` / `seSparse` descriptor.
2. `qemu-img convert -O raw` and `VmdkReader::open_path` each extract the virtual disk.
3. The two outputs are asserted **byte-identical** (`cowd_reader_matches_qemu_img`,
   `sesparse_reader_matches_qemu_img`; skipped when `qemu-img` is absent).

Two unrelated implementations agreeing on the same bytes confirms the synthetic
fixture is format-correct **and** the reader decodes it correctly. This caught a
real bug: the initial seSparse implementation assumed plain sector offsets, but
the real format (per QEMU `block/vmdk.c`) uses nibble-typed, bit-rotated grain
entries — the fixture and reader had agreed with each other while both were wrong.

Reproduce manually:

```sh
cargo run --example emit_fixture --features test-helpers -- sesparse /tmp/se/disk-sesparse.vmdk
printf '# Disk DescriptorFile\nversion=1\nCID=abcdef01\nparentCID=ffffffff\ncreateType="seSparse"\nRW 8 SESPARSE "disk-sesparse.vmdk"\n' > /tmp/se/disk.vmdk
qemu-img convert -O raw /tmp/se/disk.vmdk /tmp/se/qemu.raw
cargo run -p vmdk-cli -- dump -o /tmp/se/mine.raw /tmp/se/disk.vmdk
cmp /tmp/se/qemu.raw /tmp/se/mine.raw && echo "IDENTICAL"
```

## Reproducing

```sh
# Regenerate all qemu-img corpus files
qemu-img create -f vmdk vmdk/tests/data/minimal.vmdk 1M
qemu-img create -f vmdk -o subformat=streamOptimized vmdk/tests/data/stream_opt.vmdk 1M
qemu-img create -f vmdk -o subformat=twoGbMaxExtentFlat vmdk/tests/data/flat.vmdk 1M
qemu-img create -f vmdk -o subformat=monolithicFlat vmdk/tests/data/mono_flat.vmdk 1M
qemu-img create -f vmdk -o subformat=twoGbMaxExtentSparse vmdk/tests/data/tw_sparse.vmdk 4M

# twoGbMaxExtentSparse with real pattern data (4 MiB, bytes i%256)
python3 -c "import sys; sys.stdout.buffer.write(bytes(i%256 for i in range(4*1024*1024)))" \
  > /tmp/pat4m.raw
qemu-img convert -f raw -O vmdk -o subformat=twoGbMaxExtentSparse \
  /tmp/pat4m.raw vmdk/tests/data/tw_sparse_data.vmdk
rm /tmp/pat4m.raw

# streamOptimized with compressed grain (64 KiB, bytes i%64)
python3 -c "import sys; sys.stdout.buffer.write(bytes(i%64 for i in range(65536)))" \
  > /tmp/pat64k.raw
qemu-img convert -f raw -O vmdk -o subformat=streamOptimized \
  /tmp/pat64k.raw vmdk/tests/data/compressed_stream_opt.vmdk
rm /tmp/pat64k.raw

# Compute reference MD5s
for f in dfvfs_ext2 minimal stream_opt plaso_image mono_flat \
          tw_sparse tw_sparse_data compressed_stream_opt; do
  qemu-img convert -O raw vmdk/tests/data/$f.vmdk /tmp/ref_$f.raw
  printf "%s  %s\n" "$(md5 -q /tmp/ref_$f.raw)" "$f.vmdk"
  rm /tmp/ref_$f.raw
done

# Run validation tests
cargo test
```
