# tests/data — VMDK Real-Image Corpus

Integration test fixtures and fuzz seed corpus.
`fuzz/corpus/fuzz_open/` symlinks here; files are not duplicated.

## Files

| File | Subformat | Virtual size | Supported | Origin | Notes |
|------|-----------|-------------|-----------|--------|-------|
| `minimal.vmdk` | monolithicSparse (v1) | 1 MiB | Yes | qemu-img 11.0.0 (macOS/ARM) | Primary integration test seed |
| `dfvfs_ext2.vmdk` | monolithicSparse (v1) | 4 MiB | Yes | dfvfs test corpus (libyal) | ext2 filesystem; VMware4 origin |
| `plaso_image.vmdk` | monolithicSparse (v1) | 100 KiB | Yes | plaso test corpus (log2timeline) | Real VMware Workstation 4 image; has non-zero grain data at virtual offset 1024 |
| `stream_opt.vmdk` | streamOptimized (v3) | 1 MiB | Yes | qemu-img 11.0.0 (macOS/ARM) | All-sparse empty disk; GD/GT layout identical to v1 |
| `flat.vmdk` | twoGbMaxExtentFlat | 1 MiB | Yes (open_path only) | qemu-img 11.0.0 (macOS/ARM) | Text descriptor; open() returns Err, open_path() succeeds |
| `flat-f001.vmdk` | (raw extent for flat.vmdk) | — | No (by design) | qemu-img 11.0.0 (macOS/ARM) | Raw extent data, no VMDK header; open() returns BadMagic |

"Not supported" means `VmdkReader::open` returns `Err`, not that it panics.
These files serve as regression seeds: the reader must not panic on any of them.

## Provenance

- **qemu-img** files: generated locally with qemu-img 11.0.0 on macOS (Apple Silicon).
- **dfvfs_ext2.vmdk**: from [log2timeline/dfvfs](https://github.com/log2timeline/dfvfs) `test_data/ext2.vmdk` (Apache 2.0).
- **plaso_image.vmdk**: from [log2timeline/plaso](https://github.com/log2timeline/plaso) `test_data/image.vmdk` (Apache 2.0). VMware Workstation 4 era (`virtualHWVersion=4`, `adapterType=ide`). 200-sector disk with real filesystem data.

## Regenerating qemu-img files

```sh
qemu-img create -f vmdk tests/data/minimal.vmdk 1M
qemu-img create -f vmdk -o subformat=streamOptimized tests/data/stream_opt.vmdk 1M
qemu-img create -f vmdk -o subformat=twoGbMaxExtentFlat tests/data/flat.vmdk 1M
```
