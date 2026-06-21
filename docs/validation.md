# Validation

`vmdk-core` / `vmdk-forensic` parse untrusted VMDK structures from potentially
crafted disk images. Correctness is therefore established the way forensic tooling
must be: against **independent oracles** (a different tool, or a different code
path, that already decodes the same bytes correctly) on **real third-party
corpora** with known ground truth — never against fixtures we hand-encoded and
then graded ourselves.

This page records exactly which oracle and which corpus back each capability, so
the claim is independently re-checkable. Per-file provenance (source, download
URL, hashes, license) lives in [`core/tests/data/README.md`](https://github.com/SecurityRonin/vmdk-forensic/blob/main/core/tests/data/README.md);
the fleet-wide machine index is `issen/docs/corpus-catalog.md`. This page
cross-references both rather than duplicating them.

## How to read the evidence tiers

Each validation below is tagged with the trustworthiness of its check, not
whether the data is "synthetic":

- **Tier 1** — an independent third party authored the artifact *and* the answer
  key, or it is real-world data decoded by an independent tool. The strongest claim.
- **Tier 2** — real engine output whose ground truth is derivable from the
  documented construction, or confirmed by an *independent code path* on real
  data. Genuinely checked, but we chose the scenario.
- **Tier 3** — fixture and expected answer both authored here, nothing
  independent vouching. Used only for per-branch coverage, never as a
  correctness claim: a self-consistent round trip proves internal consistency,
  not correctness against real-world bytes.

## Independent oracles

| Oracle | Independent of us? | Validates | Tier |
|---|---|---|---|
| **QEMU** (`qemu-img convert -O raw`, 11.0.0) | Yes — separate C codebase (`block/vmdk.c`) | The decoded virtual-disk byte stream of a real VMware-written `monolithicSparse` image (`dfvfs_ext2.vmdk`), compared byte-for-byte | 1 |
| **QEMU** (`qemu-img convert -O raw`) as an independent *reader* of ESXi-only formats | Yes | `vmfsSparse`/COWD and `seSparse` decode — `qemu-img` *reads* these formats it cannot *write*, so its parser is the independent check on our synthetic extent | 2 |
| **`flate2` crate** (RFC 1950 zlib) | Yes — vetted third-party codec we reuse | The DEFLATE/zlib grain decode itself (a maintained, audited codec) | 1 |

`qemu-img` cannot *generate* COWD/seSparse (they are ESXi write-only formats), so
there is no qemu-authored corpus for them. Instead a synthetic extent is wrapped
in a descriptor and decoded by *both* `qemu-img` and our reader; two unrelated
parsers agreeing on the same bytes confirms the fixture is format-correct **and**
the reader decodes it correctly (the independent-code-path check that defines
Tier 2). This caught a real defect: the first seSparse implementation assumed
plain sector offsets, but the format uses nibble-typed, bit-rotated grain entries
(per QEMU `block/vmdk.c`) — the divergence from `qemu-img` exposed it.

## Independent test corpora

The two VMware-origin images are third-party, publicly distributed VMDKs created
by genuine VMware tooling. The qemu-generated and synthetic fixtures exercise the
remaining format branches. Full provenance, subformats, and hashes are in
[`core/tests/data/README.md`](https://github.com/SecurityRonin/vmdk-forensic/blob/main/core/tests/data/README.md)
and the per-file table in the [implementation notes](implementation-notes.md).

| Corpus | Source | Used for | License / redistribution |
|---|---|---|---|
| **dfvfs `ext2.vmdk`** (`dfvfs_ext2.vmdk`) | [log2timeline/dfvfs](https://github.com/log2timeline/dfvfs) `test_data/ext2.vmdk` | VMware4-origin `monolithicSparse` read, byte-for-byte vs `qemu-img` | **Apache-2.0** (committed) |
| **plaso `image.vmdk`** (`plaso_image.vmdk`) | [log2timeline/plaso](https://github.com/log2timeline/plaso) `test_data/image.vmdk` | Real VMware Workstation 4 image with non-zero grain data at virtual offset 1024 | **Apache-2.0** (committed) |
| **Metasploitable3 Win2k8** (`ms3-win.vmdk`) | Rapid7 [metasploitable3](https://github.com/rapid7/metasploitable3) VMware Vagrant box (Packer `vmware-iso`) | `twoGbMaxExtentSparse` descriptor with missing extents — fail-loud negative test | Descriptor only (1 KB) committed; SPARSE extents not redistributed |
| **qemu-img fixtures** (`minimal`, `stream_opt`, `flat`, `mono_flat`, `tw_sparse*`, `compressed_stream_opt`) | Generated locally with `qemu-img` 11.0.0 | GD/GT arithmetic, sparse zero-fill, v3 header, flat/multi-extent, compressed grain | Generated; reproduction below |
| **pWnOS v2.0** (not committed) | [VulnHub pWnOS v2.0](https://www.vulnhub.com/entry/pwnos-20-pre-release,34/) — VMware Workstation 7, 40 GiB | External smoke validation: GD at non-trivial sector 5151, MBR boot code in grain | Public VulnHub distribution; too large to commit |

## Per-capability validation

### Virtual-disk read of a real VMware image — Tier 1

`corpus_dfvfs_ext2_vmdk_reads_match_qemu_raw_convert`
([`core/src/lib.rs:1896`](https://github.com/SecurityRonin/vmdk-forensic/blob/main/core/src/lib.rs))
does a full stride scan (4 KiB step) of the third-party VMware-written
`dfvfs_ext2.vmdk` and asserts every sector is **byte-identical to `qemu-img
convert -O raw`** — and that `virtual_disk_size()` equals the qemu raw length.
A real VMware image, decoded by an independent C parser, matching ours sector for
sector is the strongest available claim for the `monolithicSparse` read path
(GD/GT lookup, grain reads, descriptor parsing). The test skips cleanly when
`qemu-img` is not installed.

### COWD (`vmfsSparse`/`vmfsThin`) and seSparse decode — Tier 2

`cowd_reader_matches_qemu_img` and `sesparse_reader_matches_qemu_img`
([`core/src/lib.rs:1463`](https://github.com/SecurityRonin/vmdk-forensic/blob/main/core/src/lib.rs))
build a synthetic extent filled with a recognisable pattern, wrap it in a
`vmfsSparse` / `seSparse` descriptor, and assert that `qemu-img convert -O raw`
and `VmdkFileReader::open_path` produce **byte-identical** output
(`assert_reader_matches_qemu`, [`core/src/lib.rs:1410`](https://github.com/SecurityRonin/vmdk-forensic/blob/main/core/src/lib.rs)).
These are ESXi write-only formats with no qemu-authored corpus; the independent
`qemu-img` *reader* is the oracle. Both tests skip when `qemu-img` is absent.

### Compressed (DEFLATE/zlib) grain decode — Tier 1 codec, Tier 2 fixture

`compressed_stream_opt_reads_correct_data` and `compressed_streamoptimized_reads_fully`
([`core/tests/real_images.rs:360`](https://github.com/SecurityRonin/vmdk-forensic/blob/main/core/tests/real_images.rs))
decode a real allocated grain from a `qemu-img`-generated `streamOptimized` image
(`compressed_stream_opt.vmdk`): the 280-byte zlib payload expands to a full 64 KiB
grain whose bytes match the documented source pattern `bytes(i % 64 …)`. The codec
itself is the vetted third-party `flate2` (RFC 1950 zlib) crate; the fixture's
expected bytes are derivable from its documented construction.

### Multi-extent and flat read paths — Tier 2

`core/tests/real_images.rs` exercises the path-based readers against
`qemu-img`-generated fixtures whose all-zero or pattern content is known by
construction: `flat_vmdk_*` / `mono_flat_vmdk_*` (FLAT extents via
`MultiExtentReader`), `tw_sparse_vmdk_*` (all-sparse `twoGbMaxExtentSparse`), and
`tw_sparse_data_vmdk_reads_correct_pattern` (real grain data through the
`MultiSparseReader` GD/GT/GTE lookup). `mono_flat` reproduces `minimal`'s all-zero
virtual disk through the flat path, confirming the flat and sparse paths agree.

### Fail-loud on missing extents — Tier 1 input

`ms3_win_two_gb_max_extent_sparse_open_path_returns_err`
([`core/tests/real_images.rs:231`](https://github.com/SecurityRonin/vmdk-forensic/blob/main/core/tests/real_images.rs))
opens the real Metasploitable3 `twoGbMaxExtentSparse` descriptor whose 16 SPARSE
extent files are absent and asserts `open_path` returns `Err(Io(NotFound))` on the
first missing extent — never a silent `virtual_disk_size = 0`. The descriptor is a
genuine VMware Workstation 13 (Packer) artifact.

### Integrity analysis on real images — Tier 2

`real_images_pass_integrity` and `truncated_image_fails_integrity`
([`forensic/tests/corpus.rs:14`](https://github.com/SecurityRonin/vmdk-forensic/blob/main/forensic/tests/corpus.rs))
run `VmdkIntegrity::check_integrity` over the committed corpus
(`minimal`, `dfvfs_ext2`, `plaso_image`, `stream_opt`): clean images report OK,
and a `dfvfs_ext2` image truncated to half its length (dangling grain pointers)
reports a failure. `streamoptimized_image_analyses_via_footer_gd` exercises the
`GD_AT_END` footer resolution and `validate_rgd` on `stream_opt.vmdk`.

### RGD-fallback recovery — Tier 3

The redundant-grain-directory recovery path (`enable_rgd_fallback`,
`grain_directory_recovery`, `rgd_recovery_count`) is validated by unit tests that
corrupt a known primary GD/GTE and assert the redundant copy recovers the grain
(`rgd_fallback_recovers_grain_from_corrupt_primary_gd` and siblings,
[`core/src/lib.rs:2155`](https://github.com/SecurityRonin/vmdk-forensic/blob/main/core/src/lib.rs)).
Both the corruption and the expected recovered bytes are authored here, so this is
a self-consistent internal check, not an independent-oracle claim — `qemu-img` and
`libvmdk` cannot read through a damaged primary GD, so no external oracle exists
for this capability. (See gaps below.)

### Robustness — never panic, never over-read

Every parser is fuzzed (four `cargo-fuzz` targets in `fuzz/fuzz_targets/`:
`fuzz_open`, `fuzz_read`, `fuzz_recover`, `fuzz_forensic`), each with the invariant
"must not panic." Production code is `#![forbid(unsafe_code)]` workspace-wide and
denies `clippy::unwrap_used` / `clippy::expect_used`; every length, offset, and
grain-table size is bounds-checked and capped (`numGTEsPerGT` ≤ 512, the spec
value, matching QEMU) to defend against allocation amplification.

## Reproducing the validation

The committed fixtures run with `cargo test`. The `qemu-img` differential tests
skip automatically when `qemu-img` is not on `PATH` (install via
`brew install qemu`).

```bash
# Full workspace test run (committed fixtures + qemu-img differentials when present)
cargo test

# Just the qemu-img byte-for-byte differential on the real VMware image
cargo test -p vmdk-core corpus_dfvfs_ext2_vmdk_reads_match_qemu_raw_convert

# COWD + seSparse cross-validation against qemu-img's independent reader
cargo test -p vmdk-core cowd_reader_matches_qemu_img sesparse_reader_matches_qemu_img

# Forensic integrity over the committed corpus
cargo test -p vmdk-forensic
```

Regenerate the `qemu-img` fixtures (QEMU 11.0.0, macOS/Apple Silicon):

```bash
qemu-img create -f vmdk core/tests/data/minimal.vmdk 1M
qemu-img create -f vmdk -o subformat=streamOptimized core/tests/data/stream_opt.vmdk 1M
qemu-img create -f vmdk -o subformat=twoGbMaxExtentFlat core/tests/data/flat.vmdk 1M
qemu-img create -f vmdk -o subformat=monolithicFlat core/tests/data/mono_flat.vmdk 1M
qemu-img create -f vmdk -o subformat=twoGbMaxExtentSparse core/tests/data/tw_sparse.vmdk 4M

# twoGbMaxExtentSparse with real pattern data (4 MiB, bytes i%256)
python3 -c "import sys; sys.stdout.buffer.write(bytes(i%256 for i in range(4*1024*1024)))" > /tmp/pat4m.raw
qemu-img convert -f raw -O vmdk -o subformat=twoGbMaxExtentSparse /tmp/pat4m.raw core/tests/data/tw_sparse_data.vmdk

# streamOptimized with a compressed grain (64 KiB, bytes i%64)
python3 -c "import sys; sys.stdout.buffer.write(bytes(i%64 for i in range(65536)))" > /tmp/pat64k.raw
qemu-img convert -f raw -O vmdk -o subformat=streamOptimized /tmp/pat64k.raw core/tests/data/compressed_stream_opt.vmdk
```

## Coverage & fuzzing as backstops

Line coverage is enforced in CI (`cargo llvm-cov --workspace`, failing on any
zero-hit line not annotated `// cov:unreachable`). Coverage is a regression
backstop that proves behavior is exercised — it is not the correctness claim. The
oracles above are.

## Gaps and in-progress work

- **RGD-fallback recovery has no independent oracle.** Reading through a damaged
  primary grain directory is the reader's headline differentiator — and exactly
  the capability `qemu-img`/`libvmdk` lack, so neither can serve as an oracle. The
  recovery path is currently validated only by Tier-3 self-authored corruption
  fixtures. A real damaged-VMDK corpus (or an independent recovery tool) would
  raise this to Tier 1/2 and is recommended.
- **seSparse / COWD validation is Tier 2, not Tier 1** — the extents are
  synthetic (these formats are ESXi write-only, so no third-party corpus is
  readily mintable on the host). The `qemu-img` independent-reader check is strong
  but a captured ESXi VMFS6 image would be a stronger Tier-1 anchor.
- **plaso/dfvfs ground truth for non-`dfvfs_ext2` images** rests on
  empirically-derived expected bytes rather than an independent decode; only
  `dfvfs_ext2.vmdk` is compared against `qemu-img` sector-for-sector.
</content>
</invoke>
