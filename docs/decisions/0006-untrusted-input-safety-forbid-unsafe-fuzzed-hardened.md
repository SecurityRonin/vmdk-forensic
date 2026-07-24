# 6. Untrusted-input safety: `forbid(unsafe)`, pure Rust, bounds-checked, fuzzed

Date: 2026-07-24
Status: Accepted

## Context

A VMDK reader parses attacker-controllable disk images: every offset, length, and
count in the header and grain directory is under the adversary's control. The fleet
Paranoid Gatekeeper standard requires these crates to never panic, never read out of
bounds, and never trust a length field. Unlike the mmap-based readers (`ewf`,
`memory-forensic`) that need a bounded `unsafe` for `Mmap::map`, VMDK is decoded
over an ordinary `Read + Seek` cursor and needs no `unsafe` at all — so it can hold
the stronger `forbid` posture rather than `deny` + a bounded allow.

## Decision

Adopt the strongest untrusted-input posture the design allows:

- **`unsafe_code = "forbid"` workspace-wide** (`Cargo.toml [workspace.lints.rust]`),
  no C dependency — a provable "zero places a crafted input can corrupt memory".
- **Panic-free lints:** `clippy::unwrap_used = "deny"`, `correctness`/`suspicious`
  denied; `allow-unwrap-in-tests`/`allow-expect-in-tests` in `clippy.toml` scope the
  exception to tests only.
- **Allocation-amplification cap:** `numGTEsPerGT` is capped at the spec value
  **512** (`MAX_NUM_GTES_PER_GT`, `core/src/header.rs`), matching QEMU's
  `vmdk_open_vmdk4`, so a crafted header cannot drive a multi-gigabyte grain-table
  allocation. The forensic layer applies its own `MAX_GD_BYTES` (16 MiB) cap.
- **Four `cargo fuzz` targets** (`fuzz_open`, `fuzz_read`, `fuzz_recover`,
  `fuzz_forensic`) cover the open path, the full read surface, the RGD recovery
  paths, and the forensic pipeline; run in CI and deeper on a schedule.
- **P0 hardening (0.6.0, commit cluster `836860d`…`cc695a8`), all on the
  untrusted-input path:**
  - descriptor extent + `parentFileNameHint` paths sandboxed to the image directory
    — an absolute or `..`-climbing path is refused (`cc695a8`);
  - compressed-grain decode bounded to the grain size, refusing decompression bombs
    (`e907ea8`);
  - snapshot-chain reads grain-clamped so a sparse grain cannot zero-mask an
    allocated one (`fc752b7`);
  - `custom` descriptors mixing flat and sparse extents rejected loudly instead of
    silently dropping the sparse extents (`f72a5e7`).

## Consequences

- The reader wears an honest `unsafe forbidden` guarantee (no bounded-allow
  asterisk), a real differentiator for an evidence parser.
- Header-derived allocations are bounded by spec-anchored caps, not by trust, so a
  crafted image fails loudly rather than exhausting memory or reading out of bounds.
- Robustness is proven empirically (fuzzing over untrusted input) and statically
  (lints), the paired "trust but verify" posture — neither alone is claimed as a
  universal "cannot panic".
