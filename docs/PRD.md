# vmdk-forensic — Design, Purpose & Scope

This is a **library** repo (a container reader plus its forensic analyzer), not a
user-facing product. It carries a design/scope document rather than a PRD: the
crates are *linked* by other tools, and the examiner-facing surface is
`disk4n6`/Issen. The `cli/` member (binary `vmdk`) is a developer/debug front end,
not the product.

For the decisions that shaped the code, see [`decisions/`](decisions/). For the
validation evidence and oracles, see [`validation.md`](validation.md). For format
quirks and spec contradictions, see [`implementation-notes.md`](implementation-notes.md).

## Purpose

Read VMware VMDK disk images — including images other readers give up on — as a
plain `Read + Seek` byte stream, and audit them for tampering, corruption, and
recoverability. The authoritative format reference is the *VMware Virtual Disk
Format 1.1* spec (August 2011), cross-checked against QEMU `block/vmdk.c` and
`libvmdk`.

Two crates, one workspace (ADR 0001):

- **`vmdk-core`** (imported as `vmdk`) — the read-only reader. Decodes the virtual
  disk to virtual-sector `Read + Seek`, resolves snapshot/delta chains, surfaces the
  full `ddb.*` disk database, and recovers data behind a damaged primary grain
  directory via the redundant copy.
- **`vmdk-forensic`** — the integrity analyzer. Reparses the raw structure and emits
  severity-graded `forensicnomicon::report::Finding`s (RGD adjudication,
  dangling-pointer scan, recovery triage, header provenance).

## Who links this

- **The fleet orchestrators** (`disk-forensic`, Issen) — open a VMDK as a uniform
  byte source and aggregate its findings into one report.
- **The fleet VFS** (`forensic-vfs`, behind the `vfs` feature) — compose a decoded
  VMDK as an `ImageSource` in a layered stack (e.g. `VMDK → GPT → NTFS`).
- **Rust developers** who need VMDK read access or VMDK integrity findings in their
  own tools, via `cargo add vmdk-core` / `cargo add vmdk-forensic`.
- **Examiners**, indirectly, through the `disk4n6`/Issen front end; and directly via
  the `vmdk` debug CLI for quick inspection (`examine`, `dump`, `map`, `diff`).

## What it does

- **Reads every VMDK `createType` and extent type** in the VDF 1.1 spec:
  `monolithicSparse`, `streamOptimized` (DEFLATE grains, `GD_AT_END` footer),
  `monolithicFlat` and the `vmfs*` preallocated flats, the `twoGbMaxExtent*` split
  sets, `vmfsSparse`/`vmfsThin` (ESXi COWD copy-on-write), `seSparse` (vSphere 6.5+
  space-efficient), the `vmfsRaw`/`*RawDeviceMap`/`fullDevice`/`partitionedDevice`
  device maps, and `custom` mixes routed by extent type. `ZERO`/`NOACCESS` regions
  read as zeros without touching disk.
- **Traverses snapshot/delta chains** (`VmdkChainReader`), layering a delta on its
  parent.
- **Recovers damaged images** through the redundant grain directory (opt-in, safe by
  default — ADR 0005): read-through fallback in the reader, plus recovery triage in
  the analyzer.
- **Surfaces provenance** other readers discard: the `ddb.*` disk database (adapter,
  CHS geometry, UUID, tools/HW version), Change Block Tracking (`-ctk`) reference,
  `longContentID` resolution, unclean-shutdown flag, FTP-ASCII-mangling check.
- **Grades integrity findings** as canonical findings (ADR 0004): `VMDK-RGD-MISMATCH`,
  `VMDK-UNCLEAN-SHUTDOWN`, `VMDK-FTP-ASCII-MANGLED`, `VMDK-PRIMARY-GD-RECOVERABLE`,
  `VMDK-PRIMARY-GD-UNRECOVERABLE`, `VMDK-DANGLING-GT`, `VMDK-DANGLING-GRAIN`.
- **Hashes the virtual disk** — streaming SHA-256 + MD5.

## Scope / non-goals

- **Read-only.** No crate here writes to a VMDK. Recovery emits *derived* output
  (recovered bytes to a new destination), never a mutation of the evidence.
- **Container layer only.** These crates decode the VMDK container to a byte stream;
  they do **not** parse the partition table or filesystem inside it — that is
  `mbr-forensic`/`gpt-forensic`/`disk-forensic` and the filesystem readers, fed the
  decoded bytes.
- **Not the examiner's front end.** The product-tier CLI/GUI is `disk4n6`/Issen; the
  `vmdk` binary here is a debug/inspection convenience.
- **No `unsafe`, no C library** (ADR 0006). VMDK decodes over `Read + Seek`, so the
  reader holds `unsafe_code = "forbid"` rather than a bounded-allow.
- **Lean default build** (ADR 0007). Full multibyte descriptor decoding, tracing, the
  VFS contract, and serde are optional features; the default reader is
  dependency-light for library reuse.

## Validation approach

Correctness is validated against **independent oracles**, not only self-authored
fixtures (see [`validation.md`](validation.md)):

- The real VMware-written `monolithicSparse` corpus image `dfvfs_ext2.vmdk` (from
  log2timeline/dfvfs, Apache-2.0) is read **byte-for-byte against
  `qemu-img convert -O raw`**.
- COWD and seSparse output is cross-validated against `qemu-img`'s independent
  reader, so the synthetic fixtures and this reader cannot share a blind spot.
- Four `cargo fuzz` targets (`fuzz_open`, `fuzz_read`, `fuzz_recover`,
  `fuzz_forensic`) exercise the untrusted-input paths in CI.
- Line coverage is enforced in CI (`cargo llvm-cov --workspace`).
