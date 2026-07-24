# 1. Reader/analyzer split — `core/` + `forensic/` in one workspace

Date: 2026-07-24
Status: Accepted

## Context

VMDK support spans two distinct concerns: (1) *reading* a virtual disk — decode
the container to a plain byte stream, robustly, on valid images — and (2)
*auditing* it for tampering, corruption, and recoverability, which needs to see
exactly the raw layout a robust reader normalizes away. A single crate would
force a downstream tool that only wants "give me the bytes" to compile the whole
forensic surface, and would couple the medium-agnostic reader to the analyzer.

The SecurityRonin fleet standardized this as the crate-structure standard
(reference impl `ntfs-forensic`): one workspace repo named `<x>-forensic` with a
`core/` reader crate and a `forensic/` analyzer crate. This repo was realigned to
that shape in commit `914237d` ("refactor: align to core/forensic workspace
standard").

## Decision

Ship **one workspace** (`Cargo.toml` `members = ["core", "forensic", "cli"]`) with:

- **`core/` → crate `vmdk-core`** — the read-only reader. Exposes the decoded
  virtual disk as `Read + Seek` (`VmdkReader`, `VmdkFileReader`,
  `VmdkChainReader`) plus provenance accessors. No findings.
- **`forensic/` → crate `vmdk-forensic`** — the integrity analyzer. Owns the
  typed `AnomalyKind` and `analyse()`, emitting `forensicnomicon::report::Finding`
  (ADR 0004). It re-exports the reader (`pub use vmdk::VmdkReader`) so one
  `cargo add vmdk-forensic` covers read + audit.
- **`cli/` → crate `vmdk-cli`** (binary `vmdk`) — a debug/inspection front end.
  Per the fleet standard the examiner-facing tool remains `disk4n6`/Issen; this
  member is a developer convenience, not a product surface.

Shared fields (version, edition, MSRV, license, dependency versions) live once in
`[workspace.package]` / `[workspace.dependencies]` (DRY); each member inherits via
`field.workspace = true`.

## Consequences

- A Rust tool that only needs the bytes depends on `vmdk-core` alone and never
  compiles the forensic layer.
- The analyzer and reader version and release together from one workspace, so a
  format change and its audit stay in lockstep.
- The three-member layout is fixed; a new capability lands as a module inside an
  existing crate, not a fourth member, unless it is a genuinely separable concern.
