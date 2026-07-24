# 7. Lean reader core — encoding, tracing, VFS, and serde behind optional features

Date: 2026-07-24
Status: Accepted

## Context

`vmdk-core` is a container reader other fleet *libraries* link, so it should keep a
low dependency footprint and a low MSRV floor (ADR 0008) by default, while still
exposing heavier capabilities to the consumers that want them. Three capabilities
pull weight only some consumers need: full multibyte descriptor decoding
(`encoding_rs`), structured tracing (`tracing`), and the fleet VFS contract
(`forensic-vfs`). The fleet batteries-included rule says the *analysis* layer and
the shipping *binary* must be fully capable; it does not require every optional
dependency to be compiled into the lean reader that third parties link.

## Decision

Keep the reader's default build lean and gate optional capabilities behind Cargo
features (`core/Cargo.toml`):

- **`full-encoding`** (`dep:encoding_rs`) — full Shift_JIS / GBK / Big5 / … decode
  of multibyte descriptors. **Off by default:** the default build decodes
  UTF-8 + windows-1252 dependency-free, which covers the common case; the decode is
  encoding-aware and never silently swallows an undecodable descriptor (commits
  `5799b39`, `c33f6b5`).
- **`trace`** (`dep:tracing`) — forwards internal diagnostics to the `tracing`
  ecosystem. Off by default (zero logging dep).
- **`vfs`** (`dep:forensic-vfs`) — implements the `forensic-vfs` `ImageSource`
  contract (`core/src/vfs.rs`) so a decoded VMDK composes directly into the fleet
  VFS stack (`E01 → GPT → … → filesystem` as one `ImageSource`). Off by default
  (optional `forensic-vfs 0.3` dep; commits `7d88926`, `f7c660e`, `70f2c97`).
- **`serde`** — derives on the public report types, off by default.
- **`test-helpers`** — exposes `vmdk::testutil` for downstream fixture synthesis.

Consumers that need full capability (the CLI, the analyzer, an examiner build) turn
the relevant features on; the lean default is reserved for library reuse.

## Consequences

- A library that links `vmdk-core` for plain reads pulls no `encoding_rs`,
  `tracing`, or `forensic-vfs`, keeping its graph and MSRV floor small.
- A decoded VMDK plugs into `forensic-vfs` without the reader carrying that
  dependency by default; the VFS adapter wraps the `&mut self` reader behind a
  poison-recovering `Mutex` to satisfy the `&self` `read_at` contract.
- Descriptors in unsupported multibyte encodings degrade honestly on the default
  build (surfaced, not silently mis-decoded) unless `full-encoding` is enabled.
