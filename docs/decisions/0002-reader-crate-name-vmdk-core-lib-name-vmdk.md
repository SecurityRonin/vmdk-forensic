# 2. Publish the reader as `vmdk-core`, import it as `vmdk`

Date: 2026-07-24
Status: Accepted

## Context

The reader was first published to crates.io under the bare name `vmdk` (tags up to
`vmdk 0.6.1`, e.g. commit `ff9289e`). The fleet crate-naming grammar
(`~/src/ronin-issen/CLAUDE.md`) then fixed one shape for every single-format repo:
the reader crate is `<x>-core` and the analyzer is `<x>-forensic`, so consumers
recognize the reader/analyzer pair from the package name alone on crates.io. A
crate named plain `vmdk` does not signal "the reader half of the vmdk-forensic
suite", and it breaks the symmetry every other container repo (`ewf`/`ewf-forensic`,
`vhdx`/`vhdx-forensic`, `qcow2`/`qcow2-forensic`) follows.

At the same time, `use vmdk::…` is the natural, ergonomic import for consumers, and
churning it to `vmdk_core` would break every downstream `use` for no reader-facing
benefit.

## Decision

Publish the reader crate as **`vmdk-core`** while keeping the library's import path
as **`vmdk`** via `[lib] name = "vmdk"` in `core/Cargo.toml`. Consumers still write
`use vmdk::VmdkReader;` (`cargo add vmdk-core`), and the crates.io package
self-describes as the core of the suite. The rename shipped in commits `13ae44a`
("rename reader crate vmdk -> vmdk-core 0.6.3 (imported as vmdk)") and `38916d5`
(repo rename `vmdk` → `vmdk-core`), and the repo was then renamed again to
`vmdk-forensic` (analyzer-headline) in `914237d` per the same standard.

The inter-crate dependency is declared once in `[workspace.dependencies]`:
`vmdk = { path = "core", version = "0.8.0", package = "vmdk-core" }`, so the import
alias and the published package name are wired in a single place.

## Consequences

- The import path is stable (`vmdk`) across the rename; downstream `use` lines were
  unaffected.
- The crates.io listing reads as a matched pair (`vmdk-core` reader +
  `vmdk-forensic` analyzer), consistent with the rest of the fleet.
- This burned the bare `vmdk` crates.io name during the pre-1.0 window; the package
  is now permanently `vmdk-core`. Renaming again would be a new-package event.
