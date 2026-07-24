# 8. Separate the declared MSRV floor from the pinned dev toolchain

Date: 2026-07-24
Status: Accepted

## Context

The fleet MSRV policy separates two things that are easy to conflate: the **dev
toolchain** (what contributors and CI build/fmt/clippy with) and the **declared
MSRV** (`rust-version` — a downstream-facing compatibility promise). Published
libraries keep a low, CI-verified MSRV so older toolchains can still consume them,
while development happens on the current stable.

`vmdk-core` and `vmdk-forensic` are published library crates, so they carry a
declared MSRV; the workspace also pins a single dev toolchain for reproducible
fmt/clippy across contributors.

## Decision

- **Dev toolchain pinned to the fleet stable** — `rust-toolchain.toml` pins
  `channel = "1.96.0"` with `components = ["clippy", "rustfmt"]` (commit `67fbae6`,
  "pin toolchain to 1.96.0"). This is the single source of truth for what the repo
  builds and lints with locally and in CI.
- **Declared MSRV floor `1.85`** — set once in `[workspace.package]`
  (`rust-version = "1.85"`) and inherited by every member via
  `rust-version.workspace = true`. `edition` stays `2021`. This is the compatibility
  promise, lower than the dev pin, verified as a floor rather than tracking the
  drifting toolchain.

## Consequences

- Bumping the dev toolchain (a fleet-wide, deliberate action) does not silently
  raise the libraries' downstream MSRV promise; the two move independently.
- The MSRV floor is one edit for the whole workspace, kept in lockstep across the
  reader, analyzer, and CLI.

## Unrecovered rationale

The choice of **1.85** specifically (rather than the more common fleet library
floor of 1.75/1.80) is not explained in the available git history — no commit
message ties it to a named language feature or a transitive dependency's minimum.
Rationale reconstructed from structure; original intent not recovered in available
history. Treat 1.85 as the current CI-verified floor and lower it only if a
dependency audit shows the graph supports an older toolchain.
