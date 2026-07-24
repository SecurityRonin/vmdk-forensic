# 3. The forensic layer reparses the raw structure, below the reader API

Date: 2026-07-24
Status: Accepted

## Context

`vmdk-core` is built to read *valid* images robustly: it normalizes, clamps, and
zero-fills so a healthy disk decodes cleanly. Those are exactly the behaviours a
forensic auditor must *not* inherit — an integrity analyzer needs to see the raw
`SparseExtentHeader`, the redundant grain directory, dangling pointers, and
FTP-mangled headers *as they are on disk*, not as the reader's happy-path view
presents them. The fleet crate-structure standard makes this a binding principle:
"`-forensic` is NOT required to depend on `-core`... it may need to go lower...
Never contort an audit through a happy-path reader API that hides the very anomaly
it is hunting."

## Decision

`vmdk-forensic` depends on `vmdk-core` (`forensic/Cargo.toml`:
`vmdk = { workspace = true }`) but consumes its **low-level structural modules**
(`vmdk::header`, `vmdk::sesparse`) and reparses header/grain-directory bytes in
situ, rather than driving the `VmdkReader` `Read + Seek` data API. The crate's own
doc comment states the rationale: "it reparses the raw structure — so it works on
images too damaged for some readers." `VmdkIntegrity::analyse()` walks the
grain-directory / grain-table pointers directly (with its own `MAX_GD_BYTES` cap)
to detect out-of-bounds grains, dangling tables, RGD mismatch, unclean shutdown,
and header mangling.

## Consequences

- The analyzer produces findings on images too corrupt for the reader's normal
  decode path to open cleanly.
- `vmdk-core` must keep its low-level parsers (`header`, `sesparse`) `pub` for the
  analyzer to reach; they are part of the reader's API contract, not private.
- Some header parsing exists in two places (reader decode vs. forensic reparse) by
  design — the auditor cannot share the reader's normalization without blinding
  itself to the anomalies it exists to find.
