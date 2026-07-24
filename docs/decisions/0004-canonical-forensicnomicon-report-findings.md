# 4. Emit canonical `forensicnomicon::report::Finding`, keep the typed `AnomalyKind`

Date: 2026-07-24
Status: Accepted

## Context

Every analyzer in the fleet must surface its findings through one shared reporting
model so orchestration (Issen, disk-forensic) and a future GUI render them
uniformly instead of N bespoke `XxxAnalysis` types. That model is
`forensicnomicon::report` (`Severity`, `Category`, `Finding`, `Code`). Before
commit `516dc70`, `vmdk-forensic` returned its own analysis types; that commit
(`feat(vmdk-forensic)!: emit canonical forensicnomicon::report findings`, a
breaking change) migrated it to the canonical vocabulary.

The fleet reporting-model standard prescribes the producer pattern: an analyzer
*keeps* its typed domain enum (its real knowledge) and *converts* to canonical
findings — `forensicnomicon` never enumerates every anomaly kind.

## Decision

`vmdk-forensic` keeps the typed `AnomalyKind` enum (its VMDK-specific domain
knowledge) and converts each variant to a `forensicnomicon::report::Finding` via
inherent `severity()`/`category()`/`code()`/`note()` methods
(`forensic/src/lib.rs`). `analyse()` returns `Vec<Finding>`. Codes are the
published, scheme-prefixed SCREAMING-KEBAB contract:

- `VMDK-RGD-MISMATCH`
- `VMDK-UNCLEAN-SHUTDOWN`
- `VMDK-FTP-ASCII-MANGLED`
- `VMDK-PRIMARY-GD-RECOVERABLE`
- `VMDK-PRIMARY-GD-UNRECOVERABLE`
- `VMDK-DANGLING-GT`
- `VMDK-DANGLING-GRAIN`

Findings are observations, never legal conclusions; the reporting layer/analyst
concludes.

## Consequences

- VMDK findings aggregate into one `forensicnomicon::report::Report` alongside every
  other fleet analyzer with no adapter code in the orchestrator.
- The seven codes are a stable external contract — a shipped code is never changed;
  a new anomaly gets a new code.
- `vmdk-forensic` depends directly on `forensicnomicon` (the leaf), and the `serde`
  feature threads through to `forensicnomicon/serde` so findings serialize into the
  CLI's `--json` output.
