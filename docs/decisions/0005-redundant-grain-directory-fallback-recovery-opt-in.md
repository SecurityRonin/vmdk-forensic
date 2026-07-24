# 5. Redundant-grain-directory fallback recovery — opt-in, safe by default

Date: 2026-07-24
Status: Accepted

## Context

VMware writes the grain tables **twice**: the primary grain directory (GD) and a
redundant copy (RGD) point to separate physical copies of the grain tables. When
the primary GD is damaged, `qemu-img` and `libvmdk` read only the primary and fail
— the data behind the corruption is unreadable to them even though an intact
second copy exists on disk. Recovering that data is this project's headline
differentiator for a forensic examiner working a damaged image.

But recovery must never silently alter a *healthy* read. Transparently substituting
the RGD on every read would mask real corruption and violate the forensic
requirement that a normal read reflects exactly what the primary structure says.

## Decision

Ship RGD-fallback recovery as an **opt-in** mode on the reader, off by default:

- `VmdkReader::enable_rgd_fallback()` turns it on; reads then resolve damaged
  primary pointers through the redundant copy, and `rgd_recovery_count()` reports
  how many grains were recovered (`core/src/recovery.rs`, README "Forensic
  recovery").
- With recovery **off** (the default), a dangling pointer simply errors — the safe
  default: a corrupt structure is surfaced as an error, not papered over.
- The companion `vmdk-forensic` triages *before* recovery: `GdRecoveryReport`
  quantifies how much of the primary GD the RGD can recover
  (`VMDK-PRIMARY-GD-RECOVERABLE` / `-UNRECOVERABLE`), and validates the RGD's
  grain-table **contents**, not just its pointers.

Recovery reads are additionally hardened: a grain-clamp prevents a sparse grain
from zero-masking an allocated grain later in the same read (commit `fc752b7`,
P0 fix — see ADR 0006).

## Consequences

- An examiner recovers guest data from behind a damaged primary GD that other
  readers give up on, then pipes the bytes into a filesystem parser.
- A healthy read is byte-identical whether or not recovery is compiled/enabled;
  turning recovery on cannot change a sound image's output.
- The two-step model (triage with `vmdk-forensic`, then recover with the reader)
  keeps "how bad is it?" separate from "read through it", so the analyst sees the
  damage before deciding to read past it.
