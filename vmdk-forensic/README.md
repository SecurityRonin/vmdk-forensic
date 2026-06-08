# vmdk-forensic

[![Crates.io](https://img.shields.io/crates/v/vmdk-forensic.svg)](https://crates.io/crates/vmdk-forensic)
[![docs.rs](https://img.shields.io/docsrs/vmdk-forensic)](https://docs.rs/vmdk-forensic)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![CI](https://github.com/SecurityRonin/vmdk-core/actions/workflows/ci.yml/badge.svg)](https://github.com/SecurityRonin/vmdk-core/actions)
[![Sponsor](https://img.shields.io/badge/sponsor-h4x0r-ea4aaa?logo=github-sponsors)](https://github.com/sponsors/h4x0r)

Forensic integrity analysis for VMware VMDK images. The evidence-grade layer on top of the [`vmdk`](https://crates.io/crates/vmdk) reader — it **reparses the raw structure** (so it works on images too damaged to open cleanly) and reports the redundant-grain-directory, dangling-pointer, recovery, and header-provenance findings that `qemu-img` and `libvmdk` discard.

## Quick start

```toml
[dependencies]
vmdk-forensic = "0.1"
```

```rust
use vmdk_forensic::VmdkIntegrity;
use forensicnomicon::report::Severity;

let mut a = VmdkIntegrity::new(std::fs::File::open("disk.vmdk")?);

for finding in a.analyse()? {
    if finding.severity >= Some(Severity::Medium) {
        println!("[{:?}] {} — {}", finding.severity, finding.code, finding.note);
    }
}
# Ok::<(), std::io::Error>(())
```

## What it detects

`analyse()` aggregates every check into a severity-graded `Vec<Finding>` of
canonical [`forensicnomicon::report`](https://crates.io/crates/forensicnomicon)
findings (sorted worst-first), so VMDK findings normalize alongside every other
SecurityRonin analyzer. Each carries a stable `code`, a 5-level `severity`, a
`category`, and a plain-language `note`.

| Severity | `code` | Meaning |
|---|---|---|
| High | `VMDK-RGD-MISMATCH` | The redundant grain directory diverges from the primary — the grain tables they reference hold different contents (compared by **content**, not pointers, so healthy two-copy images don't false-positive). Consistent with MITRE ATT&CK T1565.001 |
| High | `VMDK-DANGLING-GT` | A grain-table pointer points beyond end-of-file (truncation or tampering) |
| High | `VMDK-DANGLING-GRAIN` | A grain pointer points beyond end-of-file |
| High | `VMDK-PRIMARY-GD-UNRECOVERABLE` | The primary grain directory is damaged with no RGD recovery available |
| High | `VMDK-FTP-ASCII-MANGLED` | Header newline-detection bytes were rewritten by an ASCII-mode FTP transfer |
| Medium | `VMDK-PRIMARY-GD-RECOVERABLE` | The primary grain directory is damaged but recoverable via the redundant copy |
| Low | `VMDK-UNCLEAN-SHUTDOWN` | `uncleanShutdown` flag set — the disk was not closed cleanly |

## Individual checks

Each finding is also available directly:

```rust
use vmdk_forensic::VmdkIntegrity;

let mut a = VmdkIntegrity::new(std::fs::File::open("disk.vmdk")?);

// Redundant-GD adjudication: are the grain tables the GD and RGD reference identical?
let rgd_ok = a.validate_rgd()?;

// Recovery triage: how much of a damaged primary GD can the RGD recover?
let rec = a.grain_directory_recovery()?;
println!("{} damaged, {} recoverable via RGD", rec.primary_damaged, rec.recoverable_via_rgd);

// Structural integrity: dangling GD/GT/grain pointers (VMDK4 sparse + seSparse).
let integ = a.check_integrity()?;
assert!(integ.is_ok());

// Header provenance: unclean-shutdown flag, FTP-ASCII-mangling, flag bits.
if let Some(p) = a.header_provenance()? {
    println!("unclean shutdown: {}", p.unclean_shutdown);
}
# Ok::<(), std::io::Error>(())
```

## Reader vs. analyzer

This is the same split as `vhdx`/`vhdx-forensic` and `ewf`/`ewf-forensic`:

- [`vmdk`](https://crates.io/crates/vmdk) — the lean `Read + Seek` reader. Use it to
  read virtual-disk bytes, including the opt-in RGD-fallback recovery read path.
- **`vmdk-forensic`** — this crate. Use it to audit an image before trusting it:
  tamper/corruption detection, recovery triage, and provenance. It re-exports
  `vmdk::VmdkReader`, so one dependency covers read + analysis.

## Security

Built to run on untrusted, potentially crafted images: every offset derived from a
header field uses saturating arithmetic and is bounds-checked before any read or
allocation; the grain-directory size is capped; zero `unsafe`.

---

[Privacy Policy](https://securityronin.github.io/vmdk-core/privacy/) · [Terms of Service](https://securityronin.github.io/vmdk-core/terms/) · © 2026 Security Ronin Ltd
