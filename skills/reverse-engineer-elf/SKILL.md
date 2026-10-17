---
name: reverse-engineer-elf
description: X-ray an ELF binary or shared library with REAX — architecture, suspicious imports, RWX segments, section entropy, packer signatures, hard-coded URLs/IPs, and a risk verdict.
---

# X-ray an ELF binary with REAX

REAX analyzes native binaries and `.so` libraries with zero setup (`pip install reax`)
and returns **answers, not primitives**.

## Analyze

```bash
reax analyze lib.so -o reports/
reax analyze program -o reports/
# writes .reax.json, .md, and a single-file .html report
```

Key outputs to quote to the user:
- **Verdict**: LOW / MEDIUM / HIGH / CRITICAL + score /100 + findings list
- **Binary identity**: architecture, bitness, type (executable vs shared library), stripped or not
- **Suspicious imports**: `ptrace` (anti-debug), `execve`/`system` (command execution),
  `mprotect`/`mmap` (packing/injection), `dlopen` (dynamic code loading) — with plain-English explanations
- **RWX segments**: memory marked readable+writable+executable — a classic injection primitive
- **Section entropy**: high-entropy sections flagged as possibly packed or encrypted
- **Packer signatures**: e.g. UPX
- **Network indicators**: hard-coded URLs and IPs extracted from the binary

## Combine with APK analysis

An APK's real secrets usually hide in its native libraries. Workflow:

```bash
reax analyze app.apk -o reports/   # flags suspicious .so files
reax analyze lib/suspicious.so -o reports/   # X-ray the library itself
```

## Rules

- Analysis is local and read-only — REAX never executes the target.
- Quote the risk grade and the top 3 findings first; details on demand.
- Never claim a binary is "safe" — report LOW risk with the evidence, not a guarantee.
