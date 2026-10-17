---
name: reverse-engineer-macho
description: X-ray a macOS/iOS Mach-O binary with REAX — architecture, suspicious symbols, encrypted binaries, embedded dylibs, section entropy, hard-coded URLs/IPs, and a risk verdict.
---

# X-ray a Mach-O binary with REAX

REAX analyzes macOS/iOS executables, dylibs, and bundles with zero setup
(`pip install reax`) — pure-Python Mach-O parsing, no external tools —
and returns **answers, not primitives**.

## Analyze

```bash
reax analyze program -o reports/       # macOS executable
reax analyze lib.dylib -o reports/     # dynamic library
# writes .reax.json, .md, and a single-file .html report
```

Key outputs to quote to the user:
- **Verdict**: LOW / MEDIUM / HIGH / CRITICAL + score /100 + findings list
- **Binary identity**: architecture (ARM64/x86-64), executable vs dylib vs bundle
- **Suspicious symbols**: `ptrace` (anti-debug), `task_for_pid` (process control),
  `dlopen`/`dlsym` (runtime code loading), `execve`/`system` (command execution)
- **Encrypted binaries**: App Store DRM (`cryptid=1`) hides the real code
- **__RESTRICT segment**: anti-debugging / anti-tamper marker
- **Embedded dylibs**: `@rpath`/`@executable_path` dylibs shipped inside the app
- **Section entropy**: high-entropy sections flagged as possibly packed
- **Network indicators**: hard-coded URLs and IPs

## Rules

- Analysis is local and read-only — REAX never executes the target.
- Quote the risk grade and the top 3 findings first; details on demand.
- Never claim a binary is "safe" — report LOW risk with the evidence, not a guarantee.
