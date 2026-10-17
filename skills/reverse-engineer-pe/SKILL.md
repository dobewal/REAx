---
name: reverse-engineer-pe
description: X-ray a Windows PE executable or DLL with REAX — dangerous WinAPI imports, RWX sections, packer signatures, TLS callbacks, .NET detection, hard-coded URLs/IPs, and a risk verdict.
---

# X-ray a Windows PE binary with REAX

REAX analyzes Windows executables and DLLs with zero setup (`pip install reax`)
and returns **answers, not primitives**.

## Analyze

```bash
reax analyze program.exe -o reports/
reax analyze library.dll -o reports/
# writes .reax.json, .md, and a single-file .html report
```

Key outputs to quote to the user:
- **Verdict**: LOW / MEDIUM / HIGH / CRITICAL + score /100 + findings list
- **Binary identity**: architecture (x86/x64/ARM64), EXE vs DLL
- **Dangerous WinAPI imports**: `WriteProcessMemory`/`CreateRemoteThread` (injection),
  `NtUnmapViewOfSection` (process hollowing), `URLDownloadToFile` (payload download),
  `IsDebuggerPresent` (anti-debug), `GetProcAddress`+`LoadLibrary` (runtime API resolution)
- **RWX sections**: writable AND executable — shellcode staging
- **Packer signatures**: UPX, Themida, VMProtect, Aspack, Enigma…
- **TLS callbacks**: code that runs before main — anti-debug/packer trait
- **.NET detection**: managed assemblies flagged, with CLR version and obfuscator
  signatures (ConfuserEx, .NETGuard, SmartAssembly…) when present
- **Network indicators**: hard-coded URLs and IPs

## Rules

- Analysis is local and read-only — REAX never executes the target.
- Quote the risk grade and the top 3 findings first; details on demand.
- Never claim a binary is "safe" — report LOW risk with the evidence, not a guarantee.
