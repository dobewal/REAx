"""PE (Windows executable) analyzer: verdict-first static analysis.

Parses headers, imports, sections and data directories with pefile.
Also detects .NET (managed) assemblies via the CLR data directory.
Strictly read-only — never executes the target.
"""

from __future__ import annotations

import math
import re
from typing import Any

# (api name, severity, bucket, plain-English why)
WIN_APIS: list[tuple[str, int, str, str]] = [
    ("VirtualAlloc", 3, "code", "allocates executable memory (shellcode staging)"),
    ("VirtualProtect", 3, "code", "changes memory protection (unpacking)"),
    ("WriteProcessMemory", 3, "code", "writes into another process (injection)"),
    ("ReadProcessMemory", 2, "code", "reads another process' memory"),
    ("CreateRemoteThread", 3, "code", "runs code inside another process"),
    ("CreateRemoteThreadEx", 3, "code", "runs code inside another process"),
    ("NtUnmapViewOfSection", 3, "code", "hollows out a process (process hollowing)"),
    ("ZwUnmapViewOfSection", 3, "code", "hollows out a process (process hollowing)"),
    ("SetWindowsHookEx", 2, "code", "installs system-wide hooks (keylogging)"),
    ("CreateProcess", 2, "code", "spawns processes"),
    ("WinExec", 2, "code", "spawns processes"),
    ("ShellExecute", 2, "code", "spawns processes / opens URLs"),
    ("GetProcAddress", 2, "code", "resolves APIs at runtime (evades static import scan)"),
    ("LoadLibrary", 2, "code", "loads DLLs at runtime"),
    ("RegSetValue", 2, "code", "writes registry (persistence)"),
    ("RegCreateKey", 2, "code", "creates registry keys (persistence)"),
    ("IsDebuggerPresent", 2, "stealth", "anti-debugging check"),
    ("CheckRemoteDebuggerPresent", 2, "stealth", "anti-debugging check"),
    ("NtQueryInformationProcess", 2, "stealth", "anti-debugging / sandbox check"),
    ("GetTickCount", 1, "stealth", "timing check (sandbox evasion)"),
    ("URLDownloadToFile", 3, "network", "downloads files from the internet"),
    ("InternetOpenUrl", 3, "network", "opens remote URLs"),
    ("HttpSendRequest", 2, "network", "sends HTTP requests"),
    ("WinHttpOpen", 2, "network", "HTTP client"),
    ("WSAStartup", 2, "network", "initializes networking (sockets)"),
    ("socket", 2, "network", "raw socket use"),
    ("connect", 2, "network", "outbound connections"),
    ("send", 1, "network", "sends network data"),
    ("recv", 1, "network", "receives network data"),
]

PACKER_SECTIONS = ("UPX0", "UPX1", "UPX2", ".aspack", ".adata", ".themida",
                   ".vmp0", ".vmp1", ".enigma", ".petite", ".mpress")

DOTNET_OBFUSCATORS = ("Confuser", ".NETGuard", "SmartAssembly", "Dotfuscator",
                      "BabelObfuscator", "CryptoObfuscator", "Eazfuscator")

URL_RE = re.compile(rb"https?://[^\s'\"<>]{4,80}")
IP_RE = re.compile(rb"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def _shannon(data: bytes) -> float:
    if not data:
        return 0.0
    freq = {}
    for b in data:
        freq[b] = freq.get(b, 0) + 1
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


def analyze_pe(path: str) -> dict[str, Any]:
    import pefile

    with open(path, "rb") as f:
        raw = f.read()
    pe = pefile.PE(data=raw, fast_load=False)

    machine = pe.FILE_HEADER.Machine
    arch = {0x14C: "x86", 0x8664: "x86-64", 0xAA64: "ARM64"}.get(machine, f"0x{machine:x}")
    is_dll = bool(pe.FILE_HEADER.Characteristics & 0x2000)
    kind = "DLL" if is_dll else "EXE"

    # ---- imports ----
    imports: list[dict[str, Any]] = []
    try:
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            dll = entry.dll.decode(errors="replace")
            for imp in entry.imports:
                name = imp.name.decode(errors="replace") if imp.name else f"ordinal_{imp.ordinal}"
                imports.append({"dll": dll, "function": name})
    except AttributeError:
        pass
    try:
        for entry in pe.DIRECTORY_ENTRY_DELAY_IMPORT:
            dll = entry.dll.decode(errors="replace")
            for imp in entry.imports:
                name = imp.name.decode(errors="replace") if imp.name else f"ordinal_{imp.ordinal}"
                imports.append({"dll": dll, "function": name, "delayed": True})
    except AttributeError:
        pass

    suspicious: list[dict[str, Any]] = []
    for imp in imports:
        fn = imp["function"]
        # real binaries usually import the ANSI/Unicode variant (FooA/FooW),
        # so match the base name too — otherwise e.g. URLDownloadToFileA
        # slips past the network bucket entirely.
        names = {fn.lower()}
        if len(fn) > 2 and fn[-1] in "AWaw":
            names.add(fn[:-1].lower())
        for api, sev, bucket, why in WIN_APIS:
            if api.lower() in names:
                suspicious.append({**imp, "severity": sev, "bucket": bucket, "why": why})
                break

    # ---- sections ----
    secs = []
    for s in pe.sections:
        name = s.Name.decode(errors="replace").rstrip("\x00")
        chars = s.Characteristics
        secs.append({
            "name": name,
            "size": s.SizeOfRawData,
            "entropy": round(s.get_entropy(), 2),
            "rwx": (chars & 0xE0000000) == 0xE0000000,  # READ|WRITE|EXECUTE
            "executable": bool(chars & 0x20000000),
        })

    packers = [n for n in PACKER_SECTIONS
               if any(n.lower() in s["name"].lower() for s in secs)]

    # ---- TLS callbacks (common in packed / anti-debug binaries) ----
    tls_callbacks = 0
    try:
        tls = pe.DIRECTORY_ENTRY_TLS.struct
        if tls.AddressOfCallBacks:
            tls_callbacks = 1  # presence is the signal; count needs VA mapping
    except AttributeError:
        pass

    # ---- .NET detection ----
    dotnet = False
    dotnet_version = ""
    try:
        clr = pe.OPTIONAL_HEADER.DATA_DIRECTORY[14]
        dotnet = clr.VirtualAddress != 0 and clr.Size != 0
    except (AttributeError, IndexError):
        pass
    dotnet_obfuscator = ""
    if dotnet:
        ascii_blob = raw.decode("ascii", errors="ignore")
        m = re.search(r"v\d+\.\d+\.\d+", ascii_blob)
        if m:
            dotnet_version = m.group(0)
        for sig in DOTNET_OBFUSCATORS:
            if sig.lower() in ascii_blob.lower():
                dotnet_obfuscator = sig
                break

    # ---- network strings ----
    urls = sorted({m.group(0).decode(errors="replace") for m in URL_RE.finditer(raw)})[:20]
    ips = sorted({m.group(0).decode(errors="replace") for m in IP_RE.finditer(raw)
                  if not m.group(0).startswith(b"0.")})[:20]

    # ---- scoring: 4 buckets x 25 ----
    findings: list[dict[str, str]] = []
    breakdown: dict[str, int] = {}

    code_pts = sum(s["severity"] for s in suspicious if s["bucket"] == "code") * 3
    breakdown["code"] = min(25, int(code_pts))
    top_code = sorted([s for s in suspicious if s["bucket"] == "code"],
                      key=lambda s: -s["severity"])[:3]
    if top_code:
        findings.append({"level": "high" if top_code[0]["severity"] >= 3 else "medium",
                         "text": "Dangerous Windows APIs: " + "; ".join(
                             f"{s['function']} ({s['why'].split(' (')[0]})" for s in top_code)})

    stealth = 0
    if packers:
        stealth += 10
        findings.append({"level": "high",
                         "text": f"Packer signature: {', '.join(packers)} — packed binaries hide their real code"})
    if tls_callbacks:
        stealth += 8
        findings.append({"level": "medium", "text": "TLS callbacks present — code runs before main (anti-debug/packer trait)"})
    stealth += sum(s["severity"] for s in suspicious if s["bucket"] == "stealth") * 2
    if dotnet_obfuscator:
        stealth += 6
        findings.append({"level": "medium",
                         "text": f".NET obfuscator signature: {dotnet_obfuscator}"})
    breakdown["stealth"] = min(25, stealth)

    memory = 0
    rwx = [s for s in secs if s["rwx"]]
    if rwx:
        memory += 15
        findings.append({"level": "high",
                         "text": f"{len(rwx)} RWX section(s) ({', '.join(s['name'] for s in rwx)}) — writable AND executable memory"})
    hot = [s for s in secs if s["entropy"] > 7.5 and s["size"] > 4096]
    if hot:
        memory += 8
        findings.append({"level": "medium",
                         "text": f"High-entropy section(s): {', '.join(s['name'] for s in hot)} — likely packed/encrypted"})
    breakdown["memory"] = min(25, memory)

    net_pts = sum(s["severity"] for s in suspicious if s["bucket"] == "network") * 4
    net_pts += min(8, len(urls) + len(ips))
    breakdown["network"] = min(25, int(net_pts))
    top_net = sorted([s for s in suspicious if s["bucket"] == "network"],
                     key=lambda s: -s["severity"])[:2]
    if top_net:
        findings.append({"level": "medium",
                         "text": "Network-capable APIs: " + ", ".join(s["function"] for s in top_net)})

    if dotnet:
        findings.append({"level": "low",
                         "text": f".NET managed assembly (CLR {dotnet_version or 'unknown version'}) — "
                                 "analyze with a .NET decompiler for full method view"})

    score = sum(breakdown.values())
    grade = "low" if score < 25 else "medium" if score < 50 else "high" if score < 75 else "critical"

    return {
        "identity": {
            "arch": arch, "kind": kind,
            "sections": len(secs),
            "imports": len(imports),
            "dotnet": dotnet,
            "dotnet_version": dotnet_version,
        },
        "imports": {
            "count": len(imports),
            "suspicious_count": len(suspicious),
            "items": sorted(suspicious, key=lambda s: -s["severity"])[:25],
        },
        "sections_info": {
            "count": len(secs),
            "largest": sorted(secs, key=lambda s: -s["size"])[:12],
            "packers": packers,
            "tls_callbacks": tls_callbacks,
        },
        "dotnet_info": {
            "is_dotnet": dotnet,
            "version": dotnet_version,
            "obfuscator": dotnet_obfuscator,
        },
        "network_indicators": {"urls": urls, "ips": ips},
        "risk": {"score": score, "grade": grade, "findings": findings[:8], "breakdown": breakdown},
    }
