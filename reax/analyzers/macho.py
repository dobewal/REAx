"""Mach-O (macOS/iOS binary) analyzer: verdict-first static analysis.

Parses headers, segments, sections, dylibs, encryption info and the symbol
table by hand with struct — no external tools needed. Strictly read-only:
never executes the target.
"""

from __future__ import annotations

import math
import re
import struct
from typing import Any

LC_SEGMENT_64 = 0x19
LC_SYMTAB = 0x2
LC_LOAD_DYLIB = 0xC
LC_LOAD_WEAK_DYLIB = 0x18 | 0x800000
LC_RPATH = 0x1C
LC_ENCRYPTION_INFO_64 = 0x2C

CPU_TYPES = {0x0100000C: "ARM64", 0x01000007: "x86-64", 7: "x86", 12: "ARM"}
FILE_TYPES = {0x2: "executable", 0x6: "dylib", 0x8: "bundle", 0x3: "fixed VM lib"}

# symbol substring -> (severity, bucket, why)
DANGEROUS_SYMBOLS: list[tuple[str, int, str, str]] = [
    ("ptrace", 3, "stealth", "anti-debugging"),
    ("task_for_pid", 3, "code", "controls other processes"),
    ("dlopen", 2, "stealth", "loads code at runtime"),
    ("dlsym", 2, "stealth", "resolves symbols at runtime"),
    ("mmap", 2, "code", "maps memory (shellcode staging)"),
    ("mprotect", 2, "code", "changes memory protection"),
    ("execve", 3, "code", "executes programs"),
    ("system", 2, "code", "runs shell commands"),
    ("popen", 2, "code", "runs shell commands"),
    ("sysctl", 1, "stealth", "system introspection (sandbox check)"),
]

URL_RE = re.compile(rb"https?://[^\s'\"<>]{4,80}")
IP_RE = re.compile(rb"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def _shannon(data: bytes) -> float:
    if not data:
        return 0.0
    freq: dict[int, int] = {}
    for b in data:
        freq[b] = freq.get(b, 0) + 1
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


def _cstr(buf: bytes) -> str:
    return buf.split(b"\x00", 1)[0].decode(errors="replace")


def analyze_macho(path: str) -> dict[str, Any]:
    with open(path, "rb") as f:
        data = f.read()

    magic_bytes = data[:4]
    if magic_bytes == b"\xca\xfe\xba\xbe":  # fat binary — take first slice
        narch = struct.unpack(">I", data[4:8])[0]
        cputype, _, offset, size, _ = struct.unpack(">5I", data[8:28])
        data = data[offset:offset + size]
        fat_note = f"fat binary ({narch} archs) — analyzed first slice"
        magic_bytes = data[:4]
    else:
        fat_note = ""

    if magic_bytes == b"\xcf\xfa\xed\xfe":
        endian = "<"  # 64-bit little-endian
    elif magic_bytes == b"\xfe\xed\xfa\xcf":
        endian = ">"  # 64-bit big-endian
    else:
        raise ValueError("not a 64-bit Mach-O (32-bit/fat-32 unsupported)")

    e = endian
    (magic, cputype, cpusubtype, filetype, ncmds, sizeofcmds,
     flags, reserved) = struct.unpack(e + "IiiIIIII", data[:32])

    segments: list[dict[str, Any]] = []
    sections: list[dict[str, Any]] = []
    dylibs: list[str] = []
    rpaths: list[str] = []
    cryptid = 0
    symoff = nsyms = stroff = strsize = 0

    off = 32
    for _ in range(ncmds):
        if off + 8 > len(data):
            break
        cmd, cmdsize = struct.unpack(e + "II", data[off:off + 8])
        body = data[off + 8:off + cmdsize]
        if cmd == LC_SEGMENT_64 and len(body) >= 64:
            segname, vmaddr, vmsize, fileoff, filesize, maxprot, initprot, nsects, sflags = \
                struct.unpack(e + "16sQQQQiiII", body[:64])
            seg = _cstr(segname)
            segments.append({"name": seg, "vmsize": vmsize, "filesize": filesize,
                             "initprot": initprot})
            for i in range(nsects):
                s = body[64 + i * 80:64 + (i + 1) * 80]
                if len(s) < 80:
                    break
                # section_64: sectname(16) segname(16) addr(8) size(8) offset(4)
                #             align(4) reloff(4) nreloc(4) flags(4) reserved(3x4)
                (sectname, ssegname, addr, size, offset_, align, reloff,
                 nreloc, sflags2, _, _, _) = struct.unpack(e + "16s16sQQ" + "I" * 8, s)
                # section_64 is 80 bytes: 16+16+8+8+4*7 = 76? no: 16+16+8+8+4+4+4+4+4+4+4+4 = 80
                chunk = data[offset_:offset_ + size] if offset_ + size <= len(data) else b""
                sections.append({
                    "name": _cstr(sectname), "segment": _cstr(ssegname),
                    "size": size,
                    "entropy": round(_shannon(chunk[:65536]), 2),
                })
        elif cmd in (LC_LOAD_DYLIB, LC_LOAD_WEAK_DYLIB) and len(body) >= 16:
            name_off = struct.unpack(e + "I", body[:4])[0]
            dylibs.append(_cstr(body[name_off:]))
        elif cmd == LC_ENCRYPTION_INFO_64 and len(body) >= 16:
            _, _, cryptid, _ = struct.unpack(e + "IIII", body[:16])
        elif cmd == LC_SYMTAB and len(body) >= 16:
            symoff, nsyms, stroff, strsize = struct.unpack(e + "IIII", body[:16])
        elif cmd == LC_RPATH and len(body) >= 4:
            path_off = struct.unpack(e + "I", body[:4])[0]
            rpaths.append(_cstr(body[path_off:]))
        off += cmdsize

    # ---- symbol table ----
    symbols: list[str] = []
    if symoff and nsyms and stroff:
        strtab = data[stroff:stroff + strsize]
        for i in range(min(nsyms, 200000)):
            ent = data[symoff + i * 16:symoff + (i + 1) * 16]
            if len(ent) < 16:
                break
            n_strx = struct.unpack(e + "I", ent[:4])[0]
            if 0 < n_strx < len(strtab):
                symbols.append(_cstr(strtab[n_strx:]))

    suspicious: list[dict[str, Any]] = []
    for sym in symbols:
        base = sym.lstrip("_").lower()
        for sub, sev, bucket, why in DANGEROUS_SYMBOLS:
            if sub in base:
                suspicious.append({"symbol": sym, "severity": sev,
                                   "bucket": bucket, "why": why})
                break

    embedded_dylibs = [d for d in dylibs
                       if d.startswith(("@rpath", "@executable_path", "@loader_path"))]
    restrict = any(s["name"] == "__RESTRICT" and s["segment"] == "__RESTRICT"
                   for s in sections)

    urls = sorted({m.group(0).decode(errors="replace") for m in URL_RE.finditer(data)})[:20]
    ips = sorted({m.group(0).decode(errors="replace") for m in IP_RE.finditer(data)
                  if not m.group(0).startswith(b"0.")})[:20]

    # ---- scoring: 4 buckets x 25 ----
    findings: list[dict[str, str]] = []
    breakdown: dict[str, int] = {}

    code_pts = sum(s["severity"] for s in suspicious if s["bucket"] == "code") * 3
    code_pts += min(10, len(embedded_dylibs) * 5)
    breakdown["code"] = min(25, int(code_pts))
    top_code = sorted([s for s in suspicious if s["bucket"] == "code"],
                      key=lambda s: -s["severity"])[:3]
    if top_code:
        findings.append({"level": "high" if top_code[0]["severity"] >= 3 else "medium",
                         "text": "Dangerous symbols: " + "; ".join(
                             f"{s['symbol']} ({s['why']})" for s in top_code)})
    if embedded_dylibs:
        findings.append({"level": "medium",
                         "text": f"{len(embedded_dylibs)} embedded dylib(s): "
                                 f"{', '.join(embedded_dylibs[:3])}"})

    stealth = 0
    if cryptid != 0:
        stealth += 10
        findings.append({"level": "medium",
                         "text": "Encrypted (LC_ENCRYPTION_INFO cryptid=1) — App Store DRM, hides code"})
    if restrict:
        stealth += 8
        findings.append({"level": "medium",
                         "text": "__RESTRICT segment — anti-debugging / anti-tamper"})
    stealth += sum(s["severity"] for s in suspicious if s["bucket"] == "stealth") * 3
    breakdown["stealth"] = min(25, stealth)

    memory = 0
    rwx = [sg for sg in segments if sg["initprot"] & 0x7 == 0x7 and sg["filesize"] > 0]
    if rwx:
        memory += 15
        findings.append({"level": "high",
                         "text": f"RWX segment(s): {', '.join(s['name'] for s in rwx)}"})
    hot = [s for s in sections if s["entropy"] > 7.5 and s["size"] > 4096]
    if hot:
        memory += 8
        findings.append({"level": "medium",
                         "text": f"High-entropy section(s): {', '.join(s['name'] for s in hot)}"})
    breakdown["memory"] = min(25, memory)

    net_pts = min(8, len(urls) + len(ips))
    if any("CFNetwork" in d for d in dylibs):
        net_pts += 4
    breakdown["network"] = min(25, net_pts)

    score = sum(breakdown.values())
    grade = "low" if score < 25 else "medium" if score < 50 else "high" if score < 75 else "critical"

    return {
        "identity": {
            "arch": CPU_TYPES.get(cputype, f"0x{cputype:x}"),
            "kind": FILE_TYPES.get(filetype, f"type {filetype}"),
            "segments": len(segments),
            "sections": len(sections),
            "dylibs": len(dylibs),
            "encrypted": cryptid != 0,
            "fat_note": fat_note,
        },
        "symbols": {
            "count": len(symbols),
            "suspicious_count": len(suspicious),
            "items": sorted(suspicious, key=lambda s: -s["severity"])[:25],
        },
        "segments_info": {
            "segments": [{"name": s["name"], "size": s["filesize"]} for s in segments[:12]],
            "largest_sections": sorted(sections, key=lambda s: -s["size"])[:12],
            "dylibs": dylibs[:20],
            "rpaths": rpaths[:10],
        },
        "network_indicators": {"urls": urls, "ips": ips},
        "risk": {"score": score, "grade": grade, "findings": findings[:8], "breakdown": breakdown},
    }
