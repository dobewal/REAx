"""ELF analyzer: X-ray native binaries and shared libraries.

Pure-Python via pyelftools — no external tools to install.
"""

from __future__ import annotations

import math
import re
from collections import Counter
from typing import Any

# imported function -> (severity 1-3, why it matters)
SUSPICIOUS_IMPORTS: dict[str, tuple[int, str]] = {
    "ptrace": (3, "anti-debug / anti-tamper"),
    "execve": (2, "executes other programs"),
    "execvp": (2, "executes other programs"),
    "execl": (2, "executes other programs"),
    "system": (2, "runs shell commands"),
    "popen": (2, "runs shell commands"),
    "mmap": (2, "memory mapping (packing / injection)"),
    "mprotect": (2, "changes memory protection (packing / injection)"),
    "dlopen": (2, "loads code dynamically at runtime"),
    "dlsym": (2, "resolves symbols dynamically (hiding imports)"),
    "socket": (1, "network communication"),
    "connect": (2, "outbound network connections"),
    "gethostbyname": (1, "DNS resolution"),
    "getaddrinfo": (1, "DNS resolution"),
    "fork": (1, "spawns processes"),
    "clone": (1, "spawns processes/threads"),
    "kill": (2, "can terminate processes"),
    "chmod": (1, "changes file permissions"),
    "unlink": (1, "deletes files"),
    "remove": (1, "deletes files"),
    "open": (1, "file access"),
    "openat": (1, "file access"),
    "read": (1, "reads files/descriptors"),
    "write": (1, "writes files/descriptors"),
}

_IGNORE = {
    "__libc_start_main", "__cxa_finalize", "__cxa_atexit", "__gmon_start__",
    "_ITM_deregisterTMCloneTable", "_ITM_registerTMCloneTable",
    "__stack_chk_fail", "abort", "exit", "_exit", "malloc", "free",
    "calloc", "realloc", "memcpy", "memset", "memmove", "strlen",
    "strcmp", "strncmp", "strcpy", "strncpy", "strcat", "printf",
    "fprintf", "sprintf", "snprintf", "fopen", "fclose", "fread",
    "fwrite", "pthread_create", "pthread_join", "pthread_mutex_lock",
    "pthread_mutex_unlock", "mmap64",
}

_URL_RE = re.compile(rb"https?://[^\s'\"<>\\]{4,120}")
_IP_RE = re.compile(rb"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_PRINTABLE_RE = re.compile(rb"[\x20-\x7e]{6,}")
_UPX_MAGIC = (b"UPX!", b"UPX0", b"UPX1", b"UPX2")

_MACHINE_NAMES = {
    "EM_X86_64": "x86-64", "EM_386": "x86", "EM_AARCH64": "AArch64",
    "EM_ARM": "ARM", "EM_MIPS": "MIPS", "EM_RISCV": "RISC-V",
    "EM_PPC64": "PowerPC64", "EM_SPARC": "SPARC",
}
_TYPE_NAMES = {
    "ET_EXEC": "executable", "ET_DYN": "shared library",
    "ET_REL": "relocatable object", "ET_CORE": "core dump",
}


def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def analyze_elf(path: str) -> dict[str, Any]:
    from elftools.elf.elffile import ELFFile
    from elftools.elf.sections import SymbolTableSection

    ev: dict[str, Any] = {}
    with open(path, "rb") as f:
        raw = f.read()
    with open(path, "rb") as f:
        elf = ELFFile(f)
        hdr = elf.header
        machine = hdr["e_machine"]
        etype = hdr["e_type"]

        ev["identity"] = {
            "format": "ELF",
            "arch": _MACHINE_NAMES.get(machine, machine),
            "bits": elf.elfclass,
            "endian": "little" if elf.little_endian else "big",
            "type": _TYPE_NAMES.get(etype, etype),
            "stripped": elf.get_section_by_name(".symtab") is None,
        }

        # ---- imports / exports / needed libs ----
        imported: list[str] = []
        exported: list[str] = []
        needed: list[str] = []
        for section in elf.iter_sections():
            if isinstance(section, SymbolTableSection):
                is_dyn = section.name == ".dynsym"
                for sym in section.iter_symbols():
                    name = sym.name
                    if not name or name in _IGNORE or name.startswith("_"):
                        continue
                    st_type = sym["st_info"]["type"]
                    if st_type != "STT_FUNC":
                        continue
                    if sym["st_shndx"] == "SHN_UNDEF":
                        if is_dyn:
                            imported.append(name)
                    elif sym["st_info"]["bind"] != "STB_LOCAL":
                        exported.append(name)
        dyn = elf.get_section_by_name(".dynamic")
        if dyn is not None:
            for tag in dyn.iter_tags():
                if tag.entry.d_tag == "DT_NEEDED":
                    needed.append(tag.needed)

        imp_rows = []
        for name in sorted(set(imported)):
            base = name.split("@")[0]
            sev, why = SUSPICIOUS_IMPORTS.get(base, (0, ""))
            imp_rows.append({"function": name, "severity": sev, "why": why})
        imp_rows.sort(key=lambda r: (-r["severity"], r["function"]))
        ev["imports"] = {
            "count": len(set(imported)),
            "suspicious_count": sum(1 for r in imp_rows if r["severity"] > 0),
            "items": imp_rows,
            "libraries": sorted(set(needed)),
        }
        ev["exports"] = {"count": len(set(exported)), "items": sorted(set(exported))[:100]}

        # ---- sections + entropy ----
        sec_rows = []
        high_entropy = []
        for section in elf.iter_sections():
            try:
                data = section.data()
            except Exception:
                data = b""
            size = section["sh_size"]
            ent = _entropy(data[:1_000_000]) if size else 0.0
            flags = section["sh_flags"]
            sec_rows.append({
                "name": section.name or "(unnamed)",
                "size": size,
                "entropy": round(ent, 2),
                "write": bool(flags & 0x1),
                "exec": bool(flags & 0x4),
            })
            if size > 4096 and ent > 7.5:
                high_entropy.append(section.name or "(unnamed)")
        sec_rows.sort(key=lambda r: -r["size"])
        ev["sections_info"] = {
            "count": len(sec_rows),
            "largest": sec_rows[:12],
            "high_entropy": high_entropy,
        }

        # ---- segments: look for RWX ----
        rwx_segments = []
        for seg in elf.iter_segments():
            if seg["p_type"] == "PT_LOAD":
                flags = seg["p_flags"]
                if flags & 0x1 and flags & 0x2 and flags & 0x4:  # R+W+X
                    rwx_segments.append(f"offset {seg['p_offset']:#x}")
        ev["segments"] = {"rwx_count": len(rwx_segments), "rwx": rwx_segments}

        # ---- packer signatures ----
        packers = []
        if any(m in raw for m in _UPX_MAGIC):
            packers.append("UPX")
        ev["packers"] = packers

    # ---- strings: URLs and IPs ----
    urls: set[str] = set()
    ips: set[str] = set()
    for m in _PRINTABLE_RE.finditer(raw):
        s = m.group(0)
        for u in _URL_RE.findall(s):
            try:
                urls.add(u.decode("ascii"))
            except Exception:
                pass
        for ip in _IP_RE.findall(s):
            parts = ip.decode("ascii").split(".")
            if all(p.isdigit() and int(p) < 256 for p in parts):
                if not ip.startswith((b"0.", b"127.", b"255.")):
                    ips.add(ip.decode("ascii"))
    ev["network_indicators"] = {
        "urls": sorted(urls)[:100], "url_count": len(urls),
        "ips": sorted(ips)[:50], "ip_count": len(ips),
    }

    # ---- risk: 4 audited buckets x 25 = 100 (see docs/scoring.md) ----
    findings: list[dict[str, Any]] = []
    breakdown: dict[str, int] = {}
    susp = [r for r in ev["imports"]["items"] if r["severity"] > 0]

    STEALTH_IMPS = {"ptrace": 12, "dlopen": 6, "dlsym": 6}
    NETWORK_IMPS = {"socket", "connect", "gethostbyname", "getaddrinfo"}

    def _base(name: str) -> str:
        return name.split("@")[0]

    # 1. code: dangerous things the binary can do
    code_pts = sum(r["severity"] * 3.5 for r in susp
                   if _base(r["function"]) not in STEALTH_IMPS
                   and _base(r["function"]) not in NETWORK_IMPS)
    breakdown["code"] = min(25, int(code_pts))

    # 2. stealth: hiding from analysis
    stealth = sum(STEALTH_IMPS.get(_base(r["function"]), 0) for r in susp)
    if ev["packers"]:
        stealth += 10
        findings.append({"level": "medium",
                         "text": f"Packer signature detected: {', '.join(ev['packers'])}"})
    breakdown["stealth"] = min(25, stealth)

    # 3. memory: executable-memory tricks
    memory = 0
    if ev["segments"]["rwx_count"]:
        memory += 15
        findings.append({"level": "high",
                         "text": f"{ev['segments']['rwx_count']} RWX memory segment(s) — code can be written and executed at runtime"})
    if high_entropy:
        memory += 8
        findings.append({"level": "medium",
                         "text": f"High-entropy sections (possibly packed/encrypted): {', '.join(high_entropy[:3])}"})
    breakdown["memory"] = min(25, memory)

    # 4. network: talking to the outside world
    net_pts = sum(r["severity"] * 4 for r in susp if _base(r["function"]) in NETWORK_IMPS)
    ni = ev["network_indicators"]
    net_pts += min(8, ni["url_count"] + ni["ip_count"])
    breakdown["network"] = min(25, int(net_pts))

    for r in susp:
        if r["severity"] >= 2:
            findings.append({"level": "high" if r["severity"] >= 3 else "medium",
                             "text": f"Suspicious import: {r['function']} — {r['why']}"})

    score = sum(breakdown.values())
    grade = "low" if score < 25 else "medium" if score < 50 else "high" if score < 75 else "critical"
    ev["risk"] = {"score": score, "grade": grade, "findings": findings, "breakdown": breakdown}
    return ev
