"""Target detection: figure out what kind of file we're looking at."""

from __future__ import annotations

import zipfile
from pathlib import Path

APK = "apk"
ELF = "elf"
MACHO = "macho"
PE = "pe"
DEX = "dex"
JAR = "jar"
UNKNOWN = "unknown"


def detect(path: str | Path) -> str:
    p = Path(path)
    data = p.read_bytes()[:8]
    if data[:2] == b"PK":
        try:
            with zipfile.ZipFile(p) as z:
                names = z.namelist()
        except zipfile.BadZipFile:
            return UNKNOWN
        if "AndroidManifest.xml" in names:
            return APK
        if any(n.endswith(".dex") for n in names):
            return JAR
        return UNKNOWN
    if data[:4] == b"dex\n":
        return DEX
    if data[:4] == b"\x7fELF":
        return ELF
    if data[:4] in (b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf", b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe",
                    b"\xca\xfe\xba\xbe"):
        return MACHO
    if data[:2] == b"MZ":
        return PE
    return UNKNOWN
