"""Analyzer registry: kind -> analyzer function."""

from __future__ import annotations

from typing import Any, Callable

from reax.core.target import APK, DEX, ELF, JAR, JS, MACHO, PE, WEB

_REGISTRY: dict[str, Callable[[str], dict[str, Any]]] = {}


def register(kind: str):
    def deco(fn: Callable[[str], dict[str, Any]]):
        _REGISTRY[kind] = fn
        return fn
    return deco


def get(kind: str):
    return _REGISTRY.get(kind)


def supported() -> list[str]:
    return sorted(_REGISTRY)


# built-in analyzers
from reax.analyzers.apk import analyze_apk  # noqa: E402
from reax.analyzers.elf import analyze_elf  # noqa: E402
from reax.analyzers.js import analyze_js  # noqa: E402
from reax.analyzers.macho import analyze_macho  # noqa: E402
from reax.analyzers.pe import analyze_pe  # noqa: E402
from reax.analyzers.web import analyze_web  # noqa: E402

register(APK)(analyze_apk)
register(ELF)(analyze_elf)
register(JS)(analyze_js)
register(MACHO)(analyze_macho)
register(PE)(analyze_pe)
register(WEB)(analyze_web)
