"""Analyzer registry: kind -> analyzer function."""

from __future__ import annotations

from typing import Any, Callable

from reax.core.target import APK, DEX, ELF, JAR, MACHO, PE

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

register(APK)(analyze_apk)
register(ELF)(analyze_elf)
