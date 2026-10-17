"""Unified evidence model: every analysis produces one JSON-serializable dict."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def sha256_of(path: str | Path, chunk: int = 1 << 20) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for b in iter(lambda: f.read(chunk), b""):
            h.update(b)
    return h.hexdigest()


def new_evidence(target_kind: str, target_path: str) -> dict[str, Any]:
    p = Path(target_path)
    return {
        "reax_version": __import__("reax").__version__,
        "target": {
            "kind": target_kind,
            "path": str(p),
            "name": p.name,
            "size_bytes": p.stat().st_size,
            "sha256": sha256_of(p),
        },
        "analyzed_at": datetime.now(timezone.utc).isoformat(),
        "sections": {},
        "risk": {"score": 0, "grade": "unknown", "findings": []},
    }


def save_evidence(evidence: dict[str, Any], out_path: str | Path) -> Path:
    out = Path(out_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(evidence, indent=2, ensure_ascii=False), encoding="utf-8")
    return out


def load_evidence(path: str | Path) -> dict[str, Any]:
    return json.loads(Path(path).read_text(encoding="utf-8"))
