"""Unified evidence model: every analysis produces one JSON-serializable dict."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def sha256_of(path: str | Path, chunk: int = 1 << 20) -> str:
    p = Path(path)
    h = hashlib.sha256()
    if p.is_dir():
        # manifest hash: stable fingerprint of the directory tree
        for f in sorted(p.rglob("*")):
            if f.is_file():
                h.update(str(f.relative_to(p)).encode())
                h.update(str(f.stat().st_size).encode())
        return h.hexdigest()
    with open(p, "rb") as f:
        for b in iter(lambda: f.read(chunk), b""):
            h.update(b)
    return h.hexdigest()


def new_evidence(target_kind: str, target_path: str) -> dict[str, Any]:
    p = Path(target_path)
    is_url = target_path.startswith(("http://", "https://"))
    if is_url:
        name, size_bytes = target_path, 0
        sha = hashlib.sha256(target_path.encode()).hexdigest()
    else:
        name, size_bytes, sha = p.name, p.stat().st_size, sha256_of(p)
    return {
        "reax_version": __import__("reax").__version__,
        "target": {
            "kind": target_kind,
            "path": str(target_path),
            "name": name,
            "size_bytes": size_bytes,
            "sha256": sha,
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
