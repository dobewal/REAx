"""JavaScript / npm package analyzer: verdict-first static analysis.

Covers a single .js file, an npm package directory, or an npm tarball
(.tgz / .tar.gz). Pure stdlib — no Node.js needed. Strictly read-only:
we parse text, we never execute it.
"""

from __future__ import annotations

import json
import math
import re
import tarfile
import tempfile
from pathlib import Path
from typing import Any

# (regex, severity, plain-English label) — code bucket
DANGEROUS_APIS: list[tuple[str, int, str]] = [
    (r"\beval\s*\(", 3, "eval() — executes arbitrary code strings"),
    (r"\bnew\s+Function\s*\(", 3, "new Function() — compiles strings into code"),
    (r"""require\s*\(\s*['"]child_process['"]\s*\)""", 3, "child_process — spawns OS commands"),
    (r"""\b(exec|execSync|spawn|spawnSync|execFile)\s*\(""", 2, "process spawning call"),
    (r"""\bprocess\.env\b""", 2, "reads environment variables (secret theft target)"),
    (r"""\bfs\.(unlink|rm|rmdir|rmSync|unlinkSync)\w*\s*\(""", 2, "destructive filesystem call"),
    (r"""\bvm\.(runIn\w+|compileFunction)\s*\(""", 2, "vm module — sandboxed code execution"),
    (r"""\bBuffer\.from\s*\([^,]+,\s*['"]base64['"]\s*\)""", 1, "base64 decoding (payload staging)"),
    (r"""\batob\s*\(""", 1, "atob() base64 decoding"),
    (r"""\bfromCharCode\s*\(""", 1, "String.fromCharCode (string building, often obfuscated)"),
]

# (regex, points, plain-English label) — network bucket
EXFIL_PATTERNS: list[tuple[str, int, str]] = [
    (r"discord\.com/api/webhooks", 8, "Discord webhook — classic token/credential exfil"),
    (r"api\.telegram\.org/bot", 8, "Telegram bot API — exfil channel"),
    (r"https?://\d{1,3}(?:\.\d{1,3}){3}(?::\d+)?", 3, "hardcoded IP URL — evades domain reputation"),
    (r"[a-z0-9-]+\.(ngrok\.io|localtunnel\.me|trycloudflare\.com)", 5, "tunneling service — hides real server"),
    (r"pastebin\.com|paste\.ee|hastebin\.com|rentry\.co", 4, "paste site — payload staging"),
    (r"\bnew\s+WebSocket\s*\(", 2, "raw WebSocket — covert channel"),
    (r"http://[^\s'\"`]+", 1, "cleartext http:// URL"),
]

URL_RE = re.compile(r"https?://[^\s'\"`<>]+")
OBFUSCATOR_ID_RE = re.compile(r"_0x[0-9a-fA-F]{4,}")
HEX_ESCAPE_RE = re.compile(r"\\x[0-9a-fA-F]{2}")
STRING_RE = re.compile(r"""(?:"(?:[^"\\]|\\.){100,}"|'(?:[^'\\]|\\.){100,}')""")

MAX_FILES = 300
MAX_SNIPPETS = 12


def _shannon(s: str) -> float:
    if not s:
        return 0.0
    freq: dict[str, int] = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


def _collect_js_files(root: Path) -> list[Path]:
    files: list[Path] = []
    for p in root.rglob("*.js"):
        if "node_modules" in p.parts:
            continue
        if p.is_file():
            files.append(p)
            if len(files) >= MAX_FILES:
                break
    return sorted(files)


def _read_text(p: Path) -> str:
    try:
        return p.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return ""


def analyze_js(path: str) -> dict[str, Any]:
    src = Path(path)
    tmpdir = None
    try:
        if src.is_dir():
            root = src
            label = "npm package" if (src / "package.json").is_file() else "script directory"
        elif src.name.endswith((".tgz", ".tar.gz")):
            tmpdir = tempfile.TemporaryDirectory(prefix="reax-js-")
            root = Path(tmpdir.name)
            with tarfile.open(src, "r:*") as tf:
                tf.extractall(root, filter="data")
            label = "npm tarball"
            # tarballs wrap in package/ — descend if that's the only dir
            kids = [k for k in root.iterdir() if k.is_dir()]
            if len(kids) == 1 and (kids[0] / "package.json").is_file():
                root = kids[0]
        else:
            root = src.parent
            label = "script"

        js_files = _collect_js_files(root) if root.is_dir() and root != src.parent else []
        if not src.is_dir() and src.suffix == ".js":
            js_files = [src]

        # ---- package.json supply-chain signals ----
        pkg: dict[str, Any] = {}
        pkg_path = root / "package.json" if root.is_dir() else None
        if pkg_path and pkg_path.is_file():
            try:
                pkg = json.loads(pkg_path.read_text(encoding="utf-8", errors="replace"))
            except Exception:
                pkg = {}

        # ---- per-file scan ----
        api_items: list[dict[str, Any]] = []
        net_items: list[dict[str, Any]] = []
        urls: set[str] = set()
        total_lines = 0
        obf_flags: list[str] = []

        for jf in js_files:
            text = _read_text(jf)
            if not text:
                continue
            lines = text.split("\n")
            total_lines += len(lines)
            rel = str(jf.relative_to(root)) if root.is_dir() else jf.name

            def snippet(no: int) -> str:
                return lines[no].strip()[:160] if 0 <= no < len(lines) else ""

            for i, line in enumerate(lines):
                for pat, sev, what in DANGEROUS_APIS:
                    if re.search(pat, line):
                        api_items.append({
                            "api": what, "severity": sev,
                            "file": rel, "line": i + 1, "code": snippet(i),
                        })
                        break  # one hit per line keeps noise down
                for pat, pts, what in EXFIL_PATTERNS:
                    if re.search(pat, line):
                        net_items.append({
                            "indicator": what, "points": pts,
                            "file": rel, "line": i + 1, "code": snippet(i),
                        })
            for m in URL_RE.finditer(text):
                urls.add(m.group(0)[:120])

            # obfuscation heuristics per file
            avg_len = sum(len(l) for l in lines) / max(1, len(lines))
            if avg_len > 800 and len(lines) < 50:
                obf_flags.append(f"{rel}: packed/minified — {len(lines)} lines, avg {int(avg_len)} chars/line")
            if len(HEX_ESCAPE_RE.findall(text)) > 30:
                obf_flags.append(f"{rel}: heavy hex-escape encoding ({len(HEX_ESCAPE_RE.findall(text))} sequences)")
            if len(OBFUSCATOR_ID_RE.findall(text)) > 20:
                obf_flags.append(f"{rel}: obfuscator-style identifiers (_0x…) — likely javascript-obfuscator output")
            for m in STRING_RE.finditer(text):
                if _shannon(m.group(0)) > 4.7:
                    obf_flags.append(f"{rel}: high-entropy embedded string (encrypted/packed payload?)")
                    break

        # ---- scoring: 4 buckets x 25 ----
        findings: list[dict[str, str]] = []
        breakdown: dict[str, int] = {}

        code_pts = sum(min(3, a["severity"]) for a in api_items) * 2.5
        breakdown["code"] = min(25, int(code_pts))
        if api_items:
            top = sorted(api_items, key=lambda a: -a["severity"])[:3]
            findings.append({
                "level": "high" if any(a["severity"] >= 3 for a in api_items) else "medium",
                "text": "Dangerous JS APIs in use: " + "; ".join(
                    f"{a['api'].split(' — ')[0]} ({a['file']}:{a['line']})" for a in top)})

        net_pts = sum(n["points"] for n in net_items)
        breakdown["network"] = min(25, int(net_pts))
        if net_items:
            top = sorted(net_items, key=lambda n: -n["points"])[:2]
            findings.append({
                "level": "high" if any(n["points"] >= 8 for n in net_items) else "medium",
                "text": "Exfiltration indicators: " + "; ".join(
                    f"{n['indicator'].split(' — ')[0]} ({n['file']}:{n['line']})" for n in top)})

        supply_pts = 0
        scripts = pkg.get("scripts", {}) if isinstance(pkg, dict) else {}
        if isinstance(scripts, dict):
            for hook in ("preinstall", "install", "postinstall"):
                if hook in scripts:
                    supply_pts += 10
                    findings.append({
                        "level": "high",
                        "text": f"Install hook `{hook}` runs on npm install — classic supply-chain attack vector: {scripts[hook][:80]}"})
                    break
        deps = pkg.get("dependencies", {}) if isinstance(pkg, dict) else {}
        ndeps = len(deps) if isinstance(deps, dict) else 0
        if ndeps > 100:
            supply_pts += 5
        elif ndeps > 30:
            supply_pts += 2
        if isinstance(pkg, dict) and pkg:
            if not pkg.get("author"):
                supply_pts += 2
            if not pkg.get("repository"):
                supply_pts += 2
            if pkg.get("version") in ("0.0.0", "1.0.0") and not pkg.get("description"):
                supply_pts += 2
                findings.append({
                    "level": "low",
                    "text": "Bare-bones package metadata (no description, placeholder version)"})
        breakdown["supply"] = min(25, int(supply_pts))

        obf_pts = min(25, len(obf_flags) * 6)
        breakdown["obfuscation"] = min(25, int(obf_pts))
        if obf_flags:
            findings.append({
                "level": "medium",
                "text": f"Obfuscation signals: {obf_flags[0]}"})

        score = sum(breakdown.values())
        grade = "low" if score < 25 else "medium" if score < 50 else "high" if score < 75 else "critical"

        ev: dict[str, Any] = {
            "identity": {
                "kind": label,
                "name": pkg.get("name", src.name) if isinstance(pkg, dict) else src.name,
                "version": pkg.get("version", "") if isinstance(pkg, dict) else "",
                "files_analyzed": len(js_files),
                "total_lines": total_lines,
            },
            "dangerous_apis": {
                "count": len(api_items),
                "items": sorted(api_items, key=lambda a: (-a["severity"], a["file"]))[:MAX_SNIPPETS],
            },
            "network_indicators": {
                "count": len(net_items),
                "urls": sorted(urls)[:30],
                "items": sorted(net_items, key=lambda n: (-n["points"], n["file"]))[:MAX_SNIPPETS],
            },
            "supply_chain": {
                "scripts": scripts if isinstance(scripts, dict) else {},
                "dependency_count": ndeps,
                "points": min(25, int(supply_pts)),
            },
            "obfuscation": {"count": len(obf_flags), "flags": obf_flags[:10]},
            "risk": {"score": score, "grade": grade, "findings": findings[:8], "breakdown": breakdown},
        }
        return ev
    finally:
        if tmpdir is not None:
            tmpdir.cleanup()
