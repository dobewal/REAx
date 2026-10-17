"""Diff two APK evidences: what changed between versions."""

from __future__ import annotations

from typing import Any


def _set(items, key="permission"):
    return {i[key] for i in items}


def diff_apk(old: dict[str, Any], new: dict[str, Any]) -> dict[str, Any]:
    so, sn = old["sections"], new["sections"]
    io, ino = old["target"], new["target"]

    op = {p["permission"]: p for p in so["permissions"]["items"]}
    np = {p["permission"]: p for p in sn["permissions"]["items"]}
    ot = set(so["trackers"]["items"])
    nt = set(sn["trackers"]["items"])
    ol = set(so["native_libraries"]["items"])
    nl = set(sn["native_libraries"]["items"])
    oa = {a["api"] for a in so["suspicious_apis"]["items"]}
    na = {a["api"] for a in sn["suspicious_apis"]["items"]}

    return {
        "old": {"name": io["name"], "version": so["identity"].get("version_name"),
                "sha256": io["sha256"][:16], "risk": so["risk"]},
        "new": {"name": ino["name"], "version": sn["identity"].get("version_name"),
                "sha256": ino["sha256"][:16], "risk": sn["risk"]},
        "version_changed": so["identity"].get("version_name") != sn["identity"].get("version_name"),
        "size_delta_bytes": ino["size_bytes"] - io["size_bytes"],
        "risk_delta": sn["risk"]["score"] - so["risk"]["score"],
        "permissions_added": sorted(set(np) - set(op)),
        "permissions_removed": sorted(set(op) - set(np)),
        "permissions_new_risky": [p for p in sorted(set(np) - set(op)) if np[p]["severity"] >= 2],
        "trackers_added": sorted(nt - ot),
        "trackers_removed": sorted(ot - nt),
        "native_libs_added": sorted(nl - ol),
        "native_libs_removed": sorted(ol - nl),
        "apis_added": sorted(na - oa),
        "apis_removed": sorted(oa - na),
        "components": {
            k: {"old": so["components"].get(k), "new": sn["components"].get(k)}
            for k in ("activities", "services", "receivers", "providers")
        },
    }


def render_markdown(d: dict[str, Any]) -> str:
    L: list[str] = []
    A = L.append
    A(f"# REAX diff — `{d['old']['name']}` → `{d['new']['name']}`")
    A("")
    rd = d["risk_delta"]
    arrow = "🔺" if rd > 0 else "🔻" if rd < 0 else "➖"
    A(f"Risk: **{d['old']['risk']['score']} → {d['new']['risk']['score']}** {arrow} ({rd:+d}) · "
      f"Size Δ: **{d['size_delta_bytes']:+,} bytes**")
    A("")
    changed = any(d[k] for k in ("permissions_added", "permissions_removed",
                                 "trackers_added", "trackers_removed",
                                 "native_libs_added", "native_libs_removed",
                                 "apis_added", "apis_removed"))
    if not changed and d["size_delta_bytes"] == 0 and not d["version_changed"]:
        A("> No differences — the two files are effectively identical.")
        A("")
        return "\n".join(L)
    if d["permissions_new_risky"]:
        A("## ⚠️ New risky permissions")
        for p in d["permissions_new_risky"]:
            A(f"- `{p}`")
        A("")
    for title, key in [("Permissions added", "permissions_added"),
                       ("Permissions removed", "permissions_removed"),
                       ("Trackers added", "trackers_added"),
                       ("Trackers removed", "trackers_removed"),
                       ("Native libs added", "native_libs_added"),
                       ("Native libs removed", "native_libs_removed"),
                       ("New suspicious APIs", "apis_added"),
                       ("Removed suspicious APIs", "apis_removed")]:
        items = d[key]
        A(f"## {title} ({len(items)})")
        A("" if items else "None.")
        for i in items:
            A(f"- `{i}`")
        A("")
    return "\n".join(L)
