"""Single-file HTML report: dark theme, cards, tables, collapsible sections."""

from __future__ import annotations

import html
from typing import Any

CSS = """
:root{--bg:#0d1117;--card:#161b22;--line:#30363d;--txt:#e6edf3;--dim:#8b949e;
--green:#3fb950;--yellow:#d29922;--orange:#db6d28;--red:#f85149;--blue:#58a6ff}
*{box-sizing:border-box}body{background:var(--bg);color:var(--txt);
font-family:-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;margin:0;padding:24px;line-height:1.5}
.wrap{max-width:1080px;margin:0 auto}
h1{font-size:26px;margin:0 0 4px}.sub{color:var(--dim);font-size:13px;margin-bottom:20px}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:12px;margin:18px 0}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:14px}
.card .k{font-size:11px;color:var(--dim);text-transform:uppercase;letter-spacing:.06em}
.card .v{font-size:22px;font-weight:700;margin-top:4px}
.verdict{font-size:20px;font-weight:800;padding:14px 18px;border-radius:10px;margin:16px 0;
border:1px solid var(--line);background:var(--card)}
.verdict.low{border-left:6px solid var(--green)}.verdict.medium{border-left:6px solid var(--yellow)}
.verdict.high{border-left:6px solid var(--orange)}.verdict.critical{border-left:6px solid var(--red)}
details{background:var(--card);border:1px solid var(--line);border-radius:10px;margin:10px 0}
summary{cursor:pointer;padding:12px 16px;font-weight:700;font-size:15px}
.sum-body{padding:0 16px 14px}
table{width:100%;border-collapse:collapse;font-size:13px}
th{text-align:left;color:var(--dim);font-weight:600;padding:8px;border-bottom:1px solid var(--line)}
td{padding:8px;border-bottom:1px solid var(--line);vertical-align:top}
code{background:#0d1117;padding:2px 6px;border-radius:6px;font-size:12.5px;color:var(--blue)}
ul{margin:8px 0;padding-left:20px;font-size:14px}
.pill{display:inline-block;padding:2px 10px;border-radius:20px;font-size:12px;font-weight:700}
.pill.r3{background:#3d1113;color:var(--red)}.pill.r2{background:#3a2305;color:var(--orange)}
.pill.r1{background:#38300a;color:var(--yellow)}.pill.r0{background:#1c2b1c;color:var(--green)}
.foot{color:var(--dim);font-size:12px;margin-top:26px;text-align:center}
"""

GRADE_EMOJI = {"low": "🟢", "medium": "🟡", "high": "🟠", "critical": "🔴"}


def _e(x: Any) -> str:
    return html.escape(str(x if x is not None else ""))


def _details(title: str, body: str, open_: bool = False) -> str:
    return f"<details{' open' if open_ else ''}><summary>{_e(title)}</summary><div class='sum-body'>{body}</div></details>"


def render(ev: dict[str, Any]) -> str:
    t = ev["target"]
    s = ev["sections"]
    risk = s.get("risk", {})
    ident = s.get("identity", {})
    perms = s.get("permissions", {})
    comp = s.get("components", {})
    libs = s.get("native_libraries", {})
    sign = s.get("signing", {})
    dex = s.get("dex", {})
    trackers = s.get("trackers", {})
    apis = s.get("suspicious_apis", {})
    net = s.get("network_indicators", {})
    grade = risk.get("grade", "unknown")

    findings = "".join(
        f"<li>{_e(f.get('text'))}</li>" for f in risk.get("findings", [])
    ) or "<li>No notable findings.</li>"

    perm_rows = "".join(
        f"<tr><td><code>{_e(p['permission'])}</code></td>"
        f"<td><span class='pill r{p['severity']}'>{'· LOW MED HIGH'.split()[p['severity']] if p['severity'] < 4 else 'CRIT'}</span></td>"
        f"<td>{_e(p['why'])}</td></tr>"
        for p in perms.get("items", []) if p["severity"] > 0
    ) or "<tr><td colspan=3>No risky permissions.</td></tr>"

    tracker_list = "".join(f"<li>🛰️ {_e(x)}</li>" for x in trackers.get("items", [])) or "<li>None detected.</li>"
    lib_list = "".join(f"<li><code>{_e(x)}</code></li>" for x in (libs.get("items") or [])[:40]) or "<li>None.</li>"
    api_rows = "".join(
        f"<tr><td><code>{_e(a['api'])}</code></td><td>{a['hits']}</td></tr>"
        for a in (apis.get("items") or [])[:25]
    ) or "<tr><td colspan=2>None.</td></tr>"
    url_list = "".join(f"<li><code>{_e(u)}</code></li>" for u in (net.get("urls") or [])[:20])
    ip_list = "".join(f"<li><code>{_e(i)}</code></li>" for i in (net.get("ips") or [])[:20])

    body = f"""
<div class="wrap">
<h1>📦 {_e(t['name'])}</h1>
<div class="sub">REAX report · {_e(ev.get('analyzed_at',''))} · SHA256 <code>{_e(t.get('sha256','')[:24])}…</code></div>
<div class="verdict {grade}">{GRADE_EMOJI.get(grade,'⚪')} {grade.upper()} — risk score {risk.get('score',0)}/100</div>
<div class="card"><div class="k">Key findings</div><ul>{findings}</ul></div>
<div class="grid">
<div class="card"><div class="k">Package</div><div class="v" style="font-size:14px">{_e(ident.get('package'))}</div></div>
<div class="card"><div class="k">Version</div><div class="v" style="font-size:14px">{_e(ident.get('version_name'))}</div></div>
<div class="card"><div class="k">Permissions</div><div class="v">{perms.get('count',0)}</div></div>
<div class="card"><div class="k">Trackers</div><div class="v">{trackers.get('count',0)}</div></div>
<div class="card"><div class="k">Classes</div><div class="v">{dex.get('classes',0)}</div></div>
<div class="card"><div class="k">Native libs</div><div class="v">{libs.get('count',0)}</div></div>
</div>
{_details(f"Permissions ({perms.get('count',0)})", f"<table><tr><th>Permission</th><th>Risk</th><th>Why</th></tr>{perm_rows}</table>", True)}
{_details(f"Trackers ({trackers.get('count',0)})", f"<ul>{tracker_list}</ul>")}
{_details(f"Suspicious API usage ({apis.get('count',0)})", f"<table><tr><th>API</th><th>Call sites</th></tr>{api_rows}</table>")}
{_details(f"Network indicators (URLs {net.get('url_count',0)} · IPs {net.get('ip_count',0)})", f"<ul>{url_list}{ip_list}</ul>")}
{_details(f"Native libraries ({libs.get('count',0)})", f"<ul>{lib_list}</ul>")}
{_details("Components", f"<ul><li>Activities: {comp.get('activities')}</li><li>Services: {comp.get('services')}</li><li>Receivers: {comp.get('receivers')}</li><li>Providers: {comp.get('providers')}</li></ul>")}
{_details("Signing", f"<ul><li>Signed: {sign.get('signed')} (v1={sign.get('v1')} v2={sign.get('v2')} v3={sign.get('v3')})</li><li>Debuggable: {ident.get('debuggable')}</li><li>SDK: min {ident.get('min_sdk')} / target {ident.get('target_sdk')}</li></ul>")}
<div class="foot">Generated by REAX {_e(ev.get('reax_version',''))} — for educational and authorized security research only.</div>
</div>"""
    return f"<!DOCTYPE html><html><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'><title>REAX — {_e(t['name'])}</title><style>{CSS}</style></head><body>{body}</body></html>"
