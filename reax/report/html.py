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


def _breakdown_html(risk: dict[str, Any]) -> str:
    bd = risk.get("breakdown")
    if not bd:
        return ""
    rows = "".join(
        f"<div style='margin:8px 0'><div style='display:flex;justify-content:space-between'>"
        f"<span style='color:var(--dim);font-size:12px;text-transform:uppercase'>{_e(k)}</span>"
        f"<span style='font-size:12px'>{v}/25</span></div>"
        f"<div style='background:#0d1117;border-radius:6px;height:8px;margin-top:4px'>"
        f"<div style='width:{min(v * 4, 100)}%;height:8px;border-radius:6px;background:var(--blue)'></div>"
        f"</div></div>"
        for k, v in bd.items()
    )
    return f"<div class='card'><div class='k'>Score breakdown — where the points came from</div>{rows}</div>"


def render(ev: dict[str, Any]) -> str:
    kind = ev["target"]["kind"]
    if kind == "elf":
        return render_elf(ev)
    if kind == "js":
        return render_js(ev)
    if kind == "web":
        return render_web(ev)
    if kind == "pe":
        return render_pe(ev)
    if kind == "macho":
        return render_macho(ev)
    return render_apk(ev)


def render_elf(ev: dict[str, Any]) -> str:
    t = ev["target"]
    s = ev["sections"]
    risk = s.get("risk", {})
    ident = s.get("identity", {})
    imports = s.get("imports", {})
    exports = s.get("exports", {})
    secs = s.get("sections_info", {})
    segs = s.get("segments", {})
    net = s.get("network_indicators", {})
    grade = risk.get("grade", "unknown")

    findings = "".join(
        f"<li>{_e(f.get('text'))}</li>" for f in risk.get("findings", [])
    ) or "<li>No notable findings.</li>"

    susp = [r for r in imports.get("items", []) if r["severity"] > 0]
    imp_rows = "".join(
        f"<tr><td><code>{_e(r['function'])}</code></td>"
        f"<td><span class='pill r{r['severity']}'>{'· LOW MED HIGH'.split()[r['severity']]}</span></td>"
        f"<td>{_e(r['why'])}</td></tr>"
        for r in susp
    ) or "<tr><td colspan=3>No suspicious imports.</td></tr>"

    sec_rows = "".join(
        f"<tr><td><code>{_e(sec['name'])}</code></td><td>{sec['size']:,}</td>"
        f"<td>{sec['entropy']}{' 🔥' if sec['entropy'] > 7.5 else ''}</td>"
        f"<td>{'✓' if sec['write'] else ''}</td><td>{'✓' if sec['exec'] else ''}</td></tr>"
        for sec in (secs.get("largest") or [])[:12]
    )
    url_list = "".join(f"<li><code>{_e(u)}</code></li>" for u in (net.get("urls") or [])[:20])
    ip_list = "".join(f"<li><code>{_e(i)}</code></li>" for i in (net.get("ips") or [])[:20])
    lib_list = "".join(f"<li><code>{_e(x)}</code></li>" for x in (imports.get("libraries") or [])[:10])

    body = f"""
<div class="wrap">
<h1>⚙️ {_e(t['name'])}</h1>
<div class="sub">REAX ELF report · {_e(ev.get('analyzed_at',''))} · SHA256 <code>{_e(t.get('sha256','')[:24])}…</code></div>
<div class="verdict {grade}">{GRADE_EMOJI.get(grade,'⚪')} {grade.upper()} — risk score {risk.get('score',0)}/100</div>
<div class="card"><div class="k">Key findings</div><ul>{findings}</ul></div>
{_breakdown_html(risk)}
<div class="grid">
<div class="card"><div class="k">Arch</div><div class="v" style="font-size:14px">{_e(ident.get('arch'))} {_e(ident.get('bits'))}-bit</div></div>
<div class="card"><div class="k">Type</div><div class="v" style="font-size:14px">{_e(ident.get('type'))}</div></div>
<div class="card"><div class="k">Imports</div><div class="v">{imports.get('count',0)}</div></div>
<div class="card"><div class="k">Suspicious</div><div class="v">{imports.get('suspicious_count',0)}</div></div>
<div class="card"><div class="k">Exports</div><div class="v">{exports.get('count',0)}</div></div>
<div class="card"><div class="k">RWX segs</div><div class="v">{segs.get('rwx_count',0)}</div></div>
</div>
{_details(f"Suspicious imports ({imports.get('suspicious_count',0)})", f"<table><tr><th>Function</th><th>Risk</th><th>Why</th></tr>{imp_rows}</table>", True)}
{_details(f"Sections ({secs.get('count',0)})", f"<table><tr><th>Section</th><th>Size</th><th>Entropy</th><th>W</th><th>X</th></tr>{sec_rows}</table>")}
{_details(f"Network indicators (URLs {net.get('url_count',0)} · IPs {net.get('ip_count',0)})", f"<ul>{url_list}{ip_list}</ul>")}
{_details("Linked libraries", f"<ul>{lib_list}</ul>")}
{_details("Binary", f"<ul><li>Stripped: {ident.get('stripped')}</li><li>Endian: {_e(ident.get('endian'))}</li><li>Packers: {_e(', '.join(s.get('packers') or ['none']))}</li></ul>")}
<div class="foot">Generated by REAX {_e(ev.get('reax_version',''))} — for educational and authorized security research only.</div>
</div>"""
    return f"<!DOCTYPE html><html><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'><title>REAX — {_e(t['name'])}</title><style>{CSS}</style></head><body>{body}</body></html>"


def render_js(ev: dict[str, Any]) -> str:
    t = ev["target"]
    s = ev["sections"]
    risk = s.get("risk", {})
    ident = s.get("identity", {})
    apis = s.get("dangerous_apis", {})
    net = s.get("network_indicators", {})
    supply = s.get("supply_chain", {})
    obf = s.get("obfuscation", {})
    grade = risk.get("grade", "unknown")

    findings = "".join(
        f"<li>{_e(f.get('text'))}</li>" for f in risk.get("findings", [])
    ) or "<li>No notable findings.</li>"

    api_rows = "".join(
        f"<tr><td>{_e(a['api'])}</td><td><code>{_e(a['file'])}:{a['line']}</code></td>"
        f"<td><code>{_e(a['code'])}</code></td></tr>"
        for a in (apis.get("items") or [])
    ) or "<tr><td colspan=3>No dangerous APIs.</td></tr>"

    net_rows = "".join(
        f"<tr><td>{_e(n['indicator'])}</td><td><code>{_e(n['file'])}:{n['line']}</code></td>"
        f"<td><code>{_e(n['code'])}</code></td></tr>"
        for n in (net.get("items") or [])
    ) or "<tr><td colspan=3>No exfiltration indicators.</td></tr>"

    url_list = "".join(f"<li><code>{_e(u)}</code></li>" for u in (net.get("urls") or [])[:20])
    scripts = supply.get("scripts", {})
    script_list = "".join(
        f"<li><code>{_e(k)}</code>: <code>{_e(str(v)[:80])}</code>"
        f"{' ⚠️ runs on install' if k in ('preinstall', 'install', 'postinstall') else ''}</li>"
        for k, v in scripts.items()
    ) or "<li>None.</li>"
    obf_list = "".join(f"<li>⚠️ {_e(f)}</li>" for f in (obf.get("flags") or [])) or "<li>None.</li>"

    body = f"""
<div class="wrap">
<h1>📜 {_e(t['name'])}</h1>
<div class="sub">REAX JavaScript report · {_e(ev.get('analyzed_at',''))} · SHA256 <code>{_e(t.get('sha256','')[:24])}…</code></div>
<div class="verdict {grade}">{GRADE_EMOJI.get(grade,'⚪')} {grade.upper()} — risk score {risk.get('score',0)}/100</div>
<div class="card"><div class="k">Key findings</div><ul>{findings}</ul></div>
{_breakdown_html(risk)}
<div class="grid">
<div class="card"><div class="k">Kind</div><div class="v" style="font-size:14px">{_e(ident.get('kind'))}</div></div>
<div class="card"><div class="k">Package</div><div class="v" style="font-size:14px">{_e(ident.get('name'))} {_e(ident.get('version'))}</div></div>
<div class="card"><div class="k">Files</div><div class="v">{ident.get('files_analyzed',0)}</div></div>
<div class="card"><div class="k">Lines</div><div class="v">{ident.get('total_lines',0):,}</div></div>
<div class="card"><div class="k">Dependencies</div><div class="v">{supply.get('dependency_count',0)}</div></div>
<div class="card"><div class="k">Dangerous APIs</div><div class="v">{apis.get('count',0)}</div></div>
</div>
{_details(f"Dangerous APIs ({apis.get('count',0)})", f"<table><tr><th>API</th><th>Location</th><th>Code</th></tr>{api_rows}</table>", True)}
{_details(f"Exfiltration indicators ({net.get('count',0)})", f"<table><tr><th>Indicator</th><th>Location</th><th>Code</th></tr>{net_rows}</table>")}
{_details(f"URLs found ({len(net.get('urls') or [])})", f"<ul>{url_list}</ul>")}
{_details("Install scripts", f"<ul>{script_list}</ul>")}
{_details(f"Obfuscation signals ({obf.get('count',0)})", f"<ul>{obf_list}</ul>")}
<div class="foot">Generated by REAX {_e(ev.get('reax_version',''))} — for educational and authorized security research only.</div>
</div>"""
    return f"<!DOCTYPE html><html><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'><title>REAX — {_e(t['name'])}</title><style>{CSS}</style></head><body>{body}</body></html>"


def render_web(ev: dict[str, Any]) -> str:
    t = ev["target"]
    s = ev["sections"]
    risk = s.get("risk", {})
    ident = s.get("identity", {})
    scripts = s.get("scripts", {})
    trackers = s.get("trackers", {})
    forms = s.get("forms", {})
    deception = s.get("deception", {})
    grade = risk.get("grade", "unknown")

    findings = "".join(
        f"<li>{_e(f.get('text'))}</li>" for f in risk.get("findings", [])
    ) or "<li>No notable findings.</li>"

    script_list = "".join(f"<li><code>{_e(u)}</code></li>" for u in (scripts.get("external") or [])[:20])
    tracker_list = "".join(f"<li>{_e(x)}</li>" for x in (trackers.get("items") or [])) or "<li>None detected.</li>"
    form_list = "".join(
        f"<li>🔑 Password form → <code>{_e(f['action'] or '(same page)')}</code></li>"
        for f in (forms.get("password_forms") or [])
    ) or "<li>No password forms.</li>"
    deception_list = "".join(f"<li>🚩 {_e(f)}</li>" for f in (deception.get("flags") or [])) or "<li>None.</li>"

    body = f"""
<div class="wrap">
<h1>🌐 {_e(ident.get('final_url') or t['name'])}</h1>
<div class="sub">REAX website report · {_e(ev.get('analyzed_at',''))}</div>
<div class="verdict {grade}">{GRADE_EMOJI.get(grade,'⚪')} {grade.upper()} — risk score {risk.get('score',0)}/100</div>
<div class="card"><div class="k">Key findings</div><ul>{findings}</ul></div>
{_breakdown_html(risk)}
<div class="grid">
<div class="card"><div class="k">Title</div><div class="v" style="font-size:14px">{_e(ident.get('title') or '(none)')}</div></div>
<div class="card"><div class="k">TLS</div><div class="v" style="font-size:14px">{'✅ https' if ident.get('tls') else '❌ http'}</div></div>
<div class="card"><div class="k">Ext scripts</div><div class="v">{scripts.get('external_count',0)}</div></div>
<div class="card"><div class="k">Inline scripts</div><div class="v">{scripts.get('inline_count',0)}</div></div>
<div class="card"><div class="k">Trackers</div><div class="v">{trackers.get('count',0)}</div></div>
<div class="card"><div class="k">Forms</div><div class="v">{forms.get('count',0)}</div></div>
</div>
{_details(f"External scripts ({scripts.get('external_count',0)})", f"<ul>{script_list}</ul>", True)}
{_details(f"Trackers ({trackers.get('count',0)})", f"<ul>{tracker_list}</ul>")}
{_details("Password forms", f"<ul>{form_list}</ul>")}
{_details("Phishing signals", f"<ul>{deception_list}</ul>")}
<div class="foot">Generated by REAX {_e(ev.get('reax_version',''))} — for educational and authorized security research only.</div>
</div>"""
    return f"<!DOCTYPE html><html><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'><title>REAX — {_e(ident.get('final_url') or t['name'])}</title><style>{CSS}</style></head><body>{body}</body></html>"


def render_pe(ev: dict[str, Any]) -> str:
    t = ev["target"]
    s = ev["sections"]
    risk = s.get("risk", {})
    ident = s.get("identity", {})
    imports = s.get("imports", {})
    secs = s.get("sections_info", {})
    dotnet = s.get("dotnet_info", {})
    net = s.get("network_indicators", {})
    grade = risk.get("grade", "unknown")

    findings = "".join(
        f"<li>{_e(f.get('text'))}</li>" for f in risk.get("findings", [])
    ) or "<li>No notable findings.</li>"

    imp_rows = "".join(
        f"<tr><td><code>{_e(r['function'])}</code></td><td><code>{_e(r['dll'])}</code></td>"
        f"<td><span class='pill r{r['severity']}'>{'· LOW MED HIGH'.split()[r['severity']]}</span></td>"
        f"<td>{_e(r['why'])}</td></tr>"
        for r in (imports.get("items") or [])[:25]
    ) or "<tr><td colspan=4>No suspicious imports.</td></tr>"

    sec_rows = "".join(
        f"<tr><td><code>{_e(sec['name'])}</code></td><td>{sec['size']:,}</td>"
        f"<td>{sec['entropy']}{' 🔥' if sec['entropy'] > 7.5 else ''}</td>"
        f"<td>{'⚠️' if sec['rwx'] else ''}</td></tr>"
        for sec in (secs.get("largest") or [])[:12]
    )
    url_list = "".join(f"<li><code>{_e(u)}</code></li>" for u in (net.get("urls") or [])[:20])
    ip_list = "".join(f"<li><code>{_e(i)}</code></li>" for i in (net.get("ips") or [])[:20])
    dotnet_line = (f"<li>🟣 .NET managed assembly (CLR {_e(dotnet.get('version') or 'unknown')})"
                   + (f" — obfuscator: {_e(dotnet['obfuscator'])}" if dotnet.get("obfuscator") else "") + "</li>") \
        if dotnet.get("is_dotnet") else ""

    body = f"""
<div class="wrap">
<h1>🪟 {_e(t['name'])}</h1>
<div class="sub">REAX PE report · {_e(ev.get('analyzed_at',''))} · SHA256 <code>{_e(t.get('sha256','')[:24])}…</code></div>
<div class="verdict {grade}">{GRADE_EMOJI.get(grade,'⚪')} {grade.upper()} — risk score {risk.get('score',0)}/100</div>
<div class="card"><div class="k">Key findings</div><ul>{findings}</ul></div>
{_breakdown_html(risk)}
<div class="grid">
<div class="card"><div class="k">Arch</div><div class="v" style="font-size:14px">{_e(ident.get('arch'))}</div></div>
<div class="card"><div class="k">Type</div><div class="v" style="font-size:14px">{_e(ident.get('kind'))}</div></div>
<div class="card"><div class="k">Imports</div><div class="v">{imports.get('count',0)}</div></div>
<div class="card"><div class="k">Suspicious</div><div class="v">{imports.get('suspicious_count',0)}</div></div>
<div class="card"><div class="k">Sections</div><div class="v">{ident.get('sections',0)}</div></div>
<div class="card"><div class="k">Packers</div><div class="v">{', '.join(secs.get('packers') or ['none'])}</div></div>
</div>
{_details(f"Suspicious imports ({imports.get('suspicious_count',0)})", f"<table><tr><th>Function</th><th>DLL</th><th>Risk</th><th>Why</th></tr>{imp_rows}</table>", True)}
{_details(f"Sections ({ident.get('sections',0)})", f"<table><tr><th>Section</th><th>Size</th><th>Entropy</th><th>RWX</th></tr>{sec_rows}</table>")}
{_details("Network indicators", f"<ul>{url_list}{ip_list}</ul>")}
{_details("Binary notes", f"<ul>{dotnet_line}<li>TLS callbacks: {secs.get('tls_callbacks',0)}</li></ul>")}
<div class="foot">Generated by REAX {_e(ev.get('reax_version',''))} — for educational and authorized security research only.</div>
</div>"""
    return f"<!DOCTYPE html><html><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'><title>REAX — {_e(t['name'])}</title><style>{CSS}</style></head><body>{body}</body></html>"


def render_macho(ev: dict[str, Any]) -> str:
    t = ev["target"]
    s = ev["sections"]
    risk = s.get("risk", {})
    ident = s.get("identity", {})
    syms = s.get("symbols", {})
    segs = s.get("segments_info", {})
    net = s.get("network_indicators", {})
    grade = risk.get("grade", "unknown")

    findings = "".join(
        f"<li>{_e(f.get('text'))}</li>" for f in risk.get("findings", [])
    ) or "<li>No notable findings.</li>"

    sym_rows = "".join(
        f"<tr><td><code>{_e(r['symbol'])}</code></td>"
        f"<td><span class='pill r{r['severity']}'>{'· LOW MED HIGH'.split()[r['severity']]}</span></td>"
        f"<td>{_e(r['why'])}</td></tr>"
        for r in (syms.get("items") or [])[:25]
    ) or "<tr><td colspan=3>No suspicious symbols.</td></tr>"

    sec_rows = "".join(
        f"<tr><td><code>{_e(sec['name'])}</code></td><td><code>{_e(sec['segment'])}</code></td>"
        f"<td>{sec['size']:,}</td><td>{sec['entropy']}{' 🔥' if sec['entropy'] > 7.5 else ''}</td></tr>"
        for sec in (segs.get("largest_sections") or [])[:12]
    )
    dylib_list = "".join(
        f"<li><code>{_e(d)}</code>{' ⚠️ embedded' if d.startswith(('@rpath','@executable_path','@loader_path')) else ''}</li>"
        for d in (segs.get("dylibs") or [])[:20]
    )
    url_list = "".join(f"<li><code>{_e(u)}</code></li>" for u in (net.get("urls") or [])[:20])
    ip_list = "".join(f"<li><code>{_e(i)}</code></li>" for i in (net.get("ips") or [])[:20])

    body = f"""
<div class="wrap">
<h1>🍎 {_e(t['name'])}</h1>
<div class="sub">REAX Mach-O report · {_e(ev.get('analyzed_at',''))} · SHA256 <code>{_e(t.get('sha256','')[:24])}…</code></div>
<div class="verdict {grade}">{GRADE_EMOJI.get(grade,'⚪')} {grade.upper()} — risk score {risk.get('score',0)}/100</div>
<div class="card"><div class="k">Key findings</div><ul>{findings}</ul></div>
{_breakdown_html(risk)}
<div class="grid">
<div class="card"><div class="k">Arch</div><div class="v" style="font-size:14px">{_e(ident.get('arch'))}</div></div>
<div class="card"><div class="k">Type</div><div class="v" style="font-size:14px">{_e(ident.get('kind'))}</div></div>
<div class="card"><div class="k">Symbols</div><div class="v">{syms.get('count',0)}</div></div>
<div class="card"><div class="k">Suspicious</div><div class="v">{syms.get('suspicious_count',0)}</div></div>
<div class="card"><div class="k">Dylibs</div><div class="v">{ident.get('dylibs',0)}</div></div>
<div class="card"><div class="k">Encrypted</div><div class="v">{'yes' if ident.get('encrypted') else 'no'}</div></div>
</div>
{_details(f"Suspicious symbols ({syms.get('suspicious_count',0)})", f"<table><tr><th>Symbol</th><th>Risk</th><th>Why</th></tr>{sym_rows}</table>", True)}
{_details("Sections", f"<table><tr><th>Section</th><th>Segment</th><th>Size</th><th>Entropy</th></tr>{sec_rows}</table>")}
{_details(f"Linked dylibs ({ident.get('dylibs',0)})", f"<ul>{dylib_list}</ul>")}
{_details("Network indicators", f"<ul>{url_list}{ip_list}</ul>")}
<div class="foot">Generated by REAX {_e(ev.get('reax_version',''))} — for educational and authorized security research only.</div>
</div>"""
    return f"<!DOCTYPE html><html><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'><title>REAX — {_e(t['name'])}</title><style>{CSS}</style></head><body>{body}</body></html>"


def render_apk(ev: dict[str, Any]) -> str:
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
    decomp = s.get("decompiled", {})
    decomp_items = "".join(
        f"<details style='margin:6px 0'><summary><code>{_e(d['method'])}</code> "
        f"<span style='color:var(--dim);font-size:12px'>— triggered by {_e(d['api'])}</span></summary>"
        f"<pre style='background:#0d1117;padding:12px;border-radius:8px;overflow-x:auto;font-size:12.5px'><code>{_e(d['code'])}</code></pre></details>"
        for d in (decomp.get("items") or [])
    )

    body = f"""
<div class="wrap">
<h1>📦 {_e(t['name'])}</h1>
<div class="sub">REAX report · {_e(ev.get('analyzed_at',''))} · SHA256 <code>{_e(t.get('sha256','')[:24])}…</code></div>
<div class="verdict {grade}">{GRADE_EMOJI.get(grade,'⚪')} {grade.upper()} — risk score {risk.get('score',0)}/100</div>
<div class="card"><div class="k">Key findings</div><ul>{findings}</ul></div>
{_breakdown_html(risk)}
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
{_details(f"Decompiled evidence ({decomp.get('count',0)})", decomp_items or "None — no severity≥2 API hits to decompile.")}
{_details(f"Network indicators (URLs {net.get('url_count',0)} · IPs {net.get('ip_count',0)})", f"<ul>{url_list}{ip_list}</ul>")}
{_details(f"Native libraries ({libs.get('count',0)})", f"<ul>{lib_list}</ul>")}
{_details("Components", f"<ul><li>Activities: {comp.get('activities')}</li><li>Services: {comp.get('services')}</li><li>Receivers: {comp.get('receivers')}</li><li>Providers: {comp.get('providers')}</li></ul>")}
{_details("Signing", f"<ul><li>Signed: {sign.get('signed')} (v1={sign.get('v1')} v2={sign.get('v2')} v3={sign.get('v3')})</li><li>Debuggable: {ident.get('debuggable')}</li><li>SDK: min {ident.get('min_sdk')} / target {ident.get('target_sdk')}</li></ul>")}
<div class="foot">Generated by REAX {_e(ev.get('reax_version',''))} — for educational and authorized security research only.</div>
</div>"""
    return f"<!DOCTYPE html><html><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'><title>REAX — {_e(t['name'])}</title><style>{CSS}</style></head><body>{body}</body></html>"
