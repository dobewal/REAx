"""Website analyzer: verdict-first static analysis of a web page.

Give it a URL; it fetches the page (stdlib urllib, no browser needed) and
scores what the page loads and asks for. Read-only: single GET, no forms
submitted, no JavaScript executed.
"""

from __future__ import annotations

import re
import ssl
import urllib.parse
import urllib.request
from html.parser import HTMLParser
from typing import Any

TIMEOUT = 15
MAX_BYTES = 5 * 1024 * 1024

# domain fragment -> tracker name
TRACKERS: dict[str, str] = {
    "google-analytics.com": "Google Analytics",
    "googletagmanager.com": "Google Tag Manager",
    "connect.facebook.net": "Facebook Pixel",
    "facebook.net": "Facebook Pixel",
    "doubleclick.net": "DoubleClick (Google Ads)",
    "googlesyndication.com": "AdSense",
    "hotjar.com": "Hotjar (session recording)",
    "fullstory.com": "FullStory (session recording)",
    "mixpanel.com": "Mixpanel",
    "segment.io": "Segment",
    "segment.com": "Segment",
    "newrelic.com": "New Relic",
    "nr-data.net": "New Relic",
    "clarity.ms": "Microsoft Clarity (session recording)",
    "criteo.com": "Criteo (ads)",
    "adnxs.com": "AppNexus (ads)",
    "rubiconproject.com": "Rubicon (ads)",
    "pubmatic.com": "PubMatic (ads)",
    "openx.net": "OpenX (ads)",
    "taboola.com": "Taboola (ads)",
    "outbrain.com": "Outbrain (ads)",
    "tawk.to": "Tawk.to (live chat)",
    "crisp.chat": "Crisp (live chat)",
    "intercom.io": "Intercom",
    "stripe.com": "Stripe",
    "paypal.com": "PayPal",
}

BRAND_KEYWORDS = (
    "paypal", "apple", "microsoft", "google", "amazon", "facebook", "instagram",
    "netflix", "bank", "wallet", "metamask", "coinbase", "binance", "dhl",
    "fedex", "irs", "gov",
)

SUSPICIOUS_INLINE_JS = [
    (r"\beval\s*\(", 4, "eval() in inline script"),
    (r"\bdocument\.write\s*\(", 4, "document.write() in inline script"),
    (r"\bunescape\s*\(", 3, "unescape() in inline script"),
    (r"fromCharCode", 2, "fromCharCode string-building in inline script"),
]


class _PageParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.scripts_ext: list[str] = []
        self.scripts_inline: list[str] = []
        self._in_script = False
        self._buf: list[str] = []
        self.iframes: list[str] = []
        self.links: list[str] = []
        self.forms: list[dict[str, Any]] = []
        self._form: dict[str, Any] | None = None
        self.event_handlers = 0
        self.title = ""
        self._in_title = False
        self.meta: dict[str, str] = {}

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        a = dict(attrs)
        if tag == "script":
            if a.get("src"):
                self.scripts_ext.append(a["src"])
            else:
                self._in_script = True
                self._buf = []
        elif tag == "iframe" and a.get("src"):
            self.iframes.append(a["src"])
        elif tag == "link" and a.get("href"):
            self.links.append(a["href"])
        elif tag == "form":
            self._form = {"action": a.get("action", ""), "password": False, "inputs": 0}
        elif tag == "input" and self._form is not None:
            self._form["inputs"] += 1
            if (a.get("type") or "").lower() == "password":
                self._form["password"] = True
        elif tag == "title":
            self._in_title = True
        elif tag == "meta":
            name = (a.get("name") or a.get("property") or "").lower()
            if name and a.get("content"):
                self.meta[name] = a["content"][:200]
        for k in a:
            if k.startswith("on") and len(k) > 2:
                self.event_handlers += 1

    def handle_endtag(self, tag: str) -> None:
        if tag == "script" and self._in_script:
            self.scripts_inline.append("".join(self._buf))
            self._in_script = False
        elif tag == "form" and self._form is not None:
            self.forms.append(self._form)
            self._form = None
        elif tag == "title":
            self._in_title = False

    def handle_data(self, data: str) -> None:
        if self._in_script:
            self._buf.append(data)
        if self._in_title:
            self.title += data


def _fetch(url: str) -> tuple[str, str, bytes]:
    req = urllib.request.Request(
        url,
        headers={"User-Agent": "Mozilla/5.0 (REAX website analyzer; educational research)"},
    )
    ctx = ssl.create_default_context()
    with urllib.request.urlopen(req, timeout=TIMEOUT, context=ctx) as r:
        final_url = r.geturl()
        raw = r.read(MAX_BYTES + 1)
    if len(raw) > MAX_BYTES:
        raw = raw[:MAX_BYTES]
    ctype = ""
    try:
        ctype = r.headers.get_content_type()  # type: ignore[union-attr]
    except Exception:
        pass
    return final_url, ctype, raw


def analyze_web(url: str) -> dict[str, Any]:
    final_url, ctype, raw = _fetch(url)
    html = raw.decode("utf-8", errors="replace")
    parsed = urllib.parse.urlparse(final_url)
    host = (parsed.hostname or "").lower()
    is_https = parsed.scheme == "https"

    p = _PageParser()
    try:
        p.feed(html)
    except Exception:
        pass

    def abs_url(u: str) -> str:
        return urllib.parse.urljoin(final_url, u)

    ext_scripts = [abs_url(s) for s in p.scripts_ext]

    findings: list[dict[str, str]] = []
    breakdown: dict[str, int] = {}

    # ---- scripts bucket ----
    script_pts = 0
    sus_inline: list[str] = []
    for js in p.scripts_inline:
        for pat, pts, what in SUSPICIOUS_INLINE_JS:
            if re.search(pat, js):
                script_pts += pts
                sus_inline.append(what)
                break
    if len(ext_scripts) > 10:
        script_pts += 5
    elif len(ext_scripts) > 5:
        script_pts += 2
    insecure_scripts = [s for s in ext_scripts if s.startswith("http://")]
    script_pts += min(8, len(insecure_scripts) * 4)
    if p.event_handlers > 5:
        script_pts += 4
    breakdown["scripts"] = min(25, script_pts)
    if sus_inline:
        findings.append({"level": "high",
                         "text": f"Suspicious inline JavaScript: {', '.join(sorted(set(sus_inline)))}"})
    if insecure_scripts:
        findings.append({"level": "medium",
                         "text": f"{len(insecure_scripts)} external script(s) loaded over cleartext http://"})

    # ---- privacy bucket (trackers) ----
    tracker_hits: list[str] = []
    resource_hosts = {urllib.parse.urlparse(abs_url(u)).hostname or "" for u in
                      p.scripts_ext + p.iframes + p.links}
    for frag, name in TRACKERS.items():
        if any(frag in (h or "") for h in resource_hosts):
            tracker_hits.append(name)
    tracker_hits = sorted(set(tracker_hits))
    breakdown["privacy"] = min(25, len(tracker_hits) * 3)
    if tracker_hits:
        findings.append({"level": "low",
                         "text": f"{len(tracker_hits)} tracker(s): {', '.join(sorted(set(tracker_hits))[:5])}"})

    # ---- deception bucket (phishing signals) ----
    deception_pts = 0
    deception_flags: list[str] = []
    if re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", host):
        deception_pts += 10
        deception_flags.append("site hosted on a bare IP address, not a domain")
    if "xn--" in host:
        deception_pts += 10
        deception_flags.append("punycode (xn--) in domain — classic lookalike trick")
    brand_hit = next((b for b in BRAND_KEYWORDS if b in host), None)
    if brand_hit and not host.endswith(f"{brand_hit}.com"):
        # crude official-domain check: brand keyword present but not the brand's own domain
        official = {f"{brand_hit}.com", f"www.{brand_hit}.com"}
        if host not in official and not host.endswith(f".{brand_hit}.com"):
            deception_pts += 8
            deception_flags.append(f"brand keyword '{brand_hit}' in an unofficial domain")
    pw_forms = [f for f in p.forms if f["password"]]
    if pw_forms:
        deception_pts += 5
        deception_flags.append(f"{len(pw_forms)} password form(s) — check where credentials are sent")
    if host.count(".") > 4:
        deception_pts += 3
        deception_flags.append("excessive subdomains — often used to fake legitimacy")
    breakdown["deception"] = min(25, deception_pts)
    for flag in deception_flags:
        findings.append({"level": "high" if deception_pts >= 10 else "medium",
                         "text": f"Phishing signal: {flag}"})

    # ---- transport bucket ----
    transport_pts = 0
    if not is_https:
        transport_pts += 15
        findings.append({"level": "high", "text": "No TLS — page served over cleartext http://"})
    mixed = [u for u in (p.scripts_ext + p.iframes + p.links)
             if abs_url(u).startswith("http://")]
    if is_https and mixed:
        transport_pts += 8
        findings.append({"level": "medium",
                         "text": f"Mixed content: {len(mixed)} resource(s) loaded over http:// on an https:// page"})
    breakdown["transport"] = min(25, transport_pts)

    score = sum(breakdown.values())
    grade = "low" if score < 25 else "medium" if score < 50 else "high" if score < 75 else "critical"

    ev: dict[str, Any] = {
        "identity": {
            "url": url,
            "final_url": final_url,
            "title": p.title.strip()[:120],
            "page_bytes": len(raw),
            "tls": is_https,
        },
        "scripts": {
            "external_count": len(ext_scripts),
            "external": ext_scripts[:20],
            "inline_count": len(p.scripts_inline),
            "suspicious_inline": sorted(set(sus_inline)),
            "event_handlers": p.event_handlers,
        },
        "trackers": {"count": len(tracker_hits), "items": sorted(set(tracker_hits))},
        "forms": {
            "count": len(p.forms),
            "password_forms": [
                {"action": f["action"][:120], "inputs": f["inputs"]} for f in pw_forms
            ],
        },
        "deception": {"points": breakdown["deception"], "flags": deception_flags},
        "risk": {"score": score, "grade": grade, "findings": findings[:8], "breakdown": breakdown},
    }
    return ev
