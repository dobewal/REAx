---
name: reverse-engineer-apk
description: Reverse-engineer an Android APK with REAX — one command gives identity, permission risks, tracker SDKs, suspicious API usage, network indicators and a risk verdict, plus version diffs.
---

# Reverse-engineer an APK with REAX

REAX analyzes an APK with zero setup (`pip install reax`) and returns **answers, not primitives**: a risk verdict, risky permissions with explanations, embedded tracker SDKs, suspicious API call sites, URLs/IPs from strings, and a shareable HTML report.

## Analyze

```bash
reax analyze app.apk -o reports/
# writes app.reax.json, app.md, app.html
```

Key outputs to quote to the user:
- **Verdict**: LOW / MEDIUM / HIGH / CRITICAL + score /100 + findings list
- **Permissions**: only the risky ones matter — each has a severity and a plain-English "why"
- **Trackers**: named SDKs (AdMob, AppsFlyer, Facebook…) — count and list
- **Suspicious APIs**: e.g. `DexClassLoader` (dynamic code loading), `SmsManager`, `Runtime.exec`
- **Network indicators**: hard-coded URLs and IPs extracted from DEX strings

## Diff two versions

```bash
reax diff old.apk new.apk
# highlights: new risky permissions, new trackers, new native libs, risk delta
```

Use this when the user asks "what changed in the update" or "is the new version safe".

## MCP tools (when running as a server)

- `analyze(path)` — full evidence JSON
- `risk_summary(path)` — quick verdict only (token-cheap)
- `diff_apks(old_path, new_path)` — Markdown diff report

## Rules

- Analysis is local and read-only — REAX never executes the target.
- Quote the risk grade and the top 3 findings first; details on demand.
- Never claim an app is "safe" — report LOW risk with the evidence, not a guarantee.
