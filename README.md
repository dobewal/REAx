<div align="center">

# REAX

### Reverse Engineer Anything — improved.

**One command. Zero setup. Answers instead of primitives.**

[![Python](https://img.shields.io/badge/python-3.10%2B-blue?style=flat-square)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/license-MIT-f4c430?style=flat-square)](LICENSE)
[![Status](https://img.shields.io/badge/status-alpha-orange?style=flat-square)](#roadmap)

```bash
pip install reax
reax analyze app.apk
```

</div>

> ⚠️ **Educational use only.** REAX is for learning and *authorized* security
> research — your own apps, or apps you have written permission to test.
> Misuse (cracking, cloning, or exploiting other people's apps) is on you, not us.
> Read [DISCLAIMER.md](DISCLAIMER.md).

---

Point REAX at an APK and get a **verdict in seconds**: risk score, risky permissions
explained in plain English, embedded tracker SDKs, suspicious API call sites,
hard-coded URLs/IPs, hidden native payloads — plus a shareable HTML report.
No Node, no Ghidra install, no 153-tool treasure hunt.

```
🟡 MEDIUM — risk score 27/100
  • Suspicious API in use: ProcessBuilder (8 call sites)
  • 65.7 MB native payload bundled in assets/ — classic hidden-payload pattern

  ✓ reports/app.reax.json
  ✓ reports/app.md
  ✓ reports/app.html
```

## Quickstart

```bash
pip install reax

# full analysis → JSON + Markdown + single-file HTML report
reax analyze app.apk -o reports/

# X-ray a native binary or .so library
reax analyze lib/arm64-v8a/libnative.so -o reports/

# what changed between two versions?
reax diff app-v1.apk app-v2.apk

# is everything working?
reax doctor
```

## What you get

| | |
|---|---|
| 🎯 **Risk verdict** | LOW / MEDIUM / HIGH / CRITICAL score with the exact findings behind it — plus an auditable 4-bucket score breakdown ([how scoring works](docs/scoring.md)) |
| 🔑 **Permissions, decoded** | every risky permission with severity and a plain-English "why it matters" |
| 🛰️ **Tracker detection** | 50+ known tracker SDKs (AdMob, AppsFlyer, Facebook, …) |
| 🧬 **Suspicious APIs** | `DexClassLoader`, `SmsManager`, `Runtime.exec`, … with call-site counts |
| 🌐 **Network indicators** | URLs and IPs pulled from DEX strings |
| 📦 **Hidden payloads** | native `.so` files enumerated from the real package (with sizes), big blobs in `assets/` flagged |
| 🔍 **Version diff** | new permissions, new trackers, new libs, risk delta between two APKs |
| ⚙️ **ELF X-ray** | suspicious imports, RWX segments, section entropy, packer signatures for native binaries |
| 📄 **Shareable report** | one self-contained HTML file — send it to anyone, no tool needed |

## REAX vs REA

REAX is inspired by [REA](https://github.com/morluto/rea) by morluto (MIT) —
a deep, serious toolkit with 150+ MCP tools. REAX makes a different trade:

| | REA | REAX |
|---|---|---|
| Install | Node + npm + bring-your-own Ghidra/IDA/Frida | `pip install reax` — everything bundled |
| Interface | 150+ primitives to compose yourself | one command → one verdict |
| Output | evidence bundles for experts | risk score + plain-English findings + HTML report |
| Language | TypeScript | Python — hackable in an afternoon |
| Agent support | MCP | MCP **+** open Agent Skills (`skills/`) for Claude Code, Cursor, Codex |

Use REA when you need a full reverse-engineering workbench.
Use REAX when you want to know *"is this APK shady?"* before lunch.

## Agent-native

```bash
pip install "reax[mcp]"
reax-mcp            # MCP server: analyze / risk_summary / diff_apks
```

Plus a ready-made skill at `skills/reverse-engineer-apk/SKILL.md` —
drop it into any agent that speaks the open Agent Skills format.

## Roadmap

- [x] ELF / Mach-O / PE analyzers (native binaries) — **ELF done in v0.2.0**
- [ ] DEX → Java decompile view for flagged methods
- [ ] `reax serve` — local web UI for reports
- [ ] PyPI release + single-binary builds
- [ ] iOS IPA support, Mach-O and PE binaries

## Contributing

PRs welcome. Keep it: one command, zero setup, answers not primitives.

## GitHub topics

If you fork this, tag it with:
`reverse-engineering` `apk-analysis` `dex-analysis` `app-security`
`mobile-security` `android-security` `malware-analysis`
`static-analysis` `threat-intelligence` `ai-agents` `agent-skills`
`mcp` `mcp-server` `claude-code` `cli`

## Attribution

REAX is an independent implementation inspired by
[REA](https://github.com/morluto/rea) © 2026 morluto (MIT).
APK parsing via [Androguard](https://github.com/androguard/androguard).
See [NOTICE](NOTICE) for full attribution.

## License

MIT — see [LICENSE](LICENSE).
