# REAX launch kit

Post in this order, same day, morning US time:
1. Hacker News (Show HN) — 2. r/ReverseEngineering — 3. X thread — 4. r/androiddev (Showcase Saturday only)

Rules: one account, no vote begging, answer every comment in the first 4 hours.
Never buy stars / join star-pods — GitHub flags it and it kills the repo.

---

## 1. Hacker News — Show HN

Title: `Show HN: REAX – one-command APK reverse engineering (pip install, verdict in seconds)`

Body:
```
I got tired of needing Node + Ghidra + 150 tools just to answer "is this APK shady?"

REAX is a small Python tool (inspired by REA) that analyzes an APK with one
command and gives you a verdict: risk score, risky permissions in plain English,
embedded tracker SDKs, suspicious API call sites, hard-coded URLs/IPs, hidden
native payloads — plus a single-file HTML report you can send anyone.

  pip install reax
  reax analyze app.apk
  reax diff v1.apk v2.apk   # what changed between versions

It's also agent-native: MCP server + an open Agent Skills file so Claude Code /
Cursor / Codex can reverse-engineer APKs directly.

APK support today, ELF/Mach-O/PE on the roadmap. MIT licensed.
Happy to answer questions — and tell me what APK format support you'd want next.
```

## 2. Reddit — r/ReverseEngineering

Title: `[Tool] REAX — one-command APK analysis: risk verdict, trackers, suspicious APIs, version diff`

Body:
```
Built a small open-source tool for quick APK triage and wanted feedback from
people who do this for real.

What it does in one command (`reax analyze app.apk`):
- Risk verdict (LOW/MED/HIGH/CRITICAL) with findings, not just data dumps
- Risky permissions with plain-English explanations
- Tracker SDK detection (50+ signatures)
- Suspicious API usage with call-site counts (DexClassLoader, SmsManager, exec…)
- URLs/IPs extracted from DEX strings
- Native .so inventory from the actual package + flags big blobs hidden in assets/
- `reax diff v1.apk v2.apk` — new permissions/trackers/libs between versions
- Single-file HTML report

Zero setup: pip install, no Ghidra/IDA/Frida required. Python, MIT.
Also ships an MCP server + Agent Skills file for agent-driven RE.

Repo: <link>

Known limits (v0.1): APK only, no decompiler view yet, heuristics not proofs.
What would make this actually useful in your workflow?
```

## 3. X / Twitter thread

1/ I built REAX: point it at any APK, get a verdict in seconds.

pip install reax
reax analyze app.apk

Risk score, shady permissions explained, trackers, hidden payloads — one HTML report. 🧵

2/ Example: it flagged a 65MB native .so hidden in assets/ + ProcessBuilder call sites in an APK with ZERO manifest permissions. That's the kind of thing manual triage misses.

3/ It also diffs versions: `reax diff v1.apk v2.apk` → new permissions, new trackers, new libs, risk delta. Update safety checks in one command.

4/ Agent-native too: MCP server + open Agent Skills file, so your coding agent can reverse-engineer APKs directly.

MIT, Python, zero setup. Link in replies. What should it analyze next — ELF? IPA?

## 4. r/androiddev — only on Self-Promotion Saturday

Title: `[Self-promo Saturday] REAX — I made a one-command APK security triage tool`

Body: short version of the r/ReverseEngineering post, framed for devs auditing
third-party SDKs/APKs they ship.
