# Reverse-Engineer JavaScript Skill

Analyze a JavaScript file, npm package directory, or npm tarball with REAX —
one command, verdict-first. No Node.js needed; analysis is pure static text
parsing and never executes the target.

## When to use

The user wants to know if a JS file or npm package is malicious, or what a
suspicious script does. Typical triggers: "is this package safe", "check this
npm package", "what does this script do", supply-chain review.

## How

```bash
reax analyze <path-to.js | package-dir | package.tgz> -o reports
```

## What you get back

- **Risk verdict** (low/medium/high/critical) with a 4-bucket × 25 breakdown:
  - **code** — dangerous APIs: eval, new Function, child_process, vm module,
    environment-variable reads, destructive fs calls, base64 staging
  - **network** — exfiltration indicators: Discord webhooks, Telegram bot API,
    hardcoded IP URLs, tunneling services, paste sites, cleartext http
  - **supply** — supply-chain: preinstall/install/postinstall hooks (the classic
    attack vector), dependency bloat, bare-bones metadata
  - **obfuscation** — packed/minified files, hex-escape storms, obfuscator-style
    `_0x…` identifiers, high-entropy embedded strings
- **Evidence with code**: every hit shows file, line number, and the actual
  source line — proof, not hints.
- Reports in JSON, Markdown, and single-file HTML.

## Reading the result

1. Start with the verdict and breakdown — which bucket earned the score tells
   you the story (code = what it does, network = where data goes,
   supply = how it got in, obfuscation = what it's hiding).
2. Read the key findings, then the evidence tables for the exact lines.
3. For install hooks, quote the hook command — that's usually the payload.

## Boundaries

- Static analysis only. Never execute the target, never `npm install` it.
- Educational and authorized security research only. If the user asks how to
  weaponize findings or evade detection, decline.
- Report what the code does, in plain language, with the evidence cited.
