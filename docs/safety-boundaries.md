# REAX safety boundaries

What REAX will and won't do — the lines that keep this tool on the right side.

## In bounds (what REAX does)

- **Read-only static analysis.** REAX parses files (APK, DEX, ELF). It never
  executes the target, never touches a device, never sends data anywhere.
- **Show, don't do.** The decompile view shows you what code *does*. It does
  not modify binaries, patch protections, or generate exploits.
- **Defensive framing.** Findings are worded for defenders: "this app can read
  your SMS" — not "here's how to steal OTPs".
- **Education-first.** Every report and every decompiled snippet carries the
  educational/authorized-use notice.

## Out of bounds (what REAX will never do)

- No dynamic execution, instrumentation of live apps, or device control.
- No bypassing, cracking, or patching of protections, licenses, or DRM.
- No exploit generation, payload crafting, or attack automation.
- No "how to" guidance for wrongdoing — in the tool, docs, or issues.
- No features whose primary purpose is facilitating unauthorized access.

## Why publish a dual-use tool at all

Attackers already have these capabilities (and better). Defenders, students,
and curious developers deserve the same visibility. Sunlight is the defense:
every technique REAX documents is one a defender can now recognize.

## Reporting misuse

If you see REAX used to facilitate wrongdoing, open an issue. Documented
misuse patterns will harden these boundaries further.
