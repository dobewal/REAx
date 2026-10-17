# REAX scoring model

Every REAX verdict is a sum of **4 buckets × 25 points = 100**.
The breakdown is shown in the CLI, the Markdown report, and the HTML report,
so anyone can audit exactly where the points came from.

Grades: **LOW** < 25 · **MEDIUM** < 50 · **HIGH** < 75 · **CRITICAL** ≥ 75.

These are heuristics, not proofs. A HIGH score means "worth a closer look",
never "definitely malware". False positives exist — e.g. a root tool legitimately
uses `ProcessBuilder`, a game legitimately bundles big native libraries.

## APK buckets

| Bucket | Max | How points are earned |
|---|---|---|
| **Permissions** | 25 | Each declared permission has a severity 0–3 (`PERMISSION_RISK`). Points = severity-sum × 1.5. |
| **Code** | 25 | Suspicious DEX API usage found by scanning invoke instructions. Points = severity-sum × 2.5. |
| **Privacy** | 25 | Tracker SDK points (ad networks 3, analytics 2, other 1 — see `TRACKER_CATEGORY`) + 5 if the app allows cleartext (unencrypted) traffic. |
| **Packaging** | 25 | Unsigned 12 · Android **debug certificate** 12 · debuggable 5 · >10 MB native `.so` hidden in `assets/` 10. |

The debug-certificate check is one of the strongest signals: legitimate developers
never ship apps signed with the public Android debug key, but repackaged malware
often is.

## ELF buckets

| Bucket | Max | How points are earned |
|---|---|---|
| **Code** | 25 | Dangerous imported functions (`execve`, `system`, `mmap`, `kill`, …). Points = severity-sum × 3.5. |
| **Stealth** | 25 | Anti-analysis: `ptrace` 12 · `dlopen`/`dlsym` 6 each · packer signature (e.g. UPX) 10. |
| **Memory** | 25 | RWX segment (readable+writable+executable) 15 · high-entropy section (>7.5, possibly packed/encrypted) 8. |
| **Network** | 25 | Network imports (`socket`, `connect`, DNS) severity-sum × 4, plus up to 8 for hard-coded URLs/IPs found in strings. |

## Tuning

Weights live in `reax/analyzers/apk.py` (`PERMISSION_RISK`, `SUSPICIOUS_APIS`,
`TRACKER_CATEGORY`) and `reax/analyzers/elf.py` (`SUSPICIOUS_IMPORTS`).
If a weight produces consistent false positives on real samples, change the
weight — don't add an exception. The breakdown display is the calibration tool:
when a score looks wrong, the bucket that looks wrong tells you which weight to fix.
