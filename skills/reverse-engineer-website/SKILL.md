# Reverse-Engineer Website Skill

Analyze a website with REAX — one command, verdict-first. Give it a URL; it
fetches the page once (no browser, no JavaScript execution) and scores what
the page loads and asks for.

## When to use

The user wants to check if a site is safe, sketchy, or a phishing page.
Typical triggers: "is this site legit", "check this URL", "looks like a
phishing page", "what trackers does this site use".

## How

```bash
reax analyze https://example.com -o reports
```

## What you get back

- **Risk verdict** (low/medium/high/critical) with a 4-bucket × 25 breakdown:
  - **scripts** — suspicious inline JavaScript (eval, document.write),
    cleartext external scripts, script bloat
  - **privacy** — third-party trackers (analytics, pixels, session recorders,
    ad networks)
  - **deception** — phishing signals: bare-IP hosting, punycode domains,
    brand keywords in unofficial domains, password forms, subdomain stuffing
  - **transport** — missing TLS, mixed content on https pages
- Reports in JSON, Markdown, and single-file HTML.

## Reading the result

1. A **high deception** score is the phishing tell — treat the site as hostile.
2. **Transport** failures (no TLS) plus a password form means credentials
   would travel in cleartext — say so plainly.
3. Trackers alone are low-severity; they're context, not a verdict.

## Boundaries

- One GET request, read-only. Never submit forms, never log in, never probe
  beyond the single page fetch.
- Educational and authorized security research only. If the user wants help
  building a phishing page or evading detection, decline.
- When a site looks like phishing, say so directly and advise not to enter
  credentials — that's the helpful answer.
