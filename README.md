# XSSpectre

XSSpectre is a lightweight command-line security scanner for **baseline reflected-XSS and SQLi heuristics**.
It is designed for practical use in Kali-style workflows where you need a fast first-pass sweep before deeper
manual testing.

> ⚠️ **Authorized targets only**
>
> Scanning systems without explicit permission can be illegal and disruptive. Use XSSpectre only on assets you
> own or are contractually authorized to test.

## Purpose and scope

XSSpectre focuses on practical reconnaissance and triage:

- Crawl a target site and collect candidate injection points from query strings and forms.
- Probe each injection point with conservative payload sets for reflected XSS and SQLi error/time signals.
- Return structured findings suitable for quick review or downstream automation.

It is intentionally not a full DAST platform. It does not attempt authenticated session management,
JavaScript-heavy crawling, or guaranteed exploit validation.

## Installation

### With `pipx` (recommended for CLI usage)

```bash
pipx install .
```

### With `pip`

```bash
python -m pip install .
```

### Optional extras

Install HTTP-client extras (for future adapters/extensions):

```bash
python -m pip install '.[http]'
```

Install development tooling:

```bash
python -m pip install '.[dev]'
```

## Quick start

### Scan one URL (default checks: XSS + SQLi)

```bash
xsspectre scan --depth 2 --timeout 6 --concurrency 4 url "https://target.example/search?q=test"
```

### Run only XSS checks

```bash
xsspectre scan --xss --depth 1 --output text url "https://target.example"
```

### Run only SQLi checks against a target list

```bash
xsspectre scan --sqli --timeout 8 --concurrency 6 --output json list targets.txt
```

Where `targets.txt` contains one URL per line:

```text
https://target-a.example/
https://target-b.example/app?cat=1
# comments are ignored
```

## Output format examples

### Text output (`--output text`)

```text
Target: https://target.example/search?q=test
Scanned at: 2026-03-03T14:42:11+00:00
Notes:
  - Authorization required: verify scope and written approval before scanning.
  - Discovered injection points: 4
Findings:
  1. [reflected_xss] https://target.example/search
     parameter: q
     confidence: medium
     payload: <script>alert(1337)</script>
     evidence: ...<script>alert(1337)</script>...
```

### JSON output (`--output json`)

```json
[
  {
    "target": "https://target.example/search?q=test",
    "scanned_at": "2026-03-03T14:42:11+00:00",
    "notes": [
      "Authorization required: verify scope and written approval before scanning.",
      "Discovered injection points: 4"
    ],
    "findings": [
      {
        "vulnerability_type": "reflected_xss",
        "url": "https://target.example/search",
        "parameter": "q",
        "payload": "<script>alert(1337)</script>",
        "confidence": "medium",
        "evidence_snippet": "...<script>alert(1337)</script>..."
      }
    ]
  }
]
```

## Documentation

See the `docs/` directory for operator-facing guidance:

- `docs/scan-strategy.md`
- `docs/tuning-options.md`
- `docs/false-positive-handling.md`
