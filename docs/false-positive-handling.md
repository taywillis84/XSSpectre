# False-positive handling

Automated heuristics are useful but imperfect. Use this workflow to triage findings.

## 1) Reproduce manually

- Replay the exact request with the reported parameter and payload.
- Confirm whether reflection or SQL error behavior persists across repeated attempts.
- Validate in a browser and raw HTTP client to avoid rendering/tool artifacts.

## 2) Check context and encoding

For XSS-like reflections, inspect:

- HTML context (attribute/body/script/string)
- Output encoding behavior (`<`, `>`, quotes, slashes)
- Whether CSP or sanitization neutralizes execution

Reflection alone is not equivalent to exploitable XSS.

## 3) Validate SQLi signals

For SQLi-like findings:

- Compare baseline and payload response times over multiple runs.
- Look for stable error signatures, not one-off failures.
- Rule out upstream failures (WAF blocks, transient 5xx, network jitter).

## 4) Assign confidence and next action

- **Low confidence**: noisy/unreliable signal; keep as watch item.
- **Medium confidence**: repeatable indicator; requires manual deep-dive.
- **High confidence**: reproducible impact pattern; escalate for remediation.

Always include request/response evidence in your report so reviewers can independently verify conclusions.
