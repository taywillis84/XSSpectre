# Scan strategy

XSSpectre uses a three-stage strategy:

1. **Crawl** target pages up to the configured depth.
2. **Identify injection points** in query parameters and HTML forms.
3. **Probe** each point with targeted payloads for reflected-XSS and SQLi indicators.

## 1) Crawl

- Starts from each supplied seed URL.
- Follows in-scope links on the same host.
- Respects `--depth` as the number of crawl iterations.

Operationally, begin with a shallow crawl (`--depth 1`) to reduce noise, then increase depth for broad applications.

## 2) Identify injection points

Candidate inputs are collected from:

- Query-string keys (`?q=...&page=...`)
- Form fields (`input`, `textarea`, `select`) with detected method/action

Each candidate is normalized and deduplicated to reduce repeated probes.

## 3) Probe

For each discovered point:

- **XSS checks** inject reflective payloads and inspect response content.
- **SQLi checks** apply error/time heuristics and compare observed behavior.

A finding should be treated as a lead requiring analyst confirmation, not immediate proof of exploitability.
