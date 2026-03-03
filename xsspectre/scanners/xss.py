"""Baseline reflected-XSS heuristics.

Only test authorized targets.
"""

from __future__ import annotations

from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from ..reporting import VulnerabilityFinding
from .common import InjectionPoint, request_url

XSS_PAYLOADS = [
    "<script>alert(1337)</script>",
    '"/><svg/onload=alert(1337)>',
    "</title><script>alert(1337)</script>",
]


def _inject_get(url: str, parameter: str, payload: str) -> str:
    split = urlsplit(url)
    query = dict(parse_qsl(split.query, keep_blank_values=True))
    query[parameter] = payload
    return urlunsplit((split.scheme, split.netloc, split.path, urlencode(query, doseq=True), ""))


def scan_for_xss(points: list[InjectionPoint], timeout: float) -> list[VulnerabilityFinding]:
    findings: list[VulnerabilityFinding] = []
    attempted: set[tuple[str, str, str]] = set()

    for point in points:
        for payload in XSS_PAYLOADS:
            key = (point.url, point.parameter, payload)
            if key in attempted:
                continue
            attempted.add(key)

            try:
                if point.method == "POST":
                    data = {field: "xsspectre" for field in point.form_fields}
                    data[point.parameter] = payload
                    response = request_url(point.url, timeout=timeout, method="POST", data=data)
                    request_target = point.url
                else:
                    request_target = _inject_get(point.url, point.parameter, payload)
                    response = request_url(request_target, timeout=timeout)
            except Exception:
                continue

            body = response.body
            if payload in body:
                snippet_start = max(body.find(payload) - 30, 0)
                snippet_end = min(snippet_start + 180, len(body))
                findings.append(
                    VulnerabilityFinding(
                        vulnerability_type="xss-reflected",
                        url=request_target,
                        parameter=point.parameter,
                        entry_point=f"[{point.source}] {point.method} {point.url} :: {point.parameter}",
                        payload=payload,
                        confidence="high",
                        evidence_snippet=body[snippet_start:snippet_end].replace("\n", " "),
                    )
                )
            elif payload.replace("<", "&lt;") in body:
                encoded = payload.replace("<", "&lt;")
                pos = body.find(encoded)
                snippet_start = max(pos - 30, 0)
                snippet_end = min(snippet_start + 180, len(body))
                findings.append(
                    VulnerabilityFinding(
                        vulnerability_type="xss-reflection-encoded",
                        url=request_target,
                        parameter=point.parameter,
                        entry_point=f"[{point.source}] {point.method} {point.url} :: {point.parameter}",
                        payload=payload,
                        confidence="medium",
                        evidence_snippet=body[snippet_start:snippet_end].replace("\n", " "),
                    )
                )

    return findings
