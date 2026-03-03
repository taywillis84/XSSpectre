"""Baseline SQLi detection heuristics (safe probes)."""

from __future__ import annotations

from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from ..reporting import VulnerabilityFinding
from .common import InjectionPoint, request_url

SQL_ERRORS = [
    "sql syntax",
    "mysql",
    "odbc",
    "sqlite",
    "postgresql",
    "unclosed quotation mark",
]

BOOLEAN_PROBES = (
    ("' OR '1'='1", "' AND '1'='2"),
    ("1 OR 1=1", "1 AND 1=2"),
)

TIME_PROBES = [
    "1' AND SLEEP(2)-- ",
    "1'; WAITFOR DELAY '0:0:2'--",
    "1 AND pg_sleep(2)--",
]


def _inject_get(url: str, parameter: str, payload: str) -> str:
    split = urlsplit(url)
    query = dict(parse_qsl(split.query, keep_blank_values=True))
    query[parameter] = payload
    return urlunsplit((split.scheme, split.netloc, split.path, urlencode(query, doseq=True), ""))


def _request_point(point: InjectionPoint, timeout: float, payload: str):
    if point.method == "POST":
        data = {field: "1" for field in point.form_fields}
        data[point.parameter] = payload
        response = request_url(point.url, timeout=timeout, method="POST", data=data)
        return point.url, response

    target = _inject_get(point.url, point.parameter, payload)
    response = request_url(target, timeout=timeout)
    return target, response


def scan_for_sqli(points: list[InjectionPoint], timeout: float) -> list[VulnerabilityFinding]:
    findings: list[VulnerabilityFinding] = []
    attempted: set[tuple[str, str, str]] = set()

    for point in points:
        # Error-based hints.
        for payload in ["'", '"']:
            dedupe_key = (point.url, point.parameter, payload)
            if dedupe_key in attempted:
                continue
            attempted.add(dedupe_key)
            try:
                target, response = _request_point(point, timeout, payload)
            except Exception:
                continue

            lower_body = response.body.lower()
            for token in SQL_ERRORS:
                if token in lower_body:
                    snippet_start = max(lower_body.find(token) - 40, 0)
                    snippet_end = min(snippet_start + 200, len(response.body))
                    findings.append(
                        VulnerabilityFinding(
                            vulnerability_type="sqli-error-hint",
                            url=target,
                            parameter=point.parameter,
                            entry_point=f"[{point.source}] {point.method} {point.url} :: {point.parameter}",
                            payload=payload,
                            confidence="medium",
                            evidence_snippet=response.body[snippet_start:snippet_end].replace("\n", " "),
                        )
                    )
                    break

        # Boolean-based hints.
        for true_payload, false_payload in BOOLEAN_PROBES:
            dedupe_key = (point.url, point.parameter, true_payload)
            if dedupe_key in attempted:
                continue
            attempted.add(dedupe_key)
            try:
                target_true, resp_true = _request_point(point, timeout, true_payload)
                _, resp_false = _request_point(point, timeout, false_payload)
            except Exception:
                continue

            len_diff = abs(len(resp_true.body) - len(resp_false.body))
            if resp_true.status == resp_false.status and len_diff > 80:
                findings.append(
                    VulnerabilityFinding(
                        vulnerability_type="sqli-boolean-hint",
                        url=target_true,
                        parameter=point.parameter,
                        entry_point=f"[{point.source}] {point.method} {point.url} :: {point.parameter}",
                        payload=f"{true_payload} | {false_payload}",
                        confidence="low",
                        evidence_snippet=f"body length delta={len_diff}",
                    )
                )

        # Time-based hints.
        for payload in TIME_PROBES:
            dedupe_key = (point.url, point.parameter, payload)
            if dedupe_key in attempted:
                continue
            attempted.add(dedupe_key)
            try:
                target, delayed = _request_point(point, timeout, payload)
                _, baseline = _request_point(point, timeout, "1")
            except Exception:
                continue

            if delayed.elapsed - baseline.elapsed >= 1.5:
                findings.append(
                    VulnerabilityFinding(
                        vulnerability_type="sqli-time-hint",
                        url=target,
                        parameter=point.parameter,
                        entry_point=f"[{point.source}] {point.method} {point.url} :: {point.parameter}",
                        payload=payload,
                        confidence="low",
                        evidence_snippet=(
                            f"response delay delta={delayed.elapsed - baseline.elapsed:.2f}s"
                        ),
                    )
                )

    return findings
