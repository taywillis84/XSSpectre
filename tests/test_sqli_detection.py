from __future__ import annotations

from urllib.parse import parse_qs, urlsplit

from xsspectre.scanners.common import HTTPResponse, InjectionPoint
from xsspectre.scanners.sqli import scan_for_sqli


def test_sqli_error_boolean_and_time_heuristics(monkeypatch):
    def fake_request(url: str, timeout: float, method: str = "GET", data=None):
        payload = parse_qs(urlsplit(url).query).get("id", [""])[0]

        if payload in {"'", '"'}:
            return HTTPResponse(status=500, body="You have an SQL syntax error near ...", elapsed=0.01)

        if payload in {"' OR '1'='1", "1 OR 1=1"}:
            return HTTPResponse(status=200, body="A" * 300, elapsed=0.05)

        if payload in {"' AND '1'='2", "1 AND 1=2"}:
            return HTTPResponse(status=200, body="B" * 50, elapsed=0.05)

        if payload in {
            "1' AND SLEEP(2)-- ",
            "1'; WAITFOR DELAY '0:0:2'--",
            "1 AND pg_sleep(2)--",
        }:
            return HTTPResponse(status=200, body="normal", elapsed=2.1)

        if payload == "1":
            return HTTPResponse(status=200, body="normal", elapsed=0.2)

        return HTTPResponse(status=200, body="normal", elapsed=0.2)

    monkeypatch.setattr("xsspectre.scanners.sqli.request_url", fake_request)

    points = [
        InjectionPoint(method="GET", url="https://example.test/items", parameter="id", source="query"),
    ]

    findings = scan_for_sqli(points, timeout=1.0)
    types = {f.vulnerability_type for f in findings}

    assert "sqli-error-hint" in types
    assert "sqli-boolean-hint" in types
    assert "sqli-time-hint" in types
    error_finding = next(f for f in findings if f.vulnerability_type == "sqli-error-hint")
    assert error_finding.entry_point == "[query] GET https://example.test/items :: id"


def test_sqli_attempt_deduplication_prevents_duplicate_findings(monkeypatch):
    def fake_request(url: str, timeout: float, method: str = "GET", data=None):
        payload = parse_qs(urlsplit(url).query).get("id", [""])[0]
        if payload == "'":
            return HTTPResponse(status=500, body="mysql syntax error", elapsed=0.01)
        return HTTPResponse(status=200, body="baseline", elapsed=0.1)

    monkeypatch.setattr("xsspectre.scanners.sqli.request_url", fake_request)

    duplicated_points = [
        InjectionPoint(method="GET", url="https://example.test/items", parameter="id", source="query"),
        InjectionPoint(method="GET", url="https://example.test/items", parameter="id", source="query"),
    ]

    findings = scan_for_sqli(duplicated_points, timeout=1.0)

    assert sum(1 for f in findings if f.vulnerability_type == "sqli-error-hint") == 1
