from __future__ import annotations

from pathlib import Path
from urllib.parse import parse_qs, urlsplit

from xsspectre.scanners.common import HTTPResponse, InjectionPoint
from xsspectre.scanners.xss import scan_for_xss

FIXTURES = Path(__file__).parent / "fixtures"


def test_xss_reflection_classification_and_evidence(monkeypatch):
    encoded_html = (FIXTURES / "reflected_encoded.html").read_text(encoding="utf-8")

    payload_to_body = {
        "<script>alert(1337)</script>": encoded_html,
        '"/><svg/onload=alert(1337)>': "<html><body>Echo: \"/><svg/onload=alert(1337)></body></html>",
        "</title><script>alert(1337)</script>": "<html><body>no reflection</body></html>",
    }

    def fake_request(url: str, timeout: float, method: str = "GET", data=None):
        assert method == "GET"
        payload = parse_qs(urlsplit(url).query).get("q", [""])[0]
        return HTTPResponse(status=200, body=payload_to_body[payload], elapsed=0.01)

    monkeypatch.setattr("xsspectre.scanners.xss.request_url", fake_request)

    points = [
        InjectionPoint(method="GET", url="https://example.test/search", parameter="q", source="query"),
    ]
    findings = scan_for_xss(points, timeout=0.5)

    by_type = {f.vulnerability_type: f for f in findings}
    assert "xss-reflected" in by_type
    assert "xss-reflection-encoded" in by_type
    assert "Echo:" in by_type["xss-reflected"].evidence_snippet


def test_xss_attempt_deduplication_prevents_duplicate_findings(monkeypatch):
    def always_reflect(url: str, timeout: float, method: str = "GET", data=None):
        return HTTPResponse(status=200, body="prefix <script>alert(1337)</script> suffix", elapsed=0.01)

    monkeypatch.setattr("xsspectre.scanners.xss.request_url", always_reflect)

    duplicated_points = [
        InjectionPoint(method="GET", url="https://example.test/search", parameter="q", source="query"),
        InjectionPoint(method="GET", url="https://example.test/search", parameter="q", source="query"),
    ]

    findings = scan_for_xss(duplicated_points, timeout=0.5)

    assert len(findings) == 1
    assert findings[0].vulnerability_type == "xss-reflected"
