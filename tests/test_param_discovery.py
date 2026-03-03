from __future__ import annotations

from pathlib import Path

from xsspectre.scanners.common import HTTPResponse, crawl_and_discover

FIXTURES = Path(__file__).parent / "fixtures"


def test_query_and_form_parameter_discovery_with_deduplication(monkeypatch):
    root_html = (FIXTURES / "forms_page.html").read_text(encoding="utf-8")

    pages = {
        "https://example.test/start?a=1&b=2&a=3": HTTPResponse(status=200, body=root_html, elapsed=0.01),
        "https://example.test/next?page=1": HTTPResponse(status=200, body="<html></html>", elapsed=0.01),
    }

    def fake_request(url: str, timeout: float, method: str = "GET", data=None):
        return pages[url]

    monkeypatch.setattr("xsspectre.scanners.common.request_url", fake_request)

    points = crawl_and_discover("https://example.test/start?a=1&b=2&a=3", depth=2, timeout=0.5)

    discovered = {(p.method, p.url, p.parameter, p.source, p.form_fields) for p in points}

    assert ("GET", "https://example.test/start", "a", "query", ()) in discovered
    assert ("GET", "https://example.test/start", "b", "query", ()) in discovered
    assert (
        "POST",
        "https://example.test/submit",
        "username",
        "form",
        ("bio", "username"),
    ) in discovered
    assert (
        "POST",
        "https://example.test/submit",
        "bio",
        "form",
        ("bio", "username"),
    ) in discovered
    assert (
        "GET",
        "https://example.test/search",
        "q",
        "form",
        ("q", "sort"),
    ) in discovered

    # Duplicate query args and duplicate form fields should not produce duplicate points.
    assert sum(1 for p in points if p.parameter == "a" and p.source == "query") == 1
    assert sum(1 for p in points if p.parameter == "username" and p.source == "form") == 1
