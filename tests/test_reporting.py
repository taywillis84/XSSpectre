from __future__ import annotations

from xsspectre.reporting import ScanResult


def test_text_output_includes_injection_points_section():
    result = ScanResult(target="https://example.test")
    result.notes.append("Discovered injection points: 2")
    result.injection_points.extend(
        [
            {
                "source": "query",
                "method": "GET",
                "url": "https://example.test/search",
                "parameter": "q",
            },
            {
                "source": "form",
                "method": "POST",
                "url": "https://example.test/login",
                "parameter": "username",
            },
        ]
    )

    output = result.to_text()

    assert "Injection points:" in output
    assert "[query] GET https://example.test/search :: q" in output
    assert "[form] POST https://example.test/login :: username" in output


def test_to_dict_includes_structured_injection_points():
    result = ScanResult(target="https://example.test")
    result.injection_points.append(
        {"source": "query", "method": "GET", "url": "https://example.test/search", "parameter": "q"}
    )

    data = result.to_dict()

    assert data["injection_points"][0]["parameter"] == "q"
