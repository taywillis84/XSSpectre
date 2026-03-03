from __future__ import annotations

from xsspectre.reporting import ScanResult


def test_text_output_includes_injection_points_section():
    result = ScanResult(target="https://example.test")
    result.notes.append("Discovered injection points: 2")
    result.injection_points.extend(
        [
            "[query] GET https://example.test/search :: q",
            "[form] POST https://example.test/login :: username",
        ]
    )

    output = result.to_text()

    assert "Injection points:" in output
    assert "[query] GET https://example.test/search :: q" in output
    assert "[form] POST https://example.test/login :: username" in output
