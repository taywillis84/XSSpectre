from __future__ import annotations

from xsspectre.reporting import ScanResult


def test_text_output_includes_entry_point_notes():
    result = ScanResult(target="https://example.test")
    result.notes.append("Discovered injection points: 2")
    result.notes.extend(
        [
            "Entry point: [query] GET https://example.test/search :: q",
            "Entry point: [form] POST https://example.test/login :: username",
        ]
    )

    output = result.to_text()

    assert "Entry point: [query] GET https://example.test/search :: q" in output
    assert "Entry point: [form] POST https://example.test/login :: username" in output
