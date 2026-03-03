"""Structured reporting helpers for XSSpectre."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from json import dumps
from typing import Any, Literal

Confidence = Literal["low", "medium", "high"]
OutputFormat = Literal["json", "text"]


@dataclass(slots=True)
class VulnerabilityFinding:
    vulnerability_type: str
    url: str
    parameter: str
    payload: str
    confidence: Confidence
    evidence_snippet: str


@dataclass(slots=True)
class ScanResult:
    target: str
    findings: list[VulnerabilityFinding] = field(default_factory=list)
    injection_points: list[dict[str, str]] = field(default_factory=list)
    scanned_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat(timespec="seconds")
    )
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def to_json(self) -> str:
        return dumps(self.to_dict(), indent=2, sort_keys=True)

    def to_text(self) -> str:
        lines = [f"Target: {self.target}", f"Scanned at: {self.scanned_at}"]
        if self.notes:
            lines.append("Notes:")
            lines.extend([f"  - {note}" for note in self.notes])

        if self.injection_points:
            lines.append("Injection points:")
            lines.extend(
                [
                    "  - [{source}] {method} {url} :: {parameter}".format(**point)
                    for point in self.injection_points
                ]
            )

        if not self.findings:
            lines.append("Findings: none")
            return "\n".join(lines)

        lines.append("Findings:")
        for idx, finding in enumerate(self.findings, start=1):
            lines.extend(
                [
                    f"  {idx}. [{finding.vulnerability_type}] {finding.url}",
                    f"     parameter: {finding.parameter}",
                    f"     confidence: {finding.confidence}",
                    f"     payload: {finding.payload}",
                    f"     evidence: {finding.evidence_snippet}",
                ]
            )
        return "\n".join(lines)


def render_scan_results(results: list[ScanResult], output: OutputFormat) -> str:
    if output == "json":
        return dumps([result.to_dict() for result in results], indent=2, sort_keys=True)

    return "\n\n".join(result.to_text() for result in results)
