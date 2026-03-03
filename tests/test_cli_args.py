from __future__ import annotations

import argparse

from xsspectre import cli
from xsspectre.reporting import VulnerabilityFinding
from xsspectre.scanners.common import InjectionPoint


def test_parse_args_scan_url_defaults(monkeypatch):
    monkeypatch.setattr("sys.argv", ["xsspectre", "scan", "url", "https://example.test"]) 

    args = cli._parse_args()

    assert args.command == "scan"
    assert args.scan_mode == "url"
    assert args.target_url == "https://example.test"
    assert args.depth == 1
    assert args.timeout == 5.0
    assert args.output == "text"


def test_parse_args_scan_list_with_toggles(monkeypatch, tmp_path):
    targets_file = tmp_path / "targets.txt"
    targets_file.write_text("https://a.test\n", encoding="utf-8")
    monkeypatch.setattr(
        "sys.argv",
        [
            "xsspectre",
            "scan",
            "--xss",
            "--depth",
            "3",
            "--concurrency",
            "8",
            "list",
            str(targets_file),
        ],
    )

    args = cli._parse_args()

    assert args.scan_mode == "list"
    assert args.targets_file == str(targets_file)
    assert args.xss is True
    assert args.sqli is False
    assert args.depth == 3
    assert args.concurrency == 8


def test_scan_target_routes_enabled_checks(monkeypatch):
    args = argparse.Namespace(xss=True, sqli=False, depth=1, timeout=1.0)

    monkeypatch.setattr(
        cli,
        "crawl_and_discover",
        lambda *_args, **_kwargs: [
            InjectionPoint(method="GET", url="https://example.test/search", parameter="q", source="query")
        ],
    )
    monkeypatch.setattr(
        cli,
        "scan_for_xss",
        lambda points, timeout: [
            VulnerabilityFinding("xss-reflected", "https://example.test", "q", "[query] GET https://example.test/search :: q", "p", "high", "snippet")
        ],
    )
    monkeypatch.setattr(cli, "scan_for_sqli", lambda points, timeout: [])

    result = cli._scan_target("https://example.test", args)

    assert [f.vulnerability_type for f in result.findings] == ["xss-reflected"]
    assert result.injection_points == ["[query] GET https://example.test/search :: q"]


def test_scan_target_runs_both_checks_when_none_selected(monkeypatch):
    args = argparse.Namespace(xss=False, sqli=False, depth=1, timeout=1.0)

    monkeypatch.setattr(
        cli,
        "crawl_and_discover",
        lambda *_args, **_kwargs: [
            InjectionPoint(method="GET", url="https://example.test/search", parameter="q", source="query")
        ],
    )
    monkeypatch.setattr(
        cli,
        "scan_for_xss",
        lambda points, timeout: [
            VulnerabilityFinding("xss-reflected", "https://example.test", "q", "[query] GET https://example.test/search :: q", "p", "high", "snippet")
        ],
    )
    monkeypatch.setattr(
        cli,
        "scan_for_sqli",
        lambda points, timeout: [
            VulnerabilityFinding("sqli-error-hint", "https://example.test", "id", "[query] GET https://example.test/search :: q", "'", "medium", "snippet")
        ],
    )

    result = cli._scan_target("https://example.test", args)

    assert {f.vulnerability_type for f in result.findings} == {"xss-reflected", "sqli-error-hint"}
    assert result.injection_points == ["[query] GET https://example.test/search :: q"]
