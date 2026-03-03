"""CLI entrypoint for XSSpectre.

Disclaimer: Scanning can be illegal or disruptive without authorization.
Only scan assets you own or are explicitly authorized to assess.
"""

from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

from .reporting import ScanResult, render_scan_results
from .scanners.common import crawl_and_discover
from .scanners.sqli import scan_for_sqli
from .scanners.xss import scan_for_xss


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="xsspectre",
        description=(
            "Authorized security scanner for baseline XSS/SQLi checks. "
            "Use only with explicit permission."
        ),
    )

    scan_parser = parser.add_subparsers(dest="command", required=True)
    scan_cmd = scan_parser.add_parser("scan", help="Scan targets for baseline vulnerability indicators")
    scan_cmd.add_argument("--xss", action="store_true", help="Run reflected-XSS checks")
    scan_cmd.add_argument("--sqli", action="store_true", help="Run SQL injection heuristic checks")
    scan_cmd.add_argument("--depth", type=int, default=1, help="Crawl depth (default: 1)")
    scan_cmd.add_argument("--timeout", type=float, default=5.0, help="Per-request timeout seconds")
    scan_cmd.add_argument("--concurrency", type=int, default=4, help="Parallel target workers")
    scan_cmd.add_argument(
        "--output",
        choices=["json", "text"],
        default="text",
        help="Output format",
    )

    scan_sub = scan_cmd.add_subparsers(dest="scan_mode", required=True)
    url_cmd = scan_sub.add_parser("url", help="Scan a single URL")
    url_cmd.add_argument("target_url")

    list_cmd = scan_sub.add_parser("list", help="Scan targets from file (1 URL per line)")
    list_cmd.add_argument("targets_file")

    return parser.parse_args()


def _scan_target(target_url: str, args: argparse.Namespace) -> ScanResult:
    checks_selected = args.xss or args.sqli
    run_xss = args.xss or not checks_selected
    run_sqli = args.sqli or not checks_selected

    result = ScanResult(target=target_url)
    result.notes.append("Authorization required: verify scope and written approval before scanning.")

    points = crawl_and_discover(target_url, depth=args.depth, timeout=args.timeout)
    result.notes.append(f"Discovered injection points: {len(points)}")
    result.notes.extend(
        [
            f"Entry point: [{point.source}] {point.method} {point.url} :: {point.parameter}"
            for point in points
        ]
    )

    if run_xss:
        result.findings.extend(scan_for_xss(points, timeout=args.timeout))

    if run_sqli:
        result.findings.extend(scan_for_sqli(points, timeout=args.timeout))

    return result


def _load_targets(args: argparse.Namespace) -> list[str]:
    if args.scan_mode == "url":
        return [args.target_url]

    path = Path(args.targets_file)
    return [line.strip() for line in path.read_text(encoding="utf-8").splitlines() if line.strip() and not line.startswith("#")]


def main() -> int:
    args = _parse_args()
    targets = _load_targets(args)

    if not targets:
        raise SystemExit("No targets supplied.")

    results: list[ScanResult] = []
    max_workers = max(args.concurrency, 1)

    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = {pool.submit(_scan_target, target, args): target for target in targets}
        for future in as_completed(futures):
            target = futures[future]
            try:
                results.append(future.result())
            except Exception as exc:
                failed = ScanResult(target=target)
                failed.notes.append(f"Scan failed: {exc}")
                results.append(failed)

    print(render_scan_results(sorted(results, key=lambda item: item.target), output=args.output))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
