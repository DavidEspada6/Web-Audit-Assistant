from __future__ import annotations

import argparse
from datetime import datetime, timezone

from .checks import run_checks
from .http_client import HttpClient, HttpClientError
from .models import AuditReport
from .report import write_json_report, write_markdown_report
from .scope import build_scope_policy


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="web-audit",
        description="Safe web audit helper for authorized assessments.",
    )
    subparsers = parser.add_subparsers(dest="command")

    scan = subparsers.add_parser("scan", help="Run a controlled web audit")
    scan.add_argument("url", help="Target URL, for example https://example.com")
    scan.add_argument(
        "--scope",
        action="append",
        required=True,
        help="Allowed host or domain. Required. Can be used more than once.",
    )
    scan.add_argument("--json", help="Write JSON report to this path")
    scan.add_argument("--markdown", help="Write Markdown report to this path")
    scan.add_argument("--timeout", type=float, default=10.0, help="Request timeout in seconds")
    scan.add_argument("--delay", type=float, default=0.25, help="Delay between requests in seconds")
    scan.add_argument(
        "--canary",
        action="store_true",
        help="Send a harmless query parameter to check for simple reflection.",
    )

    return parser


def run_scan(args: argparse.Namespace) -> int:
    try:
        scope = build_scope_policy(args.scope)
    except ValueError as exc:
        print(f"Input error: {exc}")
        return 2

    if not scope.is_allowed_url(args.url):
        print("Input error: target URL is outside the configured --scope")
        return 2

    client = HttpClient(scope=scope, timeout=args.timeout, delay=args.delay)

    try:
        findings, stats = run_checks(client, args.url, enable_canary=args.canary)
    except HttpClientError as exc:
        print(f"Scan error: {exc}")
        return 1

    report = AuditReport(
        target=args.url,
        scope=scope.allowed_hosts,
        generated_at=datetime.now(timezone.utc).isoformat(),
        stats=stats,
        findings=findings,
    )

    print(f"Target: {report.target}")
    print(f"Scope: {', '.join(report.scope)}")
    print(f"Requested URLs: {report.stats.get('requested_urls', 0)}")
    print(f"Findings: {len(report.findings)}")

    severity_counts = report.stats.get("findings_by_severity", {})
    if isinstance(severity_counts, dict):
        for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            count = severity_counts.get(severity, 0)
            if count:
                print(f"- {severity}: {count}")

    for finding in report.findings[:10]:
        print(f"[{finding.severity}] {finding.title}: {finding.evidence}")

    if len(report.findings) > 10:
        print(f"... {len(report.findings) - 10} more findings")

    if args.json:
        output_path = write_json_report(report, args.json)
        print(f"JSON report written: {output_path}")

    if args.markdown:
        output_path = write_markdown_report(report, args.markdown)
        print(f"Markdown report written: {output_path}")

    return 0


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "scan":
        return run_scan(args)

    parser.print_help()
    return 0

