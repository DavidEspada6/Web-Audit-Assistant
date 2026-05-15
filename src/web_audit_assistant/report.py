from __future__ import annotations

import json
from pathlib import Path

from .models import AuditReport, Finding


def write_json_report(report: AuditReport, output_path: str | Path) -> Path:
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report.to_dict(), indent=2), encoding="utf-8")
    return path


def write_markdown_report(report: AuditReport, output_path: str | Path) -> Path:
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(render_markdown_report(report), encoding="utf-8")
    return path


def render_markdown_report(report: AuditReport) -> str:
    lines = [
        "# Web Audit Report",
        "",
        f"- Target: `{report.target}`",
        f"- Scope: `{', '.join(report.scope)}`",
        f"- Generated at: `{report.generated_at}`",
        f"- Findings: `{len(report.findings)}`",
        f"- Requested URLs: `{report.stats.get('requested_urls', 0)}`",
        "",
        "## Severity Summary",
        "",
        "| Severity | Count |",
        "| --- | ---: |",
    ]

    severity_counts = report.stats.get("findings_by_severity", {})
    if isinstance(severity_counts, dict):
        for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            lines.append(f"| {severity} | {severity_counts.get(severity, 0)} |")

    lines.extend(["", "## Findings", ""])

    if not report.findings:
        lines.append("No findings were identified by the current checks.")
        lines.append("")
        return "\n".join(lines)

    for finding in report.findings:
        lines.extend(render_finding(finding))

    return "\n".join(lines)


def render_finding(finding: Finding) -> list[str]:
    return [
        f"### [{finding.severity}] {finding.title}",
        "",
        f"- Rule: `{finding.rule_id}`",
        f"- Category: `{finding.category}`",
        f"- URL: `{finding.url}`",
        f"- Description: {finding.description}",
        f"- Evidence: `{finding.evidence}`",
        f"- Recommendation: {finding.recommendation}",
        "",
    ]

