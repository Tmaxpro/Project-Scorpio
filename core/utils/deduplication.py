"""Finding deduplication — keeps the richest evidence per unique (endpoint, category, rule)."""
from __future__ import annotations

from core.reporter.report_generator import Finding


def _dedup_key(finding: Finding) -> tuple:
    return (
        finding.endpoint.strip().lower(),
        finding.vuln_category,
        finding.rule_ids[0] if finding.rule_ids else "",
    )


def deduplicate_findings(findings: list[Finding]) -> list[Finding]:
    """Keep one Finding per (endpoint, vuln_category, primary_rule); prefer richest evidence."""
    seen: dict[tuple, Finding] = {}
    for f in findings:
        key = _dedup_key(f)
        if key not in seen or len(f.evidence) > len(seen[key].evidence):
            seen[key] = f
    return list(seen.values())
