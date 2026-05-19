"""Scan report generation — renders ValidationResults to Markdown and HTML."""
from __future__ import annotations

import html as _html
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING

from core.validator.rule_validator import ValidationResult

if TYPE_CHECKING:
    from core.llm.client import LLMClient

logger = logging.getLogger(__name__)

_CSS = """
<style>
* { box-sizing: border-box; margin: 0; padding: 0; }
body { font-family: 'Segoe UI', monospace; background: #0d1117; color: #c9d1d9; padding: 2rem; }
h1 { color: #58a6ff; margin-bottom: 1.5rem; }
h2 { color: #8b949e; margin: 1.5rem 0 0.75rem; }
.meta { background: #161b22; border: 1px solid #30363d; border-radius: 6px;
        padding: 1rem; margin-bottom: 1.5rem; }
.meta p { margin: 0.3rem 0; }
.high   { color: #f85149; font-weight: bold; }
.medium { color: #e3b341; font-weight: bold; }
.low    { color: #3fb950; }
.info   { color: #8b949e; }
table { width: 100%; border-collapse: collapse; margin-top: 0.5rem; }
th { background: #21262d; padding: 10px; text-align: left; border: 1px solid #30363d; }
td { padding: 10px; border: 1px solid #30363d; vertical-align: top; font-size: 0.85rem; }
tr:hover td { background: #161b22; }
.ok { color: #3fb950; margin-top: 1rem; font-size: 1.1rem; }
</style>
"""


@dataclass
class Finding:
    """A flattened, renderable representation of all triggered checks for one result."""

    task_id: str
    endpoint: str         # "METHOD /path"
    vuln_category: str
    severity: str
    is_vulnerable: bool
    rule_ids: list[str]
    evidence: str
    confirmed_by_slm: bool
    slm_reasoning: str
    remediation: str = ""
    references: list[str] = field(default_factory=list)


@dataclass
class ScanReport:
    scan_id: str
    target_url: str
    started_at: str
    finished_at: str
    total_requests: int
    total_tasks: int
    findings: list[Finding] = field(default_factory=list)

    @property
    def vulnerable_count(self) -> int:
        return sum(1 for f in self.findings if f.is_vulnerable)


class ReportGenerator:
    """Builds ScanReport objects and renders them to Markdown and HTML."""

    def __init__(self, output_dir: str = "./reports") -> None:
        self._output_dir = Path(output_dir)

    # ── Build ─────────────────────────────────────────────────────────────── #

    def build(
        self,
        scan_id: str,
        validation_results: list[ValidationResult],
        target_url: str,
        started_at: str,
        finished_at: str,
    ) -> ScanReport:
        """Collapse ValidationResults into a ScanReport."""
        findings: list[Finding] = []
        for vr in validation_results:
            triggered = vr.triggered_checks()
            if not triggered:
                continue
            findings.append(Finding(
                task_id=vr.task_id,
                endpoint=f"{vr.scan_result.request.method} {vr.scan_result.request.path}",
                vuln_category=triggered[0].owasp_category,
                severity=vr.highest_severity(),
                is_vulnerable=vr.is_vulnerable,
                rule_ids=[c.rule_id for c in triggered],
                evidence="; ".join(c.evidence for c in triggered if c.evidence),
                confirmed_by_slm=vr.confirmed_by_slm,
                slm_reasoning=vr.slm_reasoning,
            ))
        # Filter known false positives then deduplicate before finalising
        from core.validator.false_positive_filter import filter_false_positives
        from core.utils.deduplication import deduplicate_findings
        findings, _ = filter_false_positives(findings)
        findings = deduplicate_findings(findings)

        return ScanReport(
            scan_id=scan_id,
            target_url=target_url,
            started_at=started_at,
            finished_at=finished_at,
            total_requests=len(validation_results),
            total_tasks=len({vr.task_id for vr in validation_results}),
            findings=findings,
        )

    # ── LLM remediation enrichment ────────────────────────────────────────── #

    async def enrich_with_llm_remediation(
        self,
        report: ScanReport,
        llm: LLMClient,
    ) -> None:
        """Call the LLM once per unique (vuln_category, endpoint) pair to generate
        actionable remediation guidance, then write it back into each Finding.

        Skips findings that are not marked vulnerable. Errors are logged and the
        finding keeps its empty remediation string rather than raising.
        """
        from core.llm.prompts import REMEDIATION_PROMPT
        from core.coordinator.task_builder import OWASP_REFS

        seen: dict[tuple[str, str], tuple[str, list[str]]] = {}

        for finding in report.findings:
            if not finding.is_vulnerable:
                continue

            key = (finding.vuln_category, finding.endpoint)
            if key in seen:
                finding.remediation, finding.references = seen[key]
                continue

            parts = finding.endpoint.split(" ", 1)
            method = parts[0] if len(parts) == 2 else "GET"
            path = parts[1] if len(parts) == 2 else finding.endpoint

            prompt = REMEDIATION_PROMPT.format(
                vuln_category=finding.vuln_category,
                owasp_ref=OWASP_REFS.get(finding.vuln_category, finding.vuln_category),
                method=method,
                endpoint=path,
                evidence_summary=finding.evidence[:400] or "(no evidence details)",
            )
            response = await llm.instruct(prompt, task_id=finding.task_id)

            if "error" in response:
                logger.warning(
                    "Remediation LLM call failed for %s %s: %s",
                    finding.vuln_category, finding.endpoint, response["error"],
                )
                seen[key] = ("", [])
            else:
                remediation = str(response.get("remediation", ""))
                references = response.get("references", [])
                if not isinstance(references, list):
                    references = []
                finding.remediation = remediation
                finding.references = [str(r) for r in references]
                seen[key] = (finding.remediation, finding.references)

    # ── Render ────────────────────────────────────────────────────────────── #

    def render_markdown(self, report: ScanReport) -> str:
        lines = [
            "# ARIA Scan Report",
            "",
            f"**Scan ID:** `{report.scan_id}`",
            f"**Target:** {report.target_url}",
            f"**Started:** {report.started_at}",
            f"**Finished:** {report.finished_at}",
            f"**Total Requests:** {report.total_requests}",
            f"**Vulnerable Findings:** {report.vulnerable_count}",
            "",
            "## Findings",
            "",
        ]
        if not report.findings:
            lines.append("✓ No vulnerabilities detected.")
        else:
            lines += [
                "| Endpoint | Category | Severity | Rules | Evidence |",
                "|----------|----------|----------|-------|----------|",
            ]
            for f in report.findings:
                evidence = f.evidence[:80].replace("|", "\\|")
                lines.append(
                    f"| {f.endpoint} | {f.vuln_category} | {f.severity} "
                    f"| {', '.join(f.rule_ids)} | {evidence} |"
                )
            lines.append("")
            for f in report.findings:
                if f.is_vulnerable:
                    entry = [
                        f"### {f.vuln_category} — {f.endpoint}",
                        "",
                        f"- **Severity:** {f.severity}",
                        f"- **Rules:** {', '.join(f.rule_ids)}",
                        f"- **Evidence:** {f.evidence}",
                    ]
                    if f.remediation:
                        entry.append(f"- **Remediation:** {f.remediation}")
                    if f.references:
                        entry.append(f"- **References:** {', '.join(f.references)}")
                    entry.append("")
                    lines += entry
        return "\n".join(lines)

    def render_html(self, report: ScanReport) -> str:
        e = _html.escape
        if not report.findings:
            findings_html = '<p class="ok">✓ No vulnerabilities detected.</p>'
        else:
            rows = "".join(
                f"<tr><td>{e(f.endpoint)}</td><td>{e(f.vuln_category)}</td>"
                f'<td class="{e(f.severity)}">{e(f.severity.upper())}</td>'
                f"<td>{e(', '.join(f.rule_ids))}</td>"
                f"<td>{e(f.evidence[:120])}</td>"
                f"<td>{e(f.remediation[:200]) if f.remediation else '—'}</td></tr>"
                for f in report.findings
            )
            findings_html = (
                "<table><tr><th>Endpoint</th><th>Category</th>"
                "<th>Severity</th><th>Rules</th><th>Evidence</th><th>Remediation</th></tr>"
                + rows + "</table>"
            )
        return (
            "<!DOCTYPE html><html><head>"
            f'<meta charset="UTF-8"><title>ARIA Report — {e(report.scan_id)}</title>'
            + _CSS
            + "</head><body>"
            + "<h1>ARIA Scan Report</h1>"
            + '<div class="meta">'
            + f"<p><b>Scan ID:</b> {e(report.scan_id)}</p>"
            + f"<p><b>Target:</b> {e(report.target_url)}</p>"
            + f"<p><b>Started:</b> {e(report.started_at)}</p>"
            + f"<p><b>Finished:</b> {e(report.finished_at)}</p>"
            + f"<p><b>Total Requests:</b> {report.total_requests}</p>"
            + f"<p><b>Vulnerable Findings:</b> {report.vulnerable_count}</p>"
            + "</div>"
            + "<h2>Findings</h2>"
            + findings_html
            + "</body></html>"
        )

    # ── Save ──────────────────────────────────────────────────────────────── #

    def save(self, report: ScanReport) -> dict[str, Path]:
        """Write both formats to output_dir; return {format: path}."""
        self._output_dir.mkdir(parents=True, exist_ok=True)
        paths: dict[str, Path] = {}
        md_path = self._output_dir / f"{report.scan_id}.md"
        md_path.write_text(self.render_markdown(report), encoding="utf-8")
        paths["markdown"] = md_path
        html_path = self._output_dir / f"{report.scan_id}.html"
        html_path.write_text(self.render_html(report), encoding="utf-8")
        paths["html"] = html_path
        return paths
