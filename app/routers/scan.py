"""FastAPI router — scan submission, status, results, and report download."""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone

from fastapi import APIRouter, BackgroundTasks, HTTPException
from fastapi.responses import HTMLResponse

from app.schemas.scan import (
    FindingSummary,
    ScanRequest,
    ScanResultsResponse,
    ScanStatusResponse,
    ScanSubmitted,
)
from core.reporter.report_generator import ReportGenerator
from core.validator.rule_validator import ValidationResult

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/scan", tags=["scan"])

# Module-level in-memory session store (injectable for tests)
_sessions: dict[str, "ScanSession"] = {}


@dataclass
class ScanSession:
    scan_id: str
    status: str = "pending"      # pending | running | completed | failed
    progress: float = 0.0
    message: str = "Queued"
    results: list[ValidationResult] = field(default_factory=list)
    report_html: str = ""
    started_at: str = ""
    finished_at: str = ""
    error: str = ""


# ── Background task ───────────────────────────────────────────────────────── #


async def _run_scan(session: ScanSession, request: ScanRequest) -> None:
    """Execute the full scan pipeline in the background."""
    from app.scan_runner import ScanRunner

    session.status = "running"
    session.message = "Parsing specification..."
    session.started_at = datetime.now(timezone.utc).isoformat()

    def _progress(p: float, msg: str) -> None:
        session.progress = p
        session.message = msg

    try:
        runner = ScanRunner()
        results = await runner.run(
            spec=request.spec,
            target_url=request.target_url,
            auth_token=request.auth_token,
            owasp_filter=request.owasp_filter or [],
            max_payloads_per_endpoint=request.max_payloads_per_endpoint,
            scan_id=session.scan_id,
            progress_cb=_progress,
        )
        session.finished_at = datetime.now(timezone.utc).isoformat()
        session.results = results

        gen = ReportGenerator(output_dir="./reports")
        report = gen.build(
            scan_id=session.scan_id,
            validation_results=results,
            target_url=request.target_url,
            started_at=session.started_at,
            finished_at=session.finished_at,
        )
        session.report_html = gen.render_html(report)
        session.status = "completed"
        session.progress = 1.0
        session.message = (
            f"Scan complete — {report.vulnerable_count} vulnerable finding(s)"
        )
    except Exception as exc:  # noqa: BLE001
        session.status = "failed"
        session.finished_at = datetime.now(timezone.utc).isoformat()
        session.error = str(exc)
        session.message = f"Scan failed: {exc}"
        logger.exception("Scan %s failed", session.scan_id)


# ── Endpoints ─────────────────────────────────────────────────────────────── #


@router.post("", response_model=ScanSubmitted, status_code=202)
async def submit_scan(
    request: ScanRequest, background_tasks: BackgroundTasks
) -> ScanSubmitted:
    """Submit a new scan; returns immediately with a scan_id."""
    import uuid
    scan_id = str(uuid.uuid4())
    session = ScanSession(scan_id=scan_id)
    _sessions[scan_id] = session
    background_tasks.add_task(_run_scan, session, request)
    return ScanSubmitted(scan_id=scan_id, message="Scan queued")


@router.get("/{scan_id}", response_model=ScanStatusResponse)
async def get_scan_status(scan_id: str) -> ScanStatusResponse:
    session = _sessions.get(scan_id)
    if not session:
        raise HTTPException(status_code=404, detail=f"Scan {scan_id!r} not found")
    return ScanStatusResponse(
        scan_id=session.scan_id,
        status=session.status,
        progress=session.progress,
        message=session.message,
    )


@router.get("/{scan_id}/results", response_model=ScanResultsResponse)
async def get_scan_results(scan_id: str) -> ScanResultsResponse:
    session = _sessions.get(scan_id)
    if not session:
        raise HTTPException(status_code=404, detail=f"Scan {scan_id!r} not found")
    if session.status not in ("completed", "failed"):
        raise HTTPException(status_code=409, detail="Scan not yet complete")

    gen = ReportGenerator()
    report = gen.build(
        scan_id=scan_id,
        validation_results=session.results,
        target_url="",
        started_at=session.started_at,
        finished_at=session.finished_at,
    )
    return ScanResultsResponse(
        scan_id=scan_id,
        status=session.status,
        total_requests=report.total_requests,
        vulnerable_count=report.vulnerable_count,
        findings=[
            FindingSummary(
                task_id=f.task_id,
                endpoint=f.endpoint,
                vuln_category=f.vuln_category,
                severity=f.severity,
                is_vulnerable=f.is_vulnerable,
                rule_ids=f.rule_ids,
                evidence=f.evidence,
                confirmed_by_slm=f.confirmed_by_slm,
            )
            for f in report.findings
        ],
    )


@router.get("/{scan_id}/report", response_class=HTMLResponse)
async def get_scan_report(scan_id: str) -> HTMLResponse:
    session = _sessions.get(scan_id)
    if not session:
        raise HTTPException(status_code=404, detail=f"Scan {scan_id!r} not found")
    if session.status not in ("completed", "failed"):
        raise HTTPException(status_code=409, detail="Scan not yet complete")
    return HTMLResponse(content=session.report_html or "<h1>Report not available</h1>")
