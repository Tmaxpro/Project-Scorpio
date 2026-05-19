"""FastAPI router — scan submission, status, results, report, SSE stream."""
from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Any

import asyncio

from fastapi import APIRouter, BackgroundTasks, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, PlainTextResponse, StreamingResponse

from app.schemas.scan import (
    FindingSummary,
    ScanRequest,
    ScanResultsResponse,
    ScanSession,
    ScanStatusResponse,
    ScanSubmitted,
)
from core.reporter.report_generator import ReportGenerator
from app.database import get_all_scans, get_scan, save_scan

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/scan", tags=["scan"])

_OWASP_REFS: dict[str, str] = {
    "API1":  "API1:2023 — Broken Object Level Authorization",
    "API2":  "API2:2023 — Broken Authentication",
    "API3":  "API3:2023 — Broken Object Property Level Authorization",
    "API4":  "API4:2023 — Unrestricted Resource Consumption",
    "API5":  "API5:2023 — Broken Function Level Authorization",
    "API6":  "API6:2023 — Unrestricted Access to Sensitive Business Flows",
    "API7":  "API7:2023 — Server Side Request Forgery",
    "API8":  "API8:2023 — Security Misconfiguration",
    "API9":  "API9:2023 — Improper Inventory Management",
    "API10": "API10:2023 — Unsafe Consumption of APIs",
}

_REMEDIATIONS: dict[str, str] = {
    "API1": "Validate object ownership for every request. Use indirect object references and enforce authorization at the data layer.",
    "API2": "Implement strong authentication (MFA, short-lived tokens). Rotate secrets. Enforce brute-force protection.",
    "API3": "Apply property-level authorization. Never expose or accept properties the caller is not allowed to read/write.",
    "API4": "Enforce rate limits, payload size caps, and resource quotas per user/key. Return 429 on excess.",
    "API5": "Check function-level permissions explicitly; do not rely on UI hiding. Deny by default.",
    "API6": "Identify sensitive business flows and add per-flow rate limits and bot detection.",
    "API7": "Validate and whitelist URLs/IPs before making outbound requests. Block internal IP ranges.",
    "API8": "Harden HTTP headers. Disable debug endpoints. Remove stack traces from error responses.",
    "API9": "Maintain an up-to-date API inventory. Retire unused endpoints. Document all versions.",
    "API10": "Validate and sanitise all data received from third-party APIs.",
}

# Module-level in-memory session store (injectable for tests)
_sessions: dict[str, "ScanSession"] = {}



async def _push_event(session: ScanSession, event_type: str, data: dict[str, Any]) -> None:
    # Inject server-side timestamp so the frontend shows accurate log times on replay
    session._events.append({"type": event_type, "data": {**data, "ts": datetime.now(timezone.utc).isoformat()}})
    # Simple persistence strategy: save on every event (SQLite is fast enough for our use-case)
    save_scan(session)


# ── Background task ─────────────────────────────────────────────────────────


async def _run_scan(session: ScanSession, request: ScanRequest) -> None:
    from app.scan_runner import ScanRunner

    session.status = "running"
    session.message = "Parsing specification..."
    session.started_at = datetime.now(timezone.utc).isoformat()
    session.target_url = request.target_url

    def _progress(p: float, msg: str) -> None:
        session.progress = p
        session.message = msg

    async def _event_cb(event_type: str, data: dict[str, Any]) -> None:
        if event_type == "scan_info":
            session.total_tasks = data.get("total_tasks", 0)
        elif event_type == "task_completed":
            session.completed_tasks += 1
        await _push_event(session, event_type, data)

    # Determine auth config params
    auth_header_name = "Authorization"
    if request.auth_type in ("apikey", "api_key") and request.credentials:
        auth_header_name = request.credentials.name or "X-Api-Key"

    try:
        u2 = request.user2_credentials
        runner = ScanRunner()
        results = await runner.run(
            spec=request.spec,
            target_url=request.target_url,
            auth_token=request.auth_token,
            auth_type=request.auth_type,
            auth_header_name=auth_header_name,
            login_username=request.credentials.username if request.credentials else "",
            login_password=request.credentials.password if request.credentials else "",
            user2_token=u2.token if u2 else "",
            user2_login_username=u2.username if u2 else "",
            user2_login_password=u2.password if u2 else "",
            owasp_filter=request.owasp_filter or [],
            max_payloads_per_endpoint=request.max_payloads_per_endpoint,
            context=request.context,
            scan_id=session.scan_id,
            scan_mode=request.scan_mode,
            progress_cb=_progress,
            event_cb=_event_cb,
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
        if report.vulnerable_count > 0:
            from core.llm.client import LLMClient
            llm_report = LLMClient(
                config_path="config.yaml",
                scan_id=session.scan_id,
                scan_mode=request.scan_mode,
            )
            llm_report.set_event_cb(_event_cb)
            await gen.enrich_with_llm_remediation(report, llm_report)
        session.report_html = gen.render_html(report)
        session.report_md = gen.render_markdown(report)
        session.status = "completed"
        session.progress = 1.0
        session.message = f"Scan complete — {report.vulnerable_count} vulnerable finding(s)"
        await _push_event(session, "scan_completed", {
            "vulnerable_count": report.vulnerable_count,
            "total_requests": report.total_requests,
        })
    except Exception as exc:  # noqa: BLE001
        session.status = "failed"
        session.finished_at = datetime.now(timezone.utc).isoformat()
        session.error = str(exc)
        session.message = f"Scan failed: {exc}"
        logger.exception("Scan %s failed", session.scan_id)
        await _push_event(session, "error", {"message": str(exc)})
    finally:
        session._done = True


# ── Endpoints ────────────────────────────────────────────────────────────────


@router.post("", response_model=ScanSubmitted, status_code=202)
async def submit_scan(
    request: ScanRequest, background_tasks: BackgroundTasks
) -> ScanSubmitted:
    import uuid
    scan_id = str(uuid.uuid4())
    session = ScanSession(
        scan_id=scan_id,
        target_url=request.target_url,
        scan_name=request.scan_name or request.target_url,
        scan_mode=request.scan_mode
    )
    _sessions[scan_id] = session
    save_scan(session)
    background_tasks.add_task(_run_scan, session, request)
    return ScanSubmitted(scan_id=scan_id, message="Scan queued")


@router.get("", response_model=list[ScanStatusResponse])
async def list_scans() -> list[ScanStatusResponse]:
    """Return all scan sessions (for history and reports pages)."""
    # Combine active memory sessions with DB sessions, or just rely on DB
    # Since we save on every event, DB is fully up to date. 
    # But active sessions in memory might have slight delay in DB. We will just use DB to be consistent.
    db_scans = get_all_scans()
    # Update active ones from memory if present
    for i, s in enumerate(db_scans):
        if s.scan_id in _sessions:
            db_scans[i] = _sessions[s.scan_id]
    return [_session_to_status(s) for s in db_scans]


@router.get("/{scan_id}", response_model=ScanStatusResponse)
async def get_scan_status(scan_id: str) -> ScanStatusResponse:
    session = _sessions.get(scan_id) or get_scan(scan_id)
    if not session:
        raise HTTPException(status_code=404, detail=f"Scan {scan_id!r} not found")
    return _session_to_status(session)


@router.get("/{scan_id}/events")
async def scan_events(scan_id: str, request: Request) -> StreamingResponse:
    """Server-Sent Events stream for real-time scan progress."""
    session = _sessions.get(scan_id) or get_scan(scan_id)
    if not session:
        raise HTTPException(status_code=404, detail=f"Scan {scan_id!r} not found")

    # Resume from the last event the client acknowledged (SSE Last-Event-ID protocol).
    # On reconnect the browser sends this header automatically, so no events are replayed.
    last_id = request.headers.get("last-event-id", "")
    from_cursor = int(last_id) + 1 if last_id.isdigit() else 0

    async def generate():
        import time as _time
        cursor = from_cursor
        last_ping = _time.monotonic()
        PING_INTERVAL = 5  # seconds — keeps connection alive; short because LLM calls starve the event loop

        while True:
            now = _time.monotonic()
            # Drain any buffered events, tagging each with its sequence ID
            while cursor < len(session._events):
                yield f"id: {cursor}\ndata: {json.dumps(session._events[cursor])}\n\n"
                cursor += 1
                last_ping = now
            # Done?
            if session._done and cursor >= len(session._events):
                return
            # Heartbeat — no id: line so it doesn't advance Last-Event-ID
            if now - last_ping >= PING_INTERVAL:
                yield f"data: {json.dumps({'type': 'heartbeat', 'data': {}})}\n\n"
                last_ping = now
            await asyncio.sleep(0.5)

    return StreamingResponse(
        generate(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        },
    )


@router.get("/{scan_id}/results", response_model=ScanResultsResponse)
async def get_scan_results(scan_id: str) -> ScanResultsResponse:
    session = _sessions.get(scan_id) or get_scan(scan_id)
    if not session:
        raise HTTPException(status_code=404, detail=f"Scan {scan_id!r} not found")
    if session.status not in ("completed", "failed"):
        raise HTTPException(status_code=409, detail="Scan not yet complete")

    gen = ReportGenerator()
    report = gen.build(
        scan_id=scan_id,
        validation_results=session.results,
        target_url=session.target_url,
        started_at=session.started_at,
        finished_at=session.finished_at,
    )

    import yaml
    from pathlib import Path
    model_usage_log = []
    log_dir = Path("./benchmarks/runs/")
    try:
        with open("config.yaml") as fh:
            cfg = yaml.safe_load(fh)
        log_dir = Path(cfg.get("benchmarking", {}).get("log_path", "./benchmarks/runs/"))
    except Exception:
        pass
    log_file = log_dir / f"{scan_id}.jsonl"
    if log_file.exists():
        try:
            with log_file.open("r") as fh:
                for line in fh:
                    if line.strip():
                        entry = json.loads(line)
                        reason = entry.get("reason", "")
                        fallback_triggered = not entry.get("success", True) and "json" in reason.lower()
                        model_usage_log.append({
                            "timestamp": entry.get("timestamp", ""),
                            "task_id": entry.get("task_id", ""),
                            "model_used": entry.get("model_used", ""),
                            "tokens_in": entry.get("tokens_in", 0),
                            "tokens_out": entry.get("tokens_out", 0),
                            "latency_ms": entry.get("latency_ms", 0.0),
                            "success": entry.get("success", True),
                            "fallback_triggered": fallback_triggered
                        })
        except Exception as e:
            logger.warning(f"Failed to read model usage logs for scan {scan_id}: {e}")

    return ScanResultsResponse(
        scan_id=scan_id,
        status=session.status,
        total_requests=report.total_requests,
        vulnerable_count=report.vulnerable_count,
        findings=[_finding_to_summary(f) for f in report.findings],
        model_usage_log=model_usage_log,
    )


@router.get("/{scan_id}/report")
async def get_scan_report(
    scan_id: str,
    format: str = Query(default="html", pattern="^(html|markdown)$"),
):
    session = _sessions.get(scan_id) or get_scan(scan_id)
    if not session:
        raise HTTPException(status_code=404, detail=f"Scan {scan_id!r} not found")
    if session.status not in ("completed", "failed"):
        raise HTTPException(status_code=409, detail="Scan not yet complete")
    if format == "markdown":
        return PlainTextResponse(
            content=session.report_md or "# Report not available",
            media_type="text/markdown",
        )
    return HTMLResponse(content=session.report_html or "<h1>Report not available</h1>")


# ── Helpers ──────────────────────────────────────────────────────────────────


def _session_to_status(s: ScanSession) -> ScanStatusResponse:
    gen = ReportGenerator()
    vulnerable_count = 0
    findings_count = 0
    if s.status in ("completed", "failed") and s.results:
        report = gen.build(
            scan_id=s.scan_id,
            validation_results=s.results,
            target_url=s.target_url,
            started_at=s.started_at,
            finished_at=s.finished_at,
        )
        vulnerable_count = report.vulnerable_count
        findings_count = len(report.findings)
    return ScanStatusResponse(
        scan_id=s.scan_id,
        status=s.status,
        progress=s.progress,
        message=s.message,
        target=s.target_url,
        scan_name=s.scan_name,
        started_at=s.started_at,
        finished_at=s.finished_at,
        findings_count=findings_count,
        vulnerable_count=vulnerable_count,
        total_tasks=s.total_tasks,
        completed_tasks=s.completed_tasks,
        scan_mode=s.scan_mode,
    )


def _finding_to_summary(f: object) -> FindingSummary:
    # f is a core.reporter.report_generator.Finding dataclass
    parts = f.endpoint.split(" ", 1)
    method = parts[0] if len(parts) == 2 else ""
    endpoint = parts[1] if len(parts) == 2 else f.endpoint
    rule_count = len(f.rule_ids)
    confidence = "high" if f.confirmed_by_slm else ("medium" if rule_count > 1 else "low")
    category = f.vuln_category
    return FindingSummary(
        task_id=f.task_id,
        endpoint=endpoint,
        method=method,
        vuln_category=category,
        owasp_ref=_OWASP_REFS.get(category, category),
        severity=f.severity,
        confidence=confidence,
        is_vulnerable=f.is_vulnerable,
        rule_ids=f.rule_ids,
        evidence=f.evidence,
        remediation=_REMEDIATIONS.get(category, ""),
        confirmed_by_slm=f.confirmed_by_slm,
    )
