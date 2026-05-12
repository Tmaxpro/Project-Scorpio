"""Unit tests for Phase 7: ReportGenerator and FastAPI scan endpoints."""
from __future__ import annotations

import tempfile
from datetime import datetime, timezone
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from core.http_engine.client import ScanResult
from core.payload_factory.models import PayloadRequest
from core.reporter.report_generator import Finding, ReportGenerator, ScanReport
from core.validator.rule_validator import RuleCheckResult, ValidationResult

# ── Helpers ───────────────────────────────────────────────────────────────── #

_NOW = "2026-01-01T00:00:00+00:00"


def _req(method: str = "GET", path: str = "/api/items", strategy: str = "bola_exploit") -> PayloadRequest:
    return PayloadRequest(task_id="T-001", method=method, path=path, strategy=strategy, label="test")


def _scan_result(status: int = 200, body: str = "", request: PayloadRequest | None = None) -> ScanResult:
    return ScanResult(
        task_id="T-001",
        request=request or _req(),
        status_code=status,
        response_headers={},
        response_body=body,
        response_time_ms=42.0,
    )


def _vr_vulnerable() -> ValidationResult:
    check = RuleCheckResult("bola_object_access", True, "medium", "Object /api/items/2 returned 200", "API1")
    vr = ValidationResult(task_id="T-001", scan_result=_scan_result(), rule_checks=[check], is_vulnerable=True)
    return vr


def _vr_clean() -> ValidationResult:
    check = RuleCheckResult("bola_object_access", False, "medium", "", "API1")
    return ValidationResult(task_id="T-002", scan_result=_scan_result(404), rule_checks=[check])


def _make_report(findings_count: int = 1) -> ScanReport:
    findings = [
        Finding(
            task_id=f"T-00{i}",
            endpoint="GET /api/items/{id}",
            vuln_category="API1",
            severity="medium",
            is_vulnerable=True,
            rule_ids=["bola_object_access"],
            evidence="Object returned 200",
            confirmed_by_slm=False,
            slm_reasoning="",
        )
        for i in range(findings_count)
    ]
    return ScanReport(
        scan_id="scan-123",
        target_url="http://localhost:8000",
        started_at=_NOW,
        finished_at=_NOW,
        total_requests=50,
        total_tasks=5,
        findings=findings,
    )


# ── TestReportGenerator ───────────────────────────────────────────────────── #


class TestReportGenerator:
    def setup_method(self):
        self.gen = ReportGenerator()

    def test_build_includes_vulnerable_findings(self):
        report = self.gen.build("s1", [_vr_vulnerable()], "http://t", _NOW, _NOW)
        assert len(report.findings) == 1
        assert report.findings[0].is_vulnerable

    def test_build_excludes_clean_results(self):
        report = self.gen.build("s1", [_vr_clean()], "http://t", _NOW, _NOW)
        assert len(report.findings) == 0

    def test_build_counts_total_requests(self):
        report = self.gen.build("s1", [_vr_vulnerable(), _vr_clean()], "http://t", _NOW, _NOW)
        assert report.total_requests == 2

    def test_build_vulnerable_count_property(self):
        report = self.gen.build("s1", [_vr_vulnerable(), _vr_clean()], "http://t", _NOW, _NOW)
        assert report.vulnerable_count == 1

    def test_build_endpoint_format(self):
        report = self.gen.build("s1", [_vr_vulnerable()], "http://t", _NOW, _NOW)
        assert report.findings[0].endpoint == "GET /api/items"

    # Markdown rendering
    def test_markdown_contains_scan_id(self):
        md = self.gen.render_markdown(_make_report())
        assert "scan-123" in md

    def test_markdown_contains_target_url(self):
        md = self.gen.render_markdown(_make_report())
        assert "http://localhost:8000" in md

    def test_markdown_lists_findings_in_table(self):
        md = self.gen.render_markdown(_make_report(2))
        assert "bola_object_access" in md
        assert "API1" in md

    def test_markdown_zero_findings_message(self):
        report = _make_report(0)
        md = self.gen.render_markdown(report)
        assert "No vulnerabilities" in md

    def test_markdown_vulnerable_count_shown(self):
        md = self.gen.render_markdown(_make_report(3))
        assert "3" in md

    # HTML rendering
    def test_html_contains_doctype(self):
        html = self.gen.render_html(_make_report())
        assert html.startswith("<!DOCTYPE html>")

    def test_html_contains_scan_id(self):
        html = self.gen.render_html(_make_report())
        assert "scan-123" in html

    def test_html_contains_finding_evidence(self):
        html = self.gen.render_html(_make_report(1))
        assert "Object returned 200" in html

    def test_html_zero_findings_message(self):
        html = self.gen.render_html(_make_report(0))
        assert "No vulnerabilities" in html

    def test_html_escapes_xss_in_scan_id(self):
        report = _make_report(0)
        report.scan_id = '<script>alert(1)</script>'
        html = self.gen.render_html(report)
        assert "<script>" not in html
        assert "&lt;script&gt;" in html

    # Save
    def test_save_creates_markdown_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            gen = ReportGenerator(output_dir=tmp)
            paths = gen.save(_make_report())
            assert paths["markdown"].exists()
            assert paths["markdown"].suffix == ".md"

    def test_save_creates_html_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            gen = ReportGenerator(output_dir=tmp)
            paths = gen.save(_make_report())
            assert paths["html"].exists()
            assert paths["html"].suffix == ".html"

    def test_save_files_named_by_scan_id(self):
        with tempfile.TemporaryDirectory() as tmp:
            gen = ReportGenerator(output_dir=tmp)
            paths = gen.save(_make_report())
            assert "scan-123" in paths["markdown"].name
            assert "scan-123" in paths["html"].name

    def test_save_creates_output_dir_if_missing(self):
        with tempfile.TemporaryDirectory() as tmp:
            new_dir = Path(tmp) / "subdir" / "reports"
            gen = ReportGenerator(output_dir=str(new_dir))
            gen.save(_make_report())
            assert new_dir.exists()


# ── TestFastAPIEndpoints ──────────────────────────────────────────────────── #


@pytest.fixture
def client():
    from app.main import app
    from app.routers.scan import _sessions
    _sessions.clear()
    return TestClient(app, raise_server_exceptions=False)


@pytest.fixture
def completed_session():
    """Pre-populate a completed scan session for read-only endpoint tests."""
    from app.routers.scan import ScanSession, _sessions
    from core.reporter.report_generator import ReportGenerator

    scan_id = "test-scan-001"
    session = ScanSession(
        scan_id=scan_id,
        status="completed",
        progress=1.0,
        message="Scan complete — 1 vulnerable finding(s)",
        results=[_vr_vulnerable()],
        started_at=_NOW,
        finished_at=_NOW,
    )
    gen = ReportGenerator()
    report = gen.build(scan_id, [_vr_vulnerable()], "http://target", _NOW, _NOW)
    session.report_html = gen.render_html(report)
    _sessions[scan_id] = session
    return scan_id


class TestHealthEndpoint:
    def test_health_returns_ok(self, client):
        res = client.get("/health")
        assert res.status_code == 200
        assert res.json()["status"] == "ok"


class TestSubmitScan:
    def test_submit_returns_202_with_scan_id(self, client):
        res = client.post("/api/scan", json={
            "spec": "openapi: '3.0.0'\ninfo:\n  title: T\n  version: '1'\npaths: {}",
            "target_url": "http://localhost:9999",
        })
        assert res.status_code == 202
        data = res.json()
        assert "scan_id" in data
        assert len(data["scan_id"]) > 0

    def test_submit_missing_spec_returns_422(self, client):
        res = client.post("/api/scan", json={"target_url": "http://localhost:9999"})
        assert res.status_code == 422

    def test_submit_missing_target_returns_422(self, client):
        res = client.post("/api/scan", json={"spec": "openapi: '3.0.0'"})
        assert res.status_code == 422


class TestScanStatus:
    def test_status_of_existing_scan(self, client, completed_session):
        res = client.get(f"/api/scan/{completed_session}")
        assert res.status_code == 200
        data = res.json()
        assert data["scan_id"] == completed_session
        assert data["status"] == "completed"
        assert data["progress"] == 1.0

    def test_status_not_found_returns_404(self, client):
        res = client.get("/api/scan/nonexistent-scan-id")
        assert res.status_code == 404

    def test_status_includes_message(self, client, completed_session):
        res = client.get(f"/api/scan/{completed_session}")
        assert "message" in res.json()


class TestScanResults:
    def test_results_of_completed_scan(self, client, completed_session):
        res = client.get(f"/api/scan/{completed_session}/results")
        assert res.status_code == 200
        data = res.json()
        assert data["scan_id"] == completed_session
        assert data["status"] == "completed"
        assert isinstance(data["findings"], list)
        assert data["total_requests"] >= 0

    def test_results_not_found_returns_404(self, client):
        res = client.get("/api/scan/does-not-exist/results")
        assert res.status_code == 404

    def test_results_pending_scan_returns_409(self, client):
        from app.routers.scan import ScanSession, _sessions
        _sessions["pending-scan"] = ScanSession(scan_id="pending-scan", status="pending")
        res = client.get("/api/scan/pending-scan/results")
        assert res.status_code == 409

    def test_results_contain_findings_fields(self, client, completed_session):
        res = client.get(f"/api/scan/{completed_session}/results")
        findings = res.json()["findings"]
        if findings:
            f = findings[0]
            for key in ("task_id", "endpoint", "vuln_category", "severity", "rule_ids"):
                assert key in f


class TestScanReport:
    def test_report_returns_html(self, client, completed_session):
        res = client.get(f"/api/scan/{completed_session}/report")
        assert res.status_code == 200
        assert "text/html" in res.headers["content-type"]
        assert "<!DOCTYPE html>" in res.text

    def test_report_contains_scan_id(self, client, completed_session):
        res = client.get(f"/api/scan/{completed_session}/report")
        assert completed_session in res.text

    def test_report_not_found_returns_404(self, client):
        res = client.get("/api/scan/no-such-scan/report")
        assert res.status_code == 404

    def test_report_pending_returns_409(self, client):
        from app.routers.scan import ScanSession, _sessions
        _sessions["pending-r"] = ScanSession(scan_id="pending-r", status="running")
        res = client.get("/api/scan/pending-r/report")
        assert res.status_code == 409
