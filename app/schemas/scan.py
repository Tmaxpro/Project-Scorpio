"""Pydantic schemas for the ARIA scan API."""
from __future__ import annotations

from pydantic import BaseModel, Field


class ScanRequest(BaseModel):
    spec: str = Field(..., description="OpenAPI 3.x YAML or JSON content")
    target_url: str = Field(..., description="Base URL of the API under test")
    auth_token: str = Field(default="", description="Bearer token for authenticated testing")
    owasp_filter: list[str] = Field(default=[], description="OWASP categories to test; empty = all")
    max_payloads_per_endpoint: int = Field(default=20, ge=1, le=200)


class ScanSubmitted(BaseModel):
    scan_id: str
    message: str


class ScanStatusResponse(BaseModel):
    scan_id: str
    status: str      # pending | running | completed | failed
    progress: float
    message: str


class FindingSummary(BaseModel):
    task_id: str
    endpoint: str
    vuln_category: str
    severity: str
    is_vulnerable: bool
    rule_ids: list[str]
    evidence: str
    confirmed_by_slm: bool


class ScanResultsResponse(BaseModel):
    scan_id: str
    status: str
    total_requests: int
    vulnerable_count: int
    findings: list[FindingSummary]
