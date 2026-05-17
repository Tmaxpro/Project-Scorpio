"""Pydantic schemas for the ARIA scan API."""
from __future__ import annotations

import base64

from pydantic import BaseModel, Field, model_validator


class Credentials(BaseModel):
    """Auth credentials — shape varies by auth_type."""

    token: str = ""
    name: str = ""
    value: str = ""
    in_field: str = Field(default="header", alias="in")
    username: str = ""
    password: str = ""

    model_config = {"populate_by_name": True}


class ScanRequest(BaseModel):
    # Backend-native names
    spec: str = ""
    target_url: str = ""
    auth_token: str = ""
    owasp_filter: list[str] = Field(default_factory=list)
    max_payloads_per_endpoint: int = Field(default=20, ge=1, le=200)

    # Frontend aliases / extended auth fields
    openapi_yaml: str = ""
    base_url: str = ""
    owasp_categories: list[str] = Field(default_factory=list)
    auth_type: str = "none"           # bearer | apikey | api_key | basic | none
    credentials: Credentials | None = None
    context: str = ""

    @model_validator(mode="after")
    def _normalize(self) -> "ScanRequest":
        if not self.spec:
            self.spec = self.openapi_yaml
        if not self.target_url:
            self.target_url = self.base_url
        if not self.owasp_filter:
            self.owasp_filter = self.owasp_categories
        if not self.auth_token and self.credentials:
            if self.auth_type == "bearer":
                self.auth_token = self.credentials.token
            elif self.auth_type in ("apikey", "api_key"):
                self.auth_token = self.credentials.value
            elif self.auth_type == "basic":
                raw = f"{self.credentials.username}:{self.credentials.password}"
                self.auth_token = base64.b64encode(raw.encode()).decode()
        if not self.spec:
            raise ValueError("spec (or openapi_yaml) is required and must not be empty")
        if not self.target_url:
            raise ValueError("target_url (or base_url) is required and must not be empty")
        return self


class ScanSubmitted(BaseModel):
    scan_id: str
    message: str


class ScanStatusResponse(BaseModel):
    scan_id: str
    status: str
    progress: float
    message: str
    target: str = ""
    started_at: str = ""
    finished_at: str = ""
    findings_count: int = 0
    vulnerable_count: int = 0
    total_tasks: int = 0
    completed_tasks: int = 0


class EvidenceRequest(BaseModel):
    method: str = ""
    url: str = ""
    headers: dict[str, str] = Field(default_factory=dict)
    body: str | None = None


class EvidenceResponse(BaseModel):
    status_code: int = 0
    headers: dict[str, str] = Field(default_factory=dict)
    body_excerpt: str = ""
    elapsed_ms: float = 0.0


class EvidenceDetail(BaseModel):
    request: EvidenceRequest = Field(default_factory=EvidenceRequest)
    response: EvidenceResponse = Field(default_factory=EvidenceResponse)


class FindingSummary(BaseModel):
    task_id: str
    endpoint: str
    method: str = ""
    vuln_category: str
    owasp_ref: str = ""
    severity: str
    confidence: str = "medium"
    is_vulnerable: bool
    rule_ids: list[str]
    evidence: str
    evidence_detail: EvidenceDetail | None = None
    remediation: str = ""
    confirmed_by_slm: bool


class ScanResultsResponse(BaseModel):
    scan_id: str
    status: str
    total_requests: int
    vulnerable_count: int
    findings: list[FindingSummary]
