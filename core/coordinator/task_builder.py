"""Helpers for building Task objects — from LLM output or deterministic rules."""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from core.parser.enricher import EnrichedEndpoint
from core.rag.nuclei_index import OWASP_TAG_MAP

OWASP_REFS: dict[str, str] = {
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

_DEFAULT_STRATEGIES: dict[str, str] = {
    "API1":  "horizontal ID enumeration and cross-user object access test",
    "API2":  "JWT manipulation and authentication bypass",
    "API3":  "sensitive field exposure detection in API responses",
    "API4":  "rate-limit absence test with 50+ rapid identical requests",
    "API5":  "admin endpoint access as regular authenticated user",
    "API6":  "mass assignment via privileged field injection in request body",
    "API7":  "SSRF via user-controlled URL parameter",
    "API8":  "injection attacks: SQLi, NoSQLi, SSTI, XSS",
    "API9":  "API version enumeration and documentation endpoint discovery",
    "API10": "third-party API response data injection",
}

_VALID_METHODS = frozenset({"GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD", "TRACE"})
_CAT_RE = re.compile(r"^API\d+$")


@dataclass
class Task:
    """A single pentest task assigned to an attack agent."""

    task_id: str
    vuln_category: str        # e.g. "API1"
    owasp_ref: str            # e.g. "API1:2023 — BOLA"
    target_endpoint: str      # path string, e.g. "/api/v1/users/{id}"
    method: str               # uppercase HTTP method
    strategy: str             # brief attack approach description
    rag_context_tags: list[str]
    priority: int             # 1=high, 2=medium, 3=low


class TaskBuilder:
    """Static factory methods for Task creation."""

    @staticmethod
    def build_spec_summary(endpoints: list[EnrichedEndpoint]) -> str:
        """Produce a concise text table of all endpoints for the coordinator prompt."""
        lines = []
        for ep in endpoints:
            sec = ", ".join(ep.security) if ep.security else "none"
            hints = ", ".join(ep.risk_hints[:3]) if ep.risk_hints else "none"
            candidates = ", ".join(ep.owasp_candidates) if ep.owasp_candidates else "none"
            body = "yes" if ep.body_schema else "no"
            lines.append(
                f"[{ep.method}] {ep.path} | auth: {sec} | body: {body} "
                f"| hints: {hints} | owasp: {candidates}"
            )
        return "\n".join(lines) if lines else "No endpoints available."

    @staticmethod
    def from_llm_dict(data: Any, counter: int) -> Task | None:
        """Parse and validate a single task dict from LLM output.

        Returns None when required fields are missing or values are invalid so
        the caller can skip bad items without crashing.
        """
        if not isinstance(data, dict):
            return None

        required = {"vuln_category", "target_endpoint", "method", "strategy"}
        if not required.issubset(data.keys()):
            return None

        cat = str(data.get("vuln_category", "")).strip()
        if not _CAT_RE.match(cat):
            return None

        method = str(data.get("method", "")).upper().strip()
        if method not in _VALID_METHODS:
            return None

        priority = data.get("priority", 2)
        if priority not in (1, 2, 3):
            priority = 2

        rag_tags = data.get("rag_context_tags", [])
        if not isinstance(rag_tags, list):
            rag_tags = []

        return Task(
            task_id=str(data.get("task_id", f"T-{counter:03d}")),
            vuln_category=cat,
            owasp_ref=data.get("owasp_ref", OWASP_REFS.get(cat, cat)),
            target_endpoint=str(data.get("target_endpoint", "")),
            method=method,
            strategy=str(data.get("strategy", "")),
            rag_context_tags=rag_tags,
            priority=int(priority),
        )

    @staticmethod
    def from_endpoint_and_category(
        ep: EnrichedEndpoint, category: str, counter: int
    ) -> Task:
        """Build a deterministic Task from an enriched endpoint and OWASP category."""
        return Task(
            task_id=f"T-{counter:03d}",
            vuln_category=category,
            owasp_ref=OWASP_REFS.get(category, category),
            target_endpoint=ep.path,
            method=ep.method,
            strategy=_DEFAULT_STRATEGIES.get(category, f"test for {category}"),
            rag_context_tags=OWASP_TAG_MAP.get(category, [])[:3],
            priority=ep.suggested_priority,
        )
