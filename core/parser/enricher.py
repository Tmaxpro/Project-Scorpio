"""OpenAPI endpoint enricher for ARIA.

Applies deterministic (no SLM) risk-hint detection and OWASP API Top 10
candidate mapping to each EndpointInfo, producing EnrichedEndpoint objects
ready for the Coordinator to consume.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from core.parser.openapi_parser import EndpointInfo

# ── Compiled patterns ─────────────────────────────────────────────────────── #

_ID_PARAM = re.compile(r"id$|uuid|user_id|object_id", re.IGNORECASE)
_SENSITIVE = re.compile(r"email|token|password|secret|key", re.IGNORECASE)
_ADMIN_PATH = re.compile(r"/admin/", re.IGNORECASE)
_BEARER_JWT = re.compile(r"bearer|jwt|token", re.IGNORECASE)


@dataclass
class EnrichedEndpoint(EndpointInfo):
    """EndpointInfo extended with risk hints and OWASP category candidates."""

    risk_hints: list[str] = field(default_factory=list)
    owasp_candidates: list[str] = field(default_factory=list)
    suggested_priority: int = 3  # 1=high, 2=medium, 3=low


class OpenAPIEnricher:
    """Deterministically annotate EndpointInfo objects with risk metadata.

    No SLM is involved — all detection is rule-based and reproducible.
    """

    def enrich(self, endpoints: list[EndpointInfo]) -> list[EnrichedEndpoint]:
        """Enrich a list of endpoints and return EnrichedEndpoint objects."""
        return [self._enrich_one(ep) for ep in endpoints]

    # ── Internal ──────────────────────────────────────────────────────────── #

    def _enrich_one(self, ep: EndpointInfo) -> EnrichedEndpoint:
        hints = self._compute_hints(ep)
        candidates = self._compute_owasp(hints, ep)
        priority = self._compute_priority(hints)

        return EnrichedEndpoint(
            path=ep.path,
            method=ep.method,
            params=ep.params,
            body_schema=ep.body_schema,
            response_schemas=ep.response_schemas,
            security=ep.security,
            tags=ep.tags,
            summary=ep.summary,
            risk_hints=hints,
            owasp_candidates=candidates,
            suggested_priority=priority,
        )

    # ── Risk hint detection ───────────────────────────────────────────────── #

    def _compute_hints(self, ep: EndpointInfo) -> list[str]:
        hints: list[str] = []

        if any(_ID_PARAM.search(p.get("name", "")) for p in ep.params):
            hints.append("has_resource_id_param")

        if ep.security:
            hints.append("auth_required")
        else:
            hints.append("no_auth_required")

        if ep.method.upper() in ("POST", "PUT", "PATCH") and ep.body_schema:
            hints.append("accepts_user_controlled_body")

        if self._schemas_contain_sensitive(ep.response_schemas):
            hints.append("returns_sensitive_data")

        if any(
            "id" in p.get("name", "").lower() and p.get("type") == "integer"
            for p in ep.params
        ):
            hints.append("sequential_id")

        if _ADMIN_PATH.search(ep.path) or "admin" in ep.summary.lower():
            hints.append("admin_endpoint")

        return hints

    # ── OWASP candidate mapping ───────────────────────────────────────────── #

    def _compute_owasp(self, hints: list[str], ep: EndpointInfo) -> list[str]:
        hint_set = set(hints)
        candidates: list[str] = []

        # API1 — BOLA: resource ID param on an authenticated endpoint
        if "has_resource_id_param" in hint_set and "auth_required" in hint_set:
            candidates.append("API1")

        # API2 — Broken Authentication: no auth required OR uses bearer/JWT scheme
        uses_jwt = any(_BEARER_JWT.search(s) for s in ep.security)
        if "no_auth_required" in hint_set or uses_jwt:
            candidates.append("API2")

        # API3 — Broken Object Property Level Authorization: sensitive fields exposed
        if "returns_sensitive_data" in hint_set:
            candidates.append("API3")

        # API4 — Unrestricted Resource Consumption: applies to every endpoint
        candidates.append("API4")

        # API5 — Broken Function Level Authorization: admin endpoints
        if "admin_endpoint" in hint_set:
            candidates.append("API5")

        # API6 — Unrestricted Access to Sensitive Business Flows / Mass Assignment
        if "accepts_user_controlled_body" in hint_set:
            candidates.append("API6")

        # API8 — Security Misconfiguration / Injection: any string input
        if self._has_string_input(ep):
            candidates.append("API8")

        return candidates

    @staticmethod
    def _compute_priority(hints: list[str]) -> int:
        """Map hint count to priority (1=high urgency, 3=low urgency).

        More risk hints → lower priority number (higher urgency).
        """
        n = len(hints)
        if n >= 3:
            return 1
        if n == 2:
            return 2
        return 3

    # ── Schema inspection helpers ─────────────────────────────────────────── #

    def _schemas_contain_sensitive(self, response_schemas: dict) -> bool:
        return any(
            self._schema_contains_sensitive(schema)
            for schema in response_schemas.values()
        )

    def _schema_contains_sensitive(self, schema: Any) -> bool:
        """Return True if any property name in *schema* matches the sensitive pattern."""
        if isinstance(schema, dict):
            for prop_name in schema.get("properties", {}):
                if _SENSITIVE.search(prop_name):
                    return True
            for prop_schema in schema.get("properties", {}).values():
                if self._schema_contains_sensitive(prop_schema):
                    return True
            if "items" in schema:
                return self._schema_contains_sensitive(schema["items"])
        elif isinstance(schema, list):
            return any(self._schema_contains_sensitive(item) for item in schema)
        return False

    def _has_string_input(self, ep: EndpointInfo) -> bool:
        """Return True if any param or body field accepts a string value."""
        if any(p.get("type") == "string" for p in ep.params):
            return True
        return bool(ep.body_schema and self._schema_has_string_field(ep.body_schema))

    def _schema_has_string_field(self, schema: Any) -> bool:
        if not isinstance(schema, dict):
            return False
        if schema.get("type") == "string":
            return True
        for prop in schema.get("properties", {}).values():
            if self._schema_has_string_field(prop):
                return True
        if "items" in schema:
            return self._schema_has_string_field(schema["items"])
        return False
