"""Helpers for building Task objects — from LLM output or deterministic rules."""
from __future__ import annotations

import re
from dataclasses import dataclass, field
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
_PLACEHOLDER_RE = re.compile(r"\{([^}]+)\}")


@dataclass
class Task:
    """A single pentest task assigned to an attack agent."""

    task_id: str
    vuln_category: str          # e.g. "API1"
    owasp_ref: str              # e.g. "API1:2023 — BOLA"
    target_endpoint: str        # path template, e.g. "/api/v1/users/{id}"
    method: str                 # uppercase HTTP method
    strategy: str               # brief attack approach description
    rag_context_tags: list[str]
    priority: int               # 1=high, 2=medium, 3=low

    # Operational fields — populated by coordinator (LLM or rule-based fallback).
    # resolved_test_urls must NEVER contain {placeholder} — always concrete paths.
    resolved_test_urls: list[str] = field(default_factory=list)
    attacker_token_key: str = "auth_token"      # key in credentials dict
    victim_token_key: str | None = None         # key in credentials dict (BOLA)
    valid_body: dict | None = None              # valid request body from spec
    injection_body: dict | None = None          # body with injected payload
    expected_vuln_indicator: str = ""
    expected_safe_indicator: str = ""
    requires_victim_resources: bool = False     # discover victim's resources first
    resource_discovery_endpoint: str | None = None
    resource_id_field: str | None = None


class TaskBuilder:
    """Static factory methods for Task creation."""

    @staticmethod
    def build_spec_summary(endpoints: list[EnrichedEndpoint]) -> str:
        """Produce a detailed text table for the coordinator prompt.

        Includes path param types and body schema fields so the LLM can resolve
        {param} placeholders to concrete values.
        """
        lines = []
        for ep in endpoints:
            sec = ", ".join(ep.security) if ep.security else "none"
            hints = ", ".join(ep.risk_hints[:3]) if ep.risk_hints else "none"
            candidates = ", ".join(ep.owasp_candidates) if ep.owasp_candidates else "none"

            path_params = [
                "{%s}(%s)" % (
                    p["name"],
                    (p.get("schema", {}) or {}).get("type", p.get("type", "string")),
                )
                for p in ep.params if p.get("in") == "path"
            ]
            path_param_str = ", ".join(path_params) if path_params else "none"

            if ep.body_schema:
                props = ep.body_schema.get("properties", {})
                body_str = "{" + ", ".join(list(props.keys())[:6]) + "}" if props else "yes"
            else:
                body_str = "no"

            lines.append(
                f"[{ep.method}] {ep.path}"
                f" | auth: {sec}"
                f" | body: {body_str}"
                f" | path_params: {path_param_str}"
                f" | hints: {hints}"
                f" | owasp: {candidates}"
            )
        return "\n".join(lines) if lines else "No endpoints available."

    @staticmethod
    def resolve_endpoint_urls(
        path_template: str,
        params: list[dict],
        credentials: dict[str, str],
        vuln_category: str = "",
    ) -> list[str]:
        """Resolve all {placeholder} in path_template to produce concrete URLs.

        Uses credentials dict, OpenAPI param spec (example/type), and name-based
        heuristics. Never returns a URL that still contains {placeholder}.
        """
        placeholders = _PLACEHOLDER_RE.findall(path_template)
        if not placeholders:
            return [path_template]

        values_per_placeholder: list[list[str]] = []

        for placeholder in placeholders:
            pl_lower = placeholder.lower()

            # OpenAPI param spec for this placeholder
            param_spec = next(
                (p for p in params
                 if p.get("name") == placeholder and p.get("in") == "path"),
                {},
            )
            schema = param_spec.get("schema", {}) or {}
            param_type = schema.get("type", param_spec.get("type", "string"))
            param_example = schema.get("example") or param_spec.get("example")

            # Priority 1 — matching credential key (exact, substring, or superset).
            # For BOLA (API1) tasks, prefer victim-prefixed keys so the test URL
            # points to a resource belonging to the victim account.
            cred_value: str | None = None
            _victim_prefixes = ("user2", "victim", "target", "secondary")

            def _key_matches(k_lower: str) -> bool:
                return k_lower == pl_lower or k_lower in pl_lower or pl_lower in k_lower

            if vuln_category == "API1":
                for key, val in credentials.items():
                    k_lower = key.lower()
                    if (any(k_lower.startswith(p) for p in _victim_prefixes)
                            and _key_matches(k_lower)
                            and isinstance(val, str) and val):
                        cred_value = val
                        break

            if cred_value is None:
                for key, val in credentials.items():
                    k_lower = key.lower()
                    if _key_matches(k_lower) and isinstance(val, str) and val:
                        cred_value = val
                        break

            if cred_value is not None:
                candidates = [cred_value]
            elif param_example is not None:
                candidates = [str(param_example)]
            elif param_type == "integer":
                candidates = ["1", "2", "3"]
            else:
                # Heuristic by placeholder name
                if any(w in pl_lower for w in ("username", "user_name", "login")):
                    user1 = credentials.get("username") or credentials.get("user") or "user1"
                    user2 = (
                        credentials.get("user2_username")
                        or credentials.get("user2_user")
                    )
                    if vuln_category == "API1" and user2:
                        candidates = [user2, user1]
                    else:
                        candidates = [user1]
                elif any(w in pl_lower for w in ("_id", "uuid", "oid")):
                    candidates = ["1", "2"]
                else:
                    # Use the placeholder name itself as a plausible string value
                    candidates = [pl_lower.replace("_", "-"), "test"]

            values_per_placeholder.append(candidates[:3])

        # Cross-product all value lists → resolved URLs (cap at 5 total)
        resolved: list[str] = [path_template]
        for i, placeholder in enumerate(placeholders):
            new_resolved: list[str] = []
            for base_url in resolved:
                for val in values_per_placeholder[i]:
                    new_url = base_url.replace(f"{{{placeholder}}}", str(val), 1)
                    if new_url not in new_resolved:
                        new_resolved.append(new_url)
            resolved = new_resolved[:5]

        # Final guard: replace any leftover {placeholder} with its name
        clean: list[str] = []
        for url in resolved:
            remaining = _PLACEHOLDER_RE.findall(url)
            for ph in remaining:
                url = url.replace(f"{{{ph}}}", ph.replace("_", "-"))
            clean.append(url)

        return clean

    @staticmethod
    def from_llm_dict(data: Any, counter: int) -> Task | None:
        """Parse and validate a single task dict from LLM output.

        Returns None when required fields are missing or values are invalid.
        Operational fields (resolved_test_urls etc.) are optional — tasks without
        them still work via the legacy payload factory path.
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

        # Operational fields — filter out any URLs still containing placeholders
        resolved_urls = data.get("resolved_test_urls", [])
        if not isinstance(resolved_urls, list):
            resolved_urls = []
        resolved_urls = [
            str(u) for u in resolved_urls
            if isinstance(u, str) and not _PLACEHOLDER_RE.search(u)
        ]

        valid_body = data.get("valid_body")
        if not isinstance(valid_body, dict):
            valid_body = None

        injection_body = data.get("injection_body")
        if not isinstance(injection_body, dict):
            injection_body = None

        return Task(
            task_id=str(data.get("task_id", f"T-{counter:03d}")),
            vuln_category=cat,
            owasp_ref=data.get("owasp_ref", OWASP_REFS.get(cat, cat)),
            target_endpoint=str(data.get("target_endpoint", "")),
            method=method,
            strategy=str(data.get("strategy", "")),
            rag_context_tags=rag_tags,
            priority=int(priority),
            resolved_test_urls=resolved_urls,
            attacker_token_key=str(data.get("attacker_token_key") or "auth_token"),
            victim_token_key=data.get("victim_token_key") or None,
            valid_body=valid_body,
            injection_body=injection_body,
            expected_vuln_indicator=str(data.get("expected_vuln_indicator") or ""),
            expected_safe_indicator=str(data.get("expected_safe_indicator") or ""),
            requires_victim_resources=bool(data.get("requires_victim_resources", False)),
            resource_discovery_endpoint=data.get("resource_discovery_endpoint") or None,
            resource_id_field=data.get("resource_id_field") or None,
        )

    @staticmethod
    def from_endpoint_and_category(
        ep: EnrichedEndpoint,
        category: str,
        counter: int,
        credentials: dict[str, str] | None = None,
    ) -> Task:
        """Build a deterministic Task from an enriched endpoint and OWASP category."""
        creds = credentials or {}

        resolved_urls = TaskBuilder.resolve_endpoint_urls(
            path_template=ep.path,
            params=ep.params,
            credentials=creds,
            vuln_category=category,
        )

        attacker_key = "auth_token"
        victim_key = "user2_token" if (category == "API1" and "user2_token" in creds) else None
        requires_victim = category == "API1" and victim_key is not None

        return Task(
            task_id=f"T-{counter:03d}",
            vuln_category=category,
            owasp_ref=OWASP_REFS.get(category, category),
            target_endpoint=ep.path,
            method=ep.method,
            strategy=_DEFAULT_STRATEGIES.get(category, f"test for {category}"),
            rag_context_tags=OWASP_TAG_MAP.get(category, [])[:3],
            priority=ep.suggested_priority,
            resolved_test_urls=resolved_urls,
            attacker_token_key=attacker_key,
            victim_token_key=victim_key,
            requires_victim_resources=requires_victim,
            resource_discovery_endpoint=_infer_list_endpoint(ep.path) if requires_victim else None,
            resource_id_field=_infer_id_field(ep.params) if requires_victim else None,
        )


# ── Module-level helpers ──────────────────────────────────────────────────────

def _infer_list_endpoint(path: str) -> str | None:
    """Guess the collection endpoint from a parameterized path: /a/b/{x} → /a/b"""
    parts = path.rstrip("/").rsplit("/", 1)
    if len(parts) == 2 and "{" in parts[1]:
        return parts[0] or None
    return None


def _infer_id_field(params: list[dict]) -> str | None:
    """Return the name of the first path param (likely the resource ID)."""
    for p in params:
        if p.get("in") == "path":
            return p.get("name")
    return None
