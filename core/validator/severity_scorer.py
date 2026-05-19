"""Context-aware severity scoring for ARIA.

Severity depends on BOTH the vulnerability type AND the endpoint context.
Call apply_contextual_severity() after build_result() in the scan pipeline.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from core.parser.enricher import EnrichedEndpoint
    from core.validator.rule_validator import ValidationResult


@dataclass
class SeverityContext:
    endpoint: str
    method: str
    vuln_category: str
    rules: list[str]
    endpoint_has_auth: bool
    endpoint_has_resource_id: bool
    endpoint_returns_sensitive: bool


# Base severity per OWASP category
BASE_SEVERITY: dict[str, str] = {
    "API1": "high",
    "API2": "high",
    "API3": "medium",
    "API4": "low",
    "API5": "high",
    "API6": "medium",
    "API7": "high",
    "API8": "high",
    "API9": "low",
    "API10": "medium",
}

SEVERITY_ORDER = ["info", "low", "medium", "high", "critical"]

_AUTH_SEGMENTS = frozenset({
    "login", "auth", "token", "signin", "sign-in",
    "password", "reset", "otp", "verify", "2fa", "mfa", "forgot",
})


def _is_auth_endpoint(endpoint: str) -> bool:
    ep = endpoint.lower()
    return any(f"/{seg}" in ep for seg in _AUTH_SEGMENTS)


def compute_severity(ctx: SeverityContext) -> str:
    """Compute context-aware severity for a single finding."""
    base = BASE_SEVERITY.get(ctx.vuln_category, "medium")
    idx = SEVERITY_ORDER.index(base)

    # Upgrade: rate limit on auth endpoints → high (brute force risk)
    if ctx.vuln_category == "API4" and _is_auth_endpoint(ctx.endpoint):
        idx = min(idx + 1, len(SEVERITY_ORDER) - 1)
    # Upgrade: sensitive data + password in rules → escalate to high
    elif (
        ctx.vuln_category == "API3"
        and ctx.endpoint_returns_sensitive
        and "password" in " ".join(ctx.rules).lower()
    ):
        idx = min(idx + 1, len(SEVERITY_ORDER) - 1)
    # Upgrade: auth bypass on authenticated endpoint → critical
    elif (
        ctx.vuln_category == "API2"
        and "auth_bypass" in ctx.rules
        and ctx.endpoint_has_auth
    ):
        idx = min(idx + 1, len(SEVERITY_ORDER) - 1)

    # Downgrade: rate limit on public GET with no resource ID → info
    if (
        ctx.vuln_category == "API4"
        and not ctx.endpoint_has_auth
        and not ctx.endpoint_has_resource_id
        and ctx.method.upper() == "GET"
        and not _is_auth_endpoint(ctx.endpoint)
    ):
        idx = max(idx - 1, 0)
    # Downgrade: data exposure on public endpoint without password → low
    elif (
        ctx.vuln_category == "API3"
        and not ctx.endpoint_has_auth
        and "password" not in " ".join(ctx.rules).lower()
    ):
        idx = max(idx - 1, 0)

    return SEVERITY_ORDER[idx]


def apply_contextual_severity(vr: "ValidationResult", ep: "EnrichedEndpoint") -> None:
    """Mutate triggered RuleCheckResult severities in-place using endpoint context."""
    hints = set(ep.risk_hints)
    triggered_rules = [c.rule_id for c in vr.rule_checks if c.triggered]

    for check in vr.rule_checks:
        if not check.triggered:
            continue
        ctx = SeverityContext(
            endpoint=ep.path,
            method=ep.method,
            vuln_category=check.owasp_category,
            rules=triggered_rules,
            endpoint_has_auth="auth_required" in hints,
            endpoint_has_resource_id="has_resource_id_param" in hints,
            endpoint_returns_sensitive="returns_sensitive_data" in hints,
        )
        check.severity = compute_severity(ctx)
