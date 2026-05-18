"""False-positive filter for rule-based findings.

Removes findings that match known normal/expected API behaviors so they
don't pollute the report. Works on Finding dataclass objects produced by
ReportGenerator.build().
"""
from __future__ import annotations

import logging

logger = logging.getLogger(__name__)

# Endpoints where returning a token is expected (login, register, OAuth)
_AUTH_FLOW_SEGMENTS = (
    "/login", "/auth/token", "/token", "/signin", "/sign-in",
    "/register", "/signup", "/sign-up", "/create-account",
)

_TOKEN_PATTERNS = ("auth_token", "access_token", "token", "jwt", "bearer")


def _is_auth_flow_token_fp(endpoint: str, vuln_category: str, evidence: str) -> bool:
    """Token/JWT in an auth-flow (login/register) response is expected, not API3."""
    if vuln_category != "API3":
        return False
    # endpoint format from ReportGenerator is "METHOD /path"
    parts = endpoint.split(" ", 1)
    path = parts[1].lower() if len(parts) == 2 else endpoint.lower()
    evidence_lower = evidence.lower()
    has_token = any(p in evidence_lower for p in _TOKEN_PATTERNS)
    is_auth_flow = any(s in path for s in _AUTH_FLOW_SEGMENTS)
    return has_token and is_auth_flow


def filter_false_positives(findings: list) -> tuple[list, list]:
    """Remove known false positives from a findings list.

    Returns (real_findings, filtered_findings).
    """
    real: list = []
    filtered: list = []

    for f in findings:
        endpoint = getattr(f, "endpoint", "")
        category = getattr(f, "vuln_category", "")
        evidence = str(getattr(f, "evidence", "") or "")

        if _is_auth_flow_token_fp(endpoint, category, evidence):
            logger.debug(
                "FP filtered: %s [%s] — auth_flow_token_response", endpoint, category
            )
            filtered.append(f)
        else:
            real.append(f)

    if filtered:
        logger.info(
            "FP filter: removed %d findings, kept %d", len(filtered), len(real)
        )

    return real, filtered
