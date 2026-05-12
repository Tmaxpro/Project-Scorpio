"""Deterministic rule-based vulnerability detection for ARIA."""
from __future__ import annotations

import re
from dataclasses import dataclass, field

from core.http_engine.client import ScanResult

# ── Detection patterns ────────────────────────────────────────────────────── #

_SENSITIVE_RE = re.compile(
    r'(?:password|passwd|secret|api_?key|access_?token|auth_?token|'
    r'private_?key|ssn|credit_?card)["\s:=]+[^\s,}"\']{3,}',
    re.IGNORECASE,
)
_EMAIL_RE = re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b')

_SQL_ERROR_RE = re.compile(
    r"sql\s+(?:syntax|error)|"
    r"mysql_(?:num_rows|fetch)|"
    r"ORA-\d{5}|"
    r"pg_query\(\)|"
    r"unclosed.*quotation|"
    r"you have an error in your sql",
    re.IGNORECASE,
)
_NOSQL_ERROR_RE = re.compile(
    r"MongoError:|MongoServerError:|CastError:|ObjectId.*failed",
    re.IGNORECASE,
)
_SSTI_RESULT_RE = re.compile(r"\b49\b")  # {{7*7}} evaluated

_STACKTRACE_RE = re.compile(
    r"Traceback\s+\(most recent call last\)|"
    r"at\s+[\w.$]+\([\w.]+:\d+\)|"
    r"java\.(?:lang|io|util)\.\w+Exception|"
    r"System\.Exception:|"
    r"#\d+\s+\w+\s+\([^)]*\)",
    re.IGNORECASE,
)


# ── Data classes ──────────────────────────────────────────────────────────── #

@dataclass
class RuleCheckResult:
    """Result of a single deterministic rule check."""

    rule_id: str
    triggered: bool
    severity: str        # "high" | "medium" | "low" | "info"
    evidence: str
    owasp_category: str


@dataclass
class ValidationResult:
    """Full validation outcome for one ScanResult."""

    task_id: str
    scan_result: ScanResult
    rule_checks: list[RuleCheckResult] = field(default_factory=list)
    is_vulnerable: bool = False
    confirmed_by_slm: bool = False
    slm_reasoning: str = ""

    def triggered_checks(self) -> list[RuleCheckResult]:
        return [c for c in self.rule_checks if c.triggered]

    def highest_severity(self) -> str:
        _order = {"high": 0, "medium": 1, "low": 2, "info": 3}
        triggered = self.triggered_checks()
        return "info" if not triggered else min(
            triggered, key=lambda c: _order.get(c.severity, 99)
        ).severity


# ── Validator ─────────────────────────────────────────────────────────────── #

class RuleValidator:
    """Runs deterministic security checks against HTTP scan results."""

    def check(self, result: ScanResult) -> list[RuleCheckResult]:
        """Run all per-result rules against a single scan result."""
        if result.is_error:
            return []
        return [
            self._check_auth_bypass(result),
            self._check_error_disclosure(result),
            self._check_sensitive_data(result),
            self._check_injection_error(result),
            self._check_admin_endpoint_exposed(result),
            self._check_bola_object_access(result),
        ]

    def check_rate_limit_batch(self, results: list[ScanResult]) -> RuleCheckResult:
        """Detect rate-limit absence across a batch of rate-limit-test requests."""
        valid = [r for r in results if not r.is_error]
        got_throttled = any(r.status_code == 429 for r in valid)
        succeeded = sum(1 for r in valid if 200 <= r.status_code < 300)
        triggered = not got_throttled and succeeded > 10
        return RuleCheckResult(
            rule_id="rate_limit_absent",
            triggered=triggered,
            severity="high" if triggered else "info",
            evidence=(
                f"Sent {len(valid)} requests, {succeeded} succeeded with no 429"
                if triggered
                else f"Server throttled after {succeeded} requests"
            ),
            owasp_category="API4",
        )

    def build_result(
        self, scan_result: ScanResult, checks: list[RuleCheckResult]
    ) -> ValidationResult:
        """Wrap checks into a ValidationResult, setting is_vulnerable if any high/medium fired."""
        high_or_medium = [c for c in checks if c.triggered and c.severity in ("high", "medium")]
        return ValidationResult(
            task_id=scan_result.task_id,
            scan_result=scan_result,
            rule_checks=checks,
            is_vulnerable=bool(high_or_medium),
        )

    # ── Individual rules ──────────────────────────────────────────────────── #

    @staticmethod
    def _check_auth_bypass(result: ScanResult) -> RuleCheckResult:
        """API2/API5: 2xx response on a request deliberately sent without auth."""
        no_auth = "Authorization" not in result.request.headers
        intentional = (
            result.request.label in ("missing_auth_header", "admin_access:no_auth")
            or result.request.label.endswith(":unauthenticated")
            or result.request.headers.get("X-ARIA-Skip-Auth", "").lower() == "true"
        )
        triggered = no_auth and intentional and 200 <= result.status_code < 300
        return RuleCheckResult(
            rule_id="auth_bypass",
            triggered=triggered,
            severity="high",
            evidence=f"Got {result.status_code} with no Authorization header" if triggered else "",
            owasp_category="API2",
        )

    @staticmethod
    def _check_error_disclosure(result: ScanResult) -> RuleCheckResult:
        """General: HTTP 500 containing a stack trace."""
        triggered = (
            result.status_code == 500
            and bool(_STACKTRACE_RE.search(result.response_body))
        )
        return RuleCheckResult(
            rule_id="error_disclosure",
            triggered=triggered,
            severity="medium",
            evidence="500 response with stack trace" if triggered else "",
            owasp_category="API8",
        )

    @staticmethod
    def _check_sensitive_data(result: ScanResult) -> RuleCheckResult:
        """API3: sensitive field values (password, token, secret) exposed in a 2xx response."""
        if not (200 <= result.status_code < 300):
            return RuleCheckResult("sensitive_data_exposure", False, "medium", "", "API3")
        match = _SENSITIVE_RE.search(result.response_body) or _EMAIL_RE.search(result.response_body)
        triggered = bool(match)
        return RuleCheckResult(
            rule_id="sensitive_data_exposure",
            triggered=triggered,
            severity="medium",
            evidence=f"Sensitive pattern: {match.group(0)[:80]}" if triggered else "",
            owasp_category="API3",
        )

    @staticmethod
    def _check_injection_error(result: ScanResult) -> RuleCheckResult:
        """API8: DB error or template-evaluation evidence in response body."""
        sql = _SQL_ERROR_RE.search(result.response_body)
        nosql = _NOSQL_ERROR_RE.search(result.response_body)
        ssti = (
            result.request.strategy == "ssti"
            and bool(_SSTI_RESULT_RE.search(result.response_body))
        )
        triggered = bool(sql or nosql or ssti)
        if sql:
            evidence = f"SQL error: {sql.group(0)[:80]}"
        elif nosql:
            evidence = f"NoSQL error: {nosql.group(0)[:80]}"
        elif ssti:
            evidence = "SSTI: expression evaluated (49 in response)"
        else:
            evidence = ""
        return RuleCheckResult(
            rule_id="injection_error",
            triggered=triggered,
            severity="high",
            evidence=evidence,
            owasp_category="API8",
        )

    @staticmethod
    def _check_admin_endpoint_exposed(result: ScanResult) -> RuleCheckResult:
        """API5: admin endpoint accessible via spoofed role headers."""
        triggered = (
            result.request.label == "admin_access:role_spoof"
            and 200 <= result.status_code < 300
        )
        return RuleCheckResult(
            rule_id="admin_endpoint_exposed",
            triggered=triggered,
            severity="high",
            evidence=(
                f"Admin endpoint {result.request.path} accessible with spoofed role"
                if triggered else ""
            ),
            owasp_category="API5",
        )

    @staticmethod
    def _check_bola_object_access(result: ScanResult) -> RuleCheckResult:
        """API1: 200 for a BOLA cross-user access attempt."""
        triggered = (
            result.request.strategy == "bola_exploit"
            and 200 <= result.status_code < 300
            and "X-ARIA-Skip-Auth" not in result.request.headers
        )
        return RuleCheckResult(
            rule_id="bola_object_access",
            triggered=triggered,
            severity="medium",
            evidence=(
                f"Object {result.request.path} returned {result.status_code}"
                if triggered else ""
            ),
            owasp_category="API1",
        )
