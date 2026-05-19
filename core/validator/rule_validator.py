"""Deterministic rule-based vulnerability detection for ARIA."""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

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

_SSRF_RESPONSE_RE = re.compile(
    r"root:x:0:0:|"                          # /etc/passwd
    r"169\.254\.169\.254|"                   # cloud metadata IP in body
    r'"ami-id"|"instance-id"|"hostname"',    # AWS/GCP metadata keys
    re.IGNORECASE,
)

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

    def validate(
        self,
        result: ScanResult,
        baseline_result: Any | None = None,
        interpretation_rules: dict | None = None,
    ) -> tuple[ValidationResult, bool]:
        """Run all checks + agent interpretation rules; flag ambiguous results for SLM.

        Returns (ValidationResult, needs_slm_review). When needs_slm_review is True
        the caller should pass the result to SLMValidator for confirmation.
        """
        checks = self.check(result)

        if interpretation_rules and not result.is_error:
            agent_check = _evaluate_agent_rules(result, baseline_result, interpretation_rules)
            if agent_check is not None:
                checks.append(agent_check)

        vr = self.build_result(result, checks)
        needs_slm = _needs_slm_review(result, baseline_result, checks)
        return vr, needs_slm

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
            self._check_mass_assignment(result),
            self._check_ssrf_response(result),
            self._check_undocumented_endpoint(result),
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

    @staticmethod
    def _check_mass_assignment(result: ScanResult) -> RuleCheckResult:
        """API6: injected privilege field reflected back in a 2xx response."""
        _none = RuleCheckResult("mass_assignment_accepted", False, "high", "", "API6")
        if result.request.strategy != "mass_assign_exploit":
            return _none
        if not (200 <= result.status_code < 300):
            return _none

        body = result.response_body
        label = result.request.label  # e.g. "mass_assign:role='admin'"

        # Parse field and expected value from the label
        if label.startswith("mass_assign:") and "=" in label:
            part = label[len("mass_assign:"):]
            eq_pos = part.index("=")
            field = part[:eq_pos]
            raw_val = part[eq_pos + 1:].strip("'\"")

            body_lower = body.lower()
            field_key = f'"{field}"'
            if field_key in body_lower and raw_val.lower() in body_lower:
                return RuleCheckResult(
                    rule_id="mass_assignment_accepted",
                    triggered=True,
                    severity="high",
                    evidence=f"Injected '{field}' reflected as '{raw_val}' in response",
                    owasp_category="API6",
                )

        return _none

    @staticmethod
    def _check_ssrf_response(result: ScanResult) -> RuleCheckResult:
        """API7: SSRF payload triggered an internal-data leak or cloud metadata access."""
        _none = RuleCheckResult("ssrf_response", False, "high", "", "API7")
        if result.request.strategy != "ssrf":
            return _none
        if not (200 <= result.status_code < 300):
            return _none
        match = _SSRF_RESPONSE_RE.search(result.response_body)
        if not match:
            return _none
        return RuleCheckResult(
            rule_id="ssrf_response",
            triggered=True,
            severity="high",
            evidence=f"SSRF: internal data in response: {match.group(0)[:80]}",
            owasp_category="API7",
        )

    @staticmethod
    def _check_undocumented_endpoint(result: ScanResult) -> RuleCheckResult:
        """API9: debug/version/docs endpoint returns 200 (should be 404 or auth-gated)."""
        _none = RuleCheckResult("undocumented_endpoint_exposed", False, "medium", "", "API9")
        if result.request.strategy not in ("api_version_enumeration", "debug_endpoint_discovery"):
            return _none
        if result.status_code != 200:
            return _none
        return RuleCheckResult(
            rule_id="undocumented_endpoint_exposed",
            triggered=True,
            severity="medium",
            evidence=f"Undocumented endpoint {result.request.path} returned 200",
            owasp_category="API9",
        )


# ── Phase 4: Agent rule evaluation helpers ───────────────────────────────── #

def _evaluate_condition(
    result: ScanResult,
    baseline: Any | None,
    condition: str,
) -> bool:
    """Lightweight evaluation of an LLM-produced natural-language condition.

    Supports: status-code keywords (200, 2xx, 401, 403, 404, 500, 4xx), body
    keywords (error, sql, data, content, json), and baseline-comparison phrases
    (change, different, bypass, access, successful).
    Returns False for empty or uninterpretable conditions.
    """
    if not condition:
        return False

    cond = condition.lower()
    status = result.status_code
    body = (result.response_body or "").lower()

    # Status-code checks
    if "200" in cond and 200 <= status < 300:
        return True
    if "2xx" in cond and 200 <= status < 300:
        return True
    if "500" in cond and status == 500:
        return True
    if "403" in cond and status == 403:
        return True
    if "401" in cond and status == 401:
        return True
    if "404" in cond and status == 404:
        return True
    if "429" in cond and status == 429:
        return True
    if "4xx" in cond and 400 <= status < 500:
        return True

    # Body content checks
    if "error" in cond and any(w in body for w in ("error", "exception", "traceback")):
        return True
    if "sql" in cond and bool(_SQL_ERROR_RE.search(result.response_body or "")):
        return True
    if "data" in cond and 200 <= status < 300 and len(body) > 30:
        return True
    if "content" in cond and len(body) > 50:
        return True
    if "json" in cond and 200 <= status < 300 and (body.startswith("{") or body.startswith("[")):
        return True

    # Baseline-comparison phrases
    if baseline is not None:
        baseline_status = getattr(baseline, "status_code", None)
        if (
            any(k in cond for k in ("change", "different", "bypass", "access", "successful"))
            and baseline_status in (401, 403, 404)
            and 200 <= status < 300
        ):
            return True

    return False


def _evaluate_agent_rules(
    result: ScanResult,
    baseline: Any | None,
    rules: dict,
) -> RuleCheckResult | None:
    """Return a synthetic RuleCheckResult when the agent's confirmed_if condition is met.

    Also evaluates false_positive_if to suppress spurious results.
    Forces owasp_category to API8 on injection evidence, API1 on cross-user access.
    """
    confirmed_if = rules.get("confirmed_if", "")
    false_positive_if = rules.get("false_positive_if", "")

    if not _evaluate_condition(result, baseline, confirmed_if):
        return None

    if false_positive_if and _evaluate_condition(result, baseline, false_positive_if):
        return None

    body = result.response_body or ""
    if _SQL_ERROR_RE.search(body) or _NOSQL_ERROR_RE.search(body):
        category = "API8"
    elif (
        result.request.headers.get("X-ARIA-Other-User", "").lower() == "true"
        and 200 <= result.status_code < 300
    ):
        category = "API1"
    else:
        category = "API_AGENT"

    return RuleCheckResult(
        rule_id="agent_rule_match",
        triggered=True,
        severity="medium",
        evidence=f"Agent confirmed_if: {confirmed_if[:120]}",
        owasp_category=category,
    )


def _needs_slm_review(
    result: ScanResult,
    baseline: Any | None,
    checks: list[RuleCheckResult],
) -> bool:
    """Return True when SLM confirmation is warranted for an ambiguous result."""
    if result.is_error:
        return False

    # Ambiguous status change: baseline was auth-gated but result succeeded
    if baseline is not None:
        baseline_status = getattr(baseline, "status_code", None)
        if baseline_status in (401, 403, 404) and 200 <= result.status_code < 300:
            return True

    # Agent rule fired without any deterministic rule confirming it
    agent_fired = any(c.triggered and c.rule_id == "agent_rule_match" for c in checks)
    deterministic_fired = any(
        c.triggered for c in checks if c.rule_id != "agent_rule_match"
    )
    return agent_fired and not deterministic_fired
