"""SLM-based vulnerability confirmation for ARIA."""
from __future__ import annotations

import logging

from core.coordinator.task_builder import Task
from core.http_engine.client import ScanResult
from core.llm.client import LLMClient
from core.llm.prompts import SLM_VALIDATOR_PROMPT
from core.validator.rule_validator import RuleCheckResult

logger = logging.getLogger(__name__)


def _request_summary(result: ScanResult) -> str:
    req = result.request
    parts = [f"{req.method} {req.path}", f"Strategy: {req.strategy}", f"Label: {req.label}"]
    if req.query_params:
        parts.append(f"Query: {req.query_params}")
    if req.body:
        parts.append(f"Body (truncated): {str(req.body)[:300]}")
    # Omit X-ARIA-* internal headers from the summary
    visible = {k: v for k, v in req.headers.items() if not k.startswith("X-ARIA-")}
    if visible:
        parts.append(f"Headers: {visible}")
    return "\n".join(parts)


def _response_summary(result: ScanResult) -> str:
    parts = [
        f"Status: {result.status_code}",
        f"Response time: {result.response_time_ms:.1f}ms",
    ]
    interesting = {
        k: v for k, v in result.response_headers.items()
        if k.lower() in ("content-type", "x-ratelimit-limit", "www-authenticate", "server")
    }
    if interesting:
        parts.append(f"Headers: {interesting}")
    if result.response_body:
        parts.append(f"Body (first 500 chars):\n{result.response_body[:500]}")
    return "\n".join(parts)


def _rule_reasoning(checks: list[RuleCheckResult]) -> str:
    triggered = [c for c in checks if c.triggered]
    if not triggered:
        return "No deterministic rules triggered."
    return "\n".join(
        f"- [{c.owasp_category}] {c.rule_id} ({c.severity}): {c.evidence}"
        for c in triggered
    )


class SLMValidator:
    """Asks the Foundation-Sec-Instruct model to confirm a rule-triggered finding."""

    def __init__(self, llm: LLMClient) -> None:
        self._llm = llm

    async def confirm(
        self,
        result: ScanResult,
        rule_checks: list[RuleCheckResult],
        task: Task,
    ) -> tuple[bool, str]:
        """Return (is_confirmed, reasoning) from the instruct model.

        Falls back to (False, error_message) if the LLM call fails.
        """
        prompt = SLM_VALIDATOR_PROMPT.format(
            vuln_category=task.vuln_category,
            task_strategy=task.strategy,
            request_summary=_request_summary(result),
            response_summary=_response_summary(result),
            rule_validator_reasoning=_rule_reasoning(rule_checks),
        )
        response = await self._llm.instruct(prompt, task_id=task.task_id)

        if "error" in response:
            logger.warning(
                "SLM validator failed for task %s: %s",
                task.task_id,
                response["error"],
            )
            return False, f"SLM validation unavailable: {response['error']}"

        confirmed = bool(response.get("confirmed", False))
        reasoning = str(response.get("reasoning", ""))
        return confirmed, reasoning
