"""Base class for all ARIA attack agents.

An agent is the same Foundation-Sec-Reasoning SLM with a different system
prompt injected with per-OWASP-category RAG context.  Subclasses only need
to set ``OWASP_CATEGORY`` and implement ``get_default_decision()``.
"""
from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field
from typing import Any

from core.coordinator.task_builder import OWASP_REFS, Task
from core.llm.client import LLMClient
from core.llm.prompts import AGENT_SYSTEM_PROMPT
from core.parser.enricher import EnrichedEndpoint
from core.rag.owasp_rag import OWASPRag

logger = logging.getLogger(__name__)

_PLACEHOLDER_RE = re.compile(r"\{[^}]+\}")


@dataclass
class AgentDecision:
    """The agent's analysis output — consumed by the PayloadFactory and scan runner."""

    task_id: str
    chosen_strategies: list[str]
    payload_config: dict
    use_exploit_module: str | None
    reasoning: str

    # Phase 2 — contextual fields produced when the agent sees the baseline response.
    # additional_test_urls: extra concrete paths to probe (never contain {placeholder}).
    # request_bodies: extra request bodies to try on each resolved URL.
    # interpretation_rules: conditions used by the validator to confirm a finding.
    additional_test_urls: list[str] = field(default_factory=list)
    request_bodies: list[dict] = field(default_factory=list)
    interpretation_rules: dict = field(default_factory=dict)
    confidence_needed: float = 0.7


class BaseAgent:
    """Abstract base for OWASP-category-specific attack agents.

    Subclasses must set ``OWASP_CATEGORY`` and override
    ``get_default_decision()`` with sensible category-specific fallbacks.
    """

    OWASP_CATEGORY: str = ""

    def __init__(self, llm: LLMClient, rag: OWASPRag) -> None:
        self._llm = llm
        self._rag = rag
        self._auth_token: str = ""

    def set_auth_token(self, token: str) -> None:
        """Provide the current session token so JWT exploit modules can forge from it."""
        self._auth_token = token

    # ── Public API ──────────────────────────────────────────────────────── #

    def build_system_prompt(
        self,
        task: Task,
        endpoint: EnrichedEndpoint,
        baseline_result: Any | None = None,
    ) -> str:
        """Build an OWASP-context-enriched system prompt for this task.

        When *baseline_result* (a ScanResult) is provided, its status code and
        body excerpt are embedded so the reasoning model can adapt its strategy
        based on what the API actually returns for this endpoint.
        """
        owasp_context = self._fetch_rag_context(task)
        endpoint_details = self._format_endpoint_details(endpoint)

        resolved_urls = getattr(task, "resolved_test_urls", [])
        urls_str = (
            "\n".join(f"  - {u}" for u in resolved_urls[:5])
            if resolved_urls
            else "  (none — uses template path)"
        )

        if baseline_result is not None and not getattr(baseline_result, "error", None):
            baseline_status = str(getattr(baseline_result, "status_code", "N/A"))
            raw_body = getattr(baseline_result, "response_body", "") or ""
            baseline_body = raw_body[:300] if raw_body else "(empty body)"
        else:
            baseline_status = "N/A (no baseline sent)"
            baseline_body = "N/A"

        return AGENT_SYSTEM_PROMPT.format(
            owasp_category=self.OWASP_CATEGORY or task.vuln_category,
            owasp_ref=OWASP_REFS.get(
                self.OWASP_CATEGORY or task.vuln_category,
                task.owasp_ref,
            ),
            owasp_context=owasp_context,
            method=endpoint.method,
            endpoint=endpoint.path,
            endpoint_details=endpoint_details,
            task_strategy=task.strategy,
            task_id=task.task_id,
            resolved_test_urls=urls_str,
            baseline_status=baseline_status,
            baseline_body_excerpt=baseline_body,
        )

    async def analyze(
        self,
        task: Task,
        endpoint: EnrichedEndpoint,
        baseline_result: Any | None = None,
    ) -> AgentDecision:
        """Ask the reasoning model what to do for this task.

        Short-circuits to get_default_decision() when the scan mode does not
        require LLM agent decisions (fast mode). Falls back on parse failure.

        Args:
            baseline_result: ScanResult from the first probe of the target URL.
                Sent before this call so the agent can see the API's real response
                and adapt its strategy accordingly.
        """
        if not self._llm.should_use_llm_for_agents(task.priority):
            logger.debug(
                "Agent %s skipping LLM for task %s — using rule-based defaults.",
                self.OWASP_CATEGORY, task.task_id,
            )
            return self.get_default_decision(task)

        prompt = self.build_system_prompt(task, endpoint, baseline_result)
        result = await self._llm.reason(prompt, task_id=task.task_id)

        if "error" in result:
            logger.warning(
                "Agent %s LLM call failed for task %s — using defaults.",
                self.OWASP_CATEGORY,
                task.task_id,
            )
            return self.get_default_decision(task)

        try:
            decision = self._parse_decision(result, task)
            logger.info(
                "Agent %s [%s] strategies=%s module=%s rules=%s additional_urls=%s",
                self.OWASP_CATEGORY,
                task.task_id,
                decision.chosen_strategies,
                decision.use_exploit_module,
                list(decision.interpretation_rules.keys()),
                decision.additional_test_urls,
            )
            return decision
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "Agent %s failed to parse decision for task %s: %s — using defaults.",
                self.OWASP_CATEGORY,
                task.task_id,
                exc,
            )
            return self.get_default_decision(task)

    def get_default_decision(self, task: Task) -> AgentDecision:
        """Return a safe, category-agnostic default decision.

        Override in every subclass with category-specific strategies.
        """
        return AgentDecision(
            task_id=task.task_id,
            chosen_strategies=[task.strategy],
            payload_config={},
            use_exploit_module=None,
            reasoning="base agent default — override in subclass",
        )

    # ── Internal helpers ───────────────────────────────────────────────── #

    def _parse_decision(self, result: dict, task: Task) -> AgentDecision:
        """Parse an LLM response dict into a validated AgentDecision."""
        chosen = result.get("chosen_strategies") or [task.strategy]
        if not isinstance(chosen, list) or not chosen:
            chosen = [task.strategy]

        # Phase 2 fields — parse defensively
        additional_urls = result.get("additional_test_urls", [])
        if not isinstance(additional_urls, list):
            additional_urls = []
        additional_urls = [
            str(u) for u in additional_urls
            if isinstance(u, str) and not _PLACEHOLDER_RE.search(u)
        ]

        request_bodies = result.get("request_bodies", [])
        if not isinstance(request_bodies, list):
            request_bodies = []
        request_bodies = [b for b in request_bodies if isinstance(b, dict)]

        interp = result.get("interpretation_rules", {})
        if not isinstance(interp, dict):
            interp = {}

        try:
            confidence = float(result.get("confidence_needed", 0.7))
        except (TypeError, ValueError):
            confidence = 0.7

        return AgentDecision(
            task_id=str(result.get("task_id", task.task_id)),
            chosen_strategies=chosen,
            payload_config=result.get("payload_config") or {},
            use_exploit_module=result.get("use_exploit_module"),
            reasoning=str(result.get("reasoning", "")),
            additional_test_urls=additional_urls,
            request_bodies=request_bodies,
            interpretation_rules=interp,
            confidence_needed=confidence,
        )

    def _fetch_rag_context(self, task: Task) -> str:
        """Pull the top-3 OWASP knowledge chunks relevant to this task."""
        category = self.OWASP_CATEGORY or task.vuln_category
        chunks = self._rag.query(
            owasp_category=category,
            query=f"{task.strategy} {task.target_endpoint}",
            top_k=3,
        )
        return "\n\n".join(chunks) if chunks else f"No RAG context for {category}."

    @staticmethod
    def _format_endpoint_details(endpoint: EnrichedEndpoint) -> str:
        """Produce a compact text summary of the endpoint for prompt injection."""
        parts: list[str] = []
        if endpoint.params:
            parts.append(f"Parameters: {json.dumps(endpoint.params)}")
        if endpoint.body_schema:
            schema_str = json.dumps(endpoint.body_schema, indent=2)
            parts.append(f"Request body schema:\n{schema_str[:400]}")
        if endpoint.security:
            parts.append(f"Security schemes: {', '.join(endpoint.security)}")
        if endpoint.risk_hints:
            parts.append(f"Risk hints: {', '.join(endpoint.risk_hints)}")
        if endpoint.owasp_candidates:
            parts.append(f"OWASP candidates: {', '.join(endpoint.owasp_candidates)}")
        return "\n".join(parts) if parts else "No additional endpoint details."
