"""Base class for all ARIA attack agents.

An agent is the same Foundation-Sec-Reasoning SLM with a different system
prompt injected with per-OWASP-category RAG context.  Subclasses only need
to set ``OWASP_CATEGORY`` and implement ``get_default_decision()``.
"""
from __future__ import annotations

import json
import logging
from dataclasses import dataclass

from core.coordinator.task_builder import OWASP_REFS, Task
from core.llm.client import LLMClient
from core.llm.prompts import AGENT_SYSTEM_PROMPT
from core.parser.enricher import EnrichedEndpoint
from core.rag.owasp_rag import OWASPRag

logger = logging.getLogger(__name__)


@dataclass
class AgentDecision:
    """The agent's analysis output — consumed by the PayloadFactory."""

    task_id: str
    chosen_strategies: list[str]
    payload_config: dict
    use_exploit_module: str | None
    reasoning: str


class BaseAgent:
    """Abstract base for OWASP-category-specific attack agents.

    Subclasses must set ``OWASP_CATEGORY`` and override
    ``get_default_decision()`` with sensible category-specific fallbacks.
    """

    OWASP_CATEGORY: str = ""

    def __init__(self, llm: LLMClient, rag: OWASPRag) -> None:
        self._llm = llm
        self._rag = rag

    # ── Public API ──────────────────────────────────────────────────────── #

    def build_system_prompt(self, task: Task, endpoint: EnrichedEndpoint) -> str:
        """Build an OWASP-context-enriched system prompt for this task."""
        owasp_context = self._fetch_rag_context(task)
        endpoint_details = self._format_endpoint_details(endpoint)

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
        )

    async def analyze(self, task: Task, endpoint: EnrichedEndpoint) -> AgentDecision:
        """Ask the reasoning model what to do for this task.

        Parses the JSON response into an AgentDecision; falls back to
        ``get_default_decision()`` on any parse or validation failure.
        """
        prompt = self.build_system_prompt(task, endpoint)
        result = await self._llm.reason(prompt, task_id=task.task_id)

        if "error" in result:
            logger.warning(
                "Agent %s LLM call failed for task %s — using defaults.",
                self.OWASP_CATEGORY,
                task.task_id,
            )
            return self.get_default_decision(task)

        try:
            decision = AgentDecision(
                task_id=str(result.get("task_id", task.task_id)),
                chosen_strategies=result.get("chosen_strategies") or [task.strategy],
                payload_config=result.get("payload_config") or {},
                use_exploit_module=result.get("use_exploit_module"),
                reasoning=str(result.get("reasoning", "")),
            )
            # Validate chosen_strategies is a non-empty list of strings
            if not isinstance(decision.chosen_strategies, list) or not decision.chosen_strategies:
                decision.chosen_strategies = [task.strategy]
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
