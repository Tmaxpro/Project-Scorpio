"""Scan coordinator — turns enriched endpoints into a prioritised Task list.

The coordinator queries the LLM to build a strategic test plan. If the LLM
output is invalid or missing, it falls back to a deterministic rule-based plan:
one Task per (endpoint × OWASP candidate category) derived from the enricher.
"""
from __future__ import annotations

import logging
from typing import Any

from core.coordinator.task_builder import OWASP_REFS, Task, TaskBuilder
from core.llm.client import LLMClient
from core.llm.prompts import COORDINATOR_PROMPT
from core.parser.enricher import EnrichedEndpoint
from core.rag.owasp_rag import OWASPRag

logger = logging.getLogger(__name__)


class Coordinator:
    """Plan a pentest campaign from enriched endpoint data.

    Calls ``LLMClient.reason()`` once (which internally retries up to
    ``max_retries`` times and escalates to the fallback model on JSON failure).
    If the final result is still unusable, ``_rule_based_fallback()`` generates
    one Task per (endpoint × OWASP candidate) without any LLM involvement.
    """

    def __init__(self, llm: LLMClient, rag: OWASPRag) -> None:
        self._llm = llm
        self._rag = rag

    # ── Public API ──────────────────────────────────────────────────────── #

    async def plan(
        self,
        enriched_endpoints: list[EnrichedEndpoint],
        context: str,
        owasp_filter: list[str],
    ) -> list[Task]:
        """Return a prioritised list of Tasks for the given endpoints.

        Steps:
        1. Build a concise spec summary for the prompt.
        2. Pull relevant OWASP knowledge from the RAG store.
        3. Ask the reasoning model to produce a JSON task array.
        4. Validate each item; fall back to rule-based if none survive.
        """
        if not owasp_filter:
            owasp_filter = list(OWASP_REFS.keys())

        spec_summary = TaskBuilder.build_spec_summary(enriched_endpoints)
        rag_context = self._build_rag_context(owasp_filter)

        prompt = COORDINATOR_PROMPT.format(
            spec_summary=spec_summary,
            owasp_rag_context=rag_context,
            user_context=context or "No additional context provided.",
            owasp_filter=", ".join(owasp_filter),
        )

        result = await self._llm.reason(prompt, task_id="coordinator-plan")
        tasks = self._parse_task_list(result, owasp_filter)

        if not tasks:
            logger.warning(
                "LLM plan empty or invalid — switching to rule-based fallback. "
                "result_type=%s",
                type(result).__name__,
            )
            return self._rule_based_fallback(enriched_endpoints, owasp_filter)

        logger.info("Coordinator: %d tasks planned via LLM.", len(tasks))
        return tasks

    def _rule_based_fallback(
        self,
        endpoints: list[EnrichedEndpoint],
        owasp_filter: list[str],
    ) -> list[Task]:
        """One Task per (endpoint × candidate OWASP category) from enricher output."""
        tasks: list[Task] = []
        counter = 1
        for ep in endpoints:
            for cat in ep.owasp_candidates:
                if cat in owasp_filter:
                    tasks.append(
                        TaskBuilder.from_endpoint_and_category(ep, cat, counter)
                    )
                    counter += 1
        logger.info("Rule-based fallback produced %d tasks.", len(tasks))
        return tasks

    # ── Internal helpers ───────────────────────────────────────────────── #

    def _build_rag_context(self, owasp_filter: list[str]) -> str:
        """Query RAG for the top-2 chunks per requested OWASP category."""
        all_chunks: list[str] = []
        for category in owasp_filter:
            chunks = self._rag.query(
                owasp_category=category,
                query=f"{category} attack techniques vulnerabilities exploitation",
                top_k=2,
            )
            all_chunks.extend(chunks)
        if not all_chunks:
            return "No RAG context available — proceed with general OWASP knowledge."
        # Cap total context to 10 chunks to keep the prompt manageable
        return "\n\n---\n\n".join(all_chunks[:10])

    def _parse_task_list(
        self, result: Any, owasp_filter: list[str]
    ) -> list[Task]:
        """Parse LLM output into validated Task objects.

        Accepts both a bare JSON array (list) and a dict with a "tasks" key.
        Silently skips items that fail validation or reference a category not
        in *owasp_filter*.
        """
        if isinstance(result, dict):
            if "error" in result:
                return []
            if "tasks" in result and isinstance(result["tasks"], list):
                task_list = result["tasks"]
            else:
                return []
        elif isinstance(result, list):
            task_list = result
        else:
            return []

        valid: list[Task] = []
        for i, item in enumerate(task_list):
            task = TaskBuilder.from_llm_dict(item, i + 1)
            if task and task.vuln_category in owasp_filter:
                valid.append(task)
            elif task:
                logger.debug(
                    "Dropping task %s — category %s not in filter.",
                    task.task_id,
                    task.vuln_category,
                )

        return valid
