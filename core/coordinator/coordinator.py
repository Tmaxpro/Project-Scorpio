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
        credentials: dict[str, str] | None = None,
    ) -> list[Task]:
        """Return a prioritised list of Tasks for the given endpoints.

        Steps:
        1. Build a detailed spec summary (with param types) for the prompt.
        2. Pull relevant OWASP knowledge from the RAG store.
        3. Ask the reasoning model to produce a JSON task array with resolved URLs.
        4. Validate each item; fall back to rule-based if none survive.

        Args:
            credentials: dict mapping key names to values, e.g.
                {"username": "name1", "auth_token": "...", "user2_token": "..."}
                Used both in the prompt and in the rule-based fallback to resolve
                path parameters to concrete values.
        """
        creds = credentials or {}

        if not owasp_filter:
            owasp_filter = list(OWASP_REFS.keys())

        spec_summary = TaskBuilder.build_spec_summary(enriched_endpoints)
        rag_context = self._build_rag_context(owasp_filter)
        creds_summary = self._build_credentials_summary(creds)

        n_endpoints = len(enriched_endpoints)
        prompt = COORDINATOR_PROMPT.format(
            spec_summary=spec_summary,
            credentials_summary=creds_summary,
            owasp_rag_context=rag_context,
            user_context=context or "No additional context provided.",
            owasp_filter=", ".join(owasp_filter),
            endpoint_count=n_endpoints,
            min_tasks=max(n_endpoints, 5),
        )

        result = await self._llm.reason(prompt, task_id="coordinator-plan")
        tasks = self._parse_task_list(result, owasp_filter)

        # After parsing LLM tasks, backfill resolved_test_urls for any that
        # the LLM left empty (e.g. on older/weaker models)
        for t in tasks:
            if not t.resolved_test_urls:
                ep = next(
                    (e for e in enriched_endpoints if e.path == t.target_endpoint),
                    None,
                )
                if ep:
                    t.resolved_test_urls = TaskBuilder.resolve_endpoint_urls(
                        path_template=ep.path,
                        params=ep.params,
                        credentials=creds,
                        vuln_category=t.vuln_category,
                    )

        if not tasks:
            logger.warning(
                "LLM plan empty or invalid — switching to rule-based fallback. "
                "result_type=%s. Tasks will be purely rule-based (no LLM reasoning).",
                type(result).__name__,
            )
            tasks = self._rule_based_fallback(enriched_endpoints, owasp_filter, creds)
            self._log_task_plan(tasks, enriched_endpoints, owasp_filter)
            return tasks

        # Supplement: fill in any endpoint × category pairs the LLM missed
        covered = {(t.target_endpoint, t.vuln_category) for t in tasks}
        llm_count = len(tasks)
        counter = llm_count + 1
        for ep in enriched_endpoints:
            for cat in ep.owasp_candidates:
                if cat in owasp_filter and (ep.path, cat) not in covered:
                    tasks.append(
                        TaskBuilder.from_endpoint_and_category(ep, cat, counter, creds)
                    )
                    covered.add((ep.path, cat))
                    counter += 1
        if len(tasks) > llm_count:
            logger.info(
                "Supplemented %d LLM tasks with %d rule-based tasks (%d total).",
                llm_count, len(tasks) - llm_count, len(tasks),
            )
        else:
            logger.info("Coordinator: %d tasks planned via LLM.", len(tasks))

        self._log_task_plan(tasks, enriched_endpoints, owasp_filter)
        return tasks

    def _rule_based_fallback(
        self,
        endpoints: list[EnrichedEndpoint],
        owasp_filter: list[str],
        credentials: dict[str, str] | None = None,
    ) -> list[Task]:
        """One Task per (endpoint × candidate OWASP category) from enricher output."""
        creds = credentials or {}
        tasks: list[Task] = []
        counter = 1
        for ep in endpoints:
            for cat in ep.owasp_candidates:
                if cat in owasp_filter:
                    tasks.append(
                        TaskBuilder.from_endpoint_and_category(ep, cat, counter, creds)
                    )
                    counter += 1
        logger.info("Rule-based fallback produced %d tasks.", len(tasks))
        return tasks

    # ── Internal helpers ───────────────────────────────────────────────── #

    @staticmethod
    def _build_credentials_summary(credentials: dict[str, str]) -> str:
        """Format the credentials dict as a human-readable summary for the prompt.

        Token values are truncated to avoid filling the context window.
        """
        if not credentials:
            return "No credentials provided."

        lines: list[str] = []
        for key, val in credentials.items():
            if not val:
                continue
            # Show full short values (usernames); truncate long ones (tokens)
            display = val if len(val) <= 20 else f"{val[:12]}…[token]"
            lines.append(f"  {key}: {display}")
        return "\n".join(lines) if lines else "No credentials provided."

    @staticmethod
    def _log_task_plan(
        tasks: list[Task],
        enriched_endpoints: list[EnrichedEndpoint],
        owasp_filter: list[str],
    ) -> None:
        """Log a structured summary of the planned tasks for diagnostics."""
        by_category: dict[str, int] = {}
        for t in tasks:
            by_category[t.vuln_category] = by_category.get(t.vuln_category, 0) + 1

        endpoint_candidates: dict[str, int] = {}
        for ep in enriched_endpoints:
            for cat in ep.owasp_candidates:
                if cat in owasp_filter:
                    endpoint_candidates[cat] = endpoint_candidates.get(cat, 0) + 1

        logger.info("=" * 60)
        logger.info(
            "COORDINATOR PLAN — %d tasks for %d endpoints",
            len(tasks), len(enriched_endpoints),
        )
        logger.info("By OWASP category: %s", by_category)
        for cat, count in sorted(endpoint_candidates.items()):
            planned = by_category.get(cat, 0)
            if planned == 0:
                logger.warning("  ⚠ %s — %d candidates but 0 tasks planned", cat, count)
            else:
                logger.info("  ✓ %s — %d tasks (from %d candidates)", cat, planned, count)

        logger.info("Task list (showing resolved URLs):")
        for t in tasks:
            urls_preview = t.resolved_test_urls[:2] if t.resolved_test_urls else ["(none — uses template)"]
            logger.info(
                "  [P%s] %s  %s %s  → %s",
                t.priority, t.vuln_category, t.method, t.target_endpoint,
                ", ".join(urls_preview),
            )
        logger.info("=" * 60)

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
