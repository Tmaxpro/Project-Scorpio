"""Task dispatcher — runs agent analysis concurrently with a semaphore cap."""
from __future__ import annotations

import asyncio
import logging

from core.agents.base_agent import AgentDecision, BaseAgent
from core.coordinator.task_builder import Task
from core.parser.enricher import EnrichedEndpoint

logger = logging.getLogger(__name__)


class Dispatcher:
    """Dispatch a list of Tasks to the appropriate agent concurrently.

    Agent routing is determined by ``task.vuln_category``. A ``"default"``
    key in *agents* is used as a catch-all for unhandled categories.
    """

    def __init__(
        self,
        agents: dict[str, BaseAgent],
        max_concurrent: int = 3,
    ) -> None:
        self._agents = agents
        self._semaphore = asyncio.Semaphore(max_concurrent)

    async def dispatch(
        self,
        tasks: list[Task],
        endpoints: list[EnrichedEndpoint],
    ) -> list[AgentDecision]:
        """Run all tasks concurrently (up to *max_concurrent* at once).

        Endpoint lookup is done by exact (path, method) match first, then
        path-only match, then falls back to ``get_default_decision()``.
        """
        endpoint_map: dict[tuple[str, str], EnrichedEndpoint] = {
            (ep.path, ep.method.upper()): ep for ep in endpoints
        }

        async def run(task: Task) -> AgentDecision:
            async with self._semaphore:
                agent = self._agents.get(task.vuln_category) or self._agents.get("default")
                if agent is None:
                    logger.warning(
                        "No agent for category %s (task %s) — using pass-through decision.",
                        task.vuln_category,
                        task.task_id,
                    )
                    return AgentDecision(
                        task_id=task.task_id,
                        chosen_strategies=[task.strategy],
                        payload_config={},
                        use_exploit_module=None,
                        reasoning=f"no agent registered for {task.vuln_category}",
                    )

                ep = endpoint_map.get(
                    (task.target_endpoint, task.method.upper())
                ) or next(
                    (e for e in endpoints if e.path == task.target_endpoint),
                    None,
                )

                if ep is None:
                    logger.debug(
                        "Endpoint not found for task %s (%s %s) — using defaults.",
                        task.task_id,
                        task.method,
                        task.target_endpoint,
                    )
                    return agent.get_default_decision(task)

                return await agent.analyze(task, ep)

        results = await asyncio.gather(*[run(t) for t in tasks], return_exceptions=False)
        return list(results)
