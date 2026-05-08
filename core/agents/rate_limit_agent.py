"""API4 — Unrestricted Resource Consumption (rate-limit) agent."""
from __future__ import annotations

from core.agents.base_agent import AgentDecision, BaseAgent
from core.coordinator.task_builder import Task


class RateLimitAgent(BaseAgent):
    """Tests endpoints for missing or bypassable rate limiting."""

    OWASP_CATEGORY = "API4"

    def get_default_decision(self, task: Task) -> AgentDecision:
        return AgentDecision(
            task_id=task.task_id,
            chosen_strategies=["rate_limit_absence_check"],
            payload_config={
                "request_count": 50,
                "delay_between_ms": 0,
                "vary_headers": False,
            },
            use_exploit_module=None,
            reasoning=(
                "default API4 strategy: send 50 identical requests "
                "and check for absence of 429"
            ),
        )
