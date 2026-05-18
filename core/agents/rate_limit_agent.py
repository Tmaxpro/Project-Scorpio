"""API4 — Unrestricted Resource Consumption (rate-limit) agent."""
from __future__ import annotations

from core.agents.base_agent import AgentDecision, BaseAgent
from core.coordinator.task_builder import Task
from core.payload_factory.exploit_modules.rate_limit_exploit import should_test_rate_limit


class RateLimitAgent(BaseAgent):
    """Tests endpoints for missing or bypassable rate limiting."""

    OWASP_CATEGORY = "API4"

    def get_default_decision(self, task: Task) -> AgentDecision:
        should_test, count = should_test_rate_limit(task.target_endpoint, task.method)

        if not should_test:
            return AgentDecision(
                task_id=task.task_id,
                chosen_strategies=[],
                payload_config={},
                use_exploit_module=None,
                reasoning=(
                    f"API4 skipped for {task.method} {task.target_endpoint} "
                    "— low-risk public endpoint"
                ),
            )

        return AgentDecision(
            task_id=task.task_id,
            chosen_strategies=["rate_limit_absence_check"],
            payload_config={
                "request_count": count,
                "delay_between_ms": 0,
                "vary_headers": False,
            },
            use_exploit_module=None,
            reasoning=(
                f"API4: send {count} requests to {task.target_endpoint} "
                "and check for absence of 429"
            ),
        )
