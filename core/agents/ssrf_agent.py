"""API7 — Server Side Request Forgery agent."""
from __future__ import annotations

from core.agents.base_agent import AgentDecision, BaseAgent
from core.coordinator.task_builder import Task


class SSRFAgent(BaseAgent):
    """Injects SSRF payloads into URL-accepting parameters to probe internal access."""

    OWASP_CATEGORY = "API7"

    def get_default_decision(self, task: Task) -> AgentDecision:
        return AgentDecision(
            task_id=task.task_id,
            chosen_strategies=["ssrf"],
            payload_config={
                "test_internal": True,
                "test_metadata": True,
                "test_file": True,
            },
            use_exploit_module=None,
            reasoning="default API7 strategy: inject SSRF payloads into URL-accepting fields",
        )
