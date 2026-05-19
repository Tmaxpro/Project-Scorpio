"""API10 — Unsafe Consumption of APIs agent."""
from __future__ import annotations

from core.agents.base_agent import AgentDecision, BaseAgent
from core.coordinator.task_builder import Task


class APIConsumptionAgent(BaseAgent):
    """Tests endpoints that may consume third-party data for injection and validation issues."""

    OWASP_CATEGORY = "API10"

    def get_default_decision(self, task: Task) -> AgentDecision:
        return AgentDecision(
            task_id=task.task_id,
            chosen_strategies=["sqli", "nosqli", "third_party_injection"],
            payload_config={
                "target_trusted_fields": True,
            },
            use_exploit_module=None,
            reasoning="default API10 strategy: inject into fields that may receive or forward third-party data",
        )
