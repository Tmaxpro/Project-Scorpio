"""API8 — Security Misconfiguration / Injection agent."""
from __future__ import annotations

from core.agents.base_agent import AgentDecision, BaseAgent
from core.coordinator.task_builder import Task


class InjectionAgent(BaseAgent):
    """Tests string inputs for SQLi, NoSQLi, SSTI, and XSS injection."""

    OWASP_CATEGORY = "API8"

    def get_default_decision(self, task: Task) -> AgentDecision:
        return AgentDecision(
            task_id=task.task_id,
            chosen_strategies=["sqli", "nosqli", "ssti", "xss"],
            payload_config={
                "test_types": ["sqli", "nosqli", "ssti", "xss"],
                "reflect_check": True,
                "error_check": True,
                "time_based": False,
            },
            use_exploit_module=None,
            reasoning="default API8 strategy: test all string inputs for injection",
        )
