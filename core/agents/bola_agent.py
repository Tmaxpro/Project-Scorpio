"""API1 — Broken Object Level Authorization (BOLA) agent."""
from __future__ import annotations

from core.agents.base_agent import AgentDecision, BaseAgent
from core.coordinator.task_builder import Task


class BOLAAgent(BaseAgent):
    """Tests endpoints for horizontal privilege escalation via ID manipulation."""

    OWASP_CATEGORY = "API1"

    def get_default_decision(self, task: Task) -> AgentDecision:
        return AgentDecision(
            task_id=task.task_id,
            chosen_strategies=["horizontal_id_enumeration", "uuid_substitution"],
            payload_config={
                "id_range": 20,
                "test_unauthenticated": True,
                "test_other_user_token": True,
            },
            use_exploit_module="bola_exploit",
            reasoning="default BOLA strategy: enumerate IDs around the owned resource",
        )
