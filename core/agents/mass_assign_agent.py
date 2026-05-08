"""API6 — Unrestricted Access to Sensitive Business Flows / Mass Assignment agent."""
from __future__ import annotations

from core.agents.base_agent import AgentDecision, BaseAgent
from core.coordinator.task_builder import Task

_PRIVILEGED_FIELDS = [
    "role", "isAdmin", "admin", "is_admin", "permissions",
    "user_id", "userId", "price", "discount", "balance",
    "verified", "active", "status", "privileged", "superuser",
]


class MassAssignAgent(BaseAgent):
    """Tests POST/PUT/PATCH endpoints for mass assignment vulnerabilities."""

    OWASP_CATEGORY = "API6"

    def get_default_decision(self, task: Task) -> AgentDecision:
        return AgentDecision(
            task_id=task.task_id,
            chosen_strategies=["privilege_field_injection", "role_escalation"],
            payload_config={"inject_fields": _PRIVILEGED_FIELDS},
            use_exploit_module="mass_assign_exploit",
            reasoning="default API6 strategy: inject privileged fields not in spec",
        )
