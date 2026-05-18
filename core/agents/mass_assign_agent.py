"""API6 — Unrestricted Access to Sensitive Business Flows / Mass Assignment agent."""
from __future__ import annotations

from core.agents.base_agent import AgentDecision, BaseAgent
from core.coordinator.task_builder import Task

_PRIVILEGED_FIELDS = [
    # Role escalation
    "role", "roles", "user_role", "userRole",
    "is_admin", "isAdmin", "admin", "is_superuser", "superuser",
    "privileges", "permission", "permissions",
    "access_level", "accessLevel", "account_type",
    # Status manipulation
    "active", "activated", "verified", "is_verified",
    "confirmed", "status", "account_status",
    # Identity / ownership
    "user_id", "userId", "id", "owner_id",
    # Financial
    "price", "discount", "balance", "credit",
]


class MassAssignAgent(BaseAgent):
    """Tests POST/PUT/PATCH endpoints for mass assignment vulnerabilities."""

    OWASP_CATEGORY = "API6"

    def get_default_decision(self, task: Task) -> AgentDecision:
        return AgentDecision(
            task_id=task.task_id,
            chosen_strategies=["inject_privilege_fields", "inject_status_fields"],
            payload_config={"inject_fields": _PRIVILEGED_FIELDS},
            use_exploit_module="mass_assign_exploit",
            reasoning="default API6 strategy: inject privileged fields not in spec",
        )
