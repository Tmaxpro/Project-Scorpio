"""API3 — Broken Object Property Level Authorization agent.

Covers both sub-issues in OWASP API3:2023:
  1. Excessive Data Exposure  — GET responses leak sensitive fields
  2. Mass Assignment          — write endpoints accept privileged fields they shouldn't
"""
from __future__ import annotations

from core.agents.base_agent import AgentDecision, BaseAgent
from core.coordinator.task_builder import Task

_SENSITIVE_RESPONSE_FIELDS = [
    "password", "password_hash", "passwd", "secret", "token", "api_key",
    "ssn", "credit_card", "cvv", "private_key", "access_token", "refresh_token",
    "internal_id", "admin_notes",
]

_PRIVILEGED_WRITE_FIELDS = [
    "role", "isAdmin", "admin", "is_admin", "permissions",
    "verified", "active", "status", "privileged", "superuser",
    "price", "discount", "balance",
]


class PropertyAuthAgent(BaseAgent):
    """Tests endpoints for property-level authorization failures."""

    OWASP_CATEGORY = "API3"

    def get_default_decision(self, task: Task) -> AgentDecision:
        method = (task.method or "GET").upper()

        if method in ("POST", "PUT", "PATCH"):
            return AgentDecision(
                task_id=task.task_id,
                chosen_strategies=["write_property_injection", "mass_assignment"],
                payload_config={"inject_fields": _PRIVILEGED_WRITE_FIELDS},
                use_exploit_module="mass_assign_exploit",
                reasoning="write endpoint — inject privileged fields to test mass assignment",
            )

        return AgentDecision(
            task_id=task.task_id,
            chosen_strategies=["response_property_audit", "excessive_data_exposure"],
            payload_config={"sensitive_fields": _SENSITIVE_RESPONSE_FIELDS},
            use_exploit_module=None,
            reasoning="read endpoint — audit response for leaked sensitive properties",
        )
