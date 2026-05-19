"""API9 — Improper Inventory Management agent."""
from __future__ import annotations

from core.agents.base_agent import AgentDecision, BaseAgent
from core.coordinator.task_builder import Task


class InventoryAgent(BaseAgent):
    """Probes for undocumented API versions and exposed debug/documentation endpoints."""

    OWASP_CATEGORY = "API9"

    def get_default_decision(self, task: Task) -> AgentDecision:
        return AgentDecision(
            task_id=task.task_id,
            chosen_strategies=["api_version_enumeration", "debug_endpoint_discovery"],
            payload_config={
                "probe_versions": ["v1", "v2", "v3", "beta"],
                "probe_docs": True,
                "probe_debug": True,
            },
            use_exploit_module=None,
            reasoning="default API9 strategy: enumerate old API versions and discover undocumented endpoints",
        )
