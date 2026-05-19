"""API2 (Broken Authentication) and API5 (Broken Function Level Authorization) agent."""
from __future__ import annotations

from core.agents.base_agent import AgentDecision, BaseAgent
from core.coordinator.task_builder import Task


class AuthAgent(BaseAgent):
    """Tests authentication weaknesses (API2) and function-level auth bypass (API5)."""

    OWASP_CATEGORY = "API2"

    def get_default_decision(self, task: Task) -> AgentDecision:
        if task.vuln_category == "API5":
            return AgentDecision(
                task_id=task.task_id,
                chosen_strategies=["admin_endpoint_access", "http_method_enumeration"],
                payload_config={
                    "test_methods": ["GET", "POST", "PUT", "DELETE", "PATCH"],
                    "role_headers": {"X-Role": "admin", "X-User-Type": "administrator"},
                },
                use_exploit_module=None,
                reasoning="default API5 strategy: access admin endpoint as regular user",
            )

        from core.payload_factory.exploit_modules.jwt_exploit import _DEFAULT_WEAK_SECRETS
        return AgentDecision(
            task_id=task.task_id,
            chosen_strategies=[
                "jwt_none_algorithm",
                "jwt_weak_secret_bruteforce",
                "missing_auth_header",
                "expired_token_reuse",
            ],
            payload_config={
                "test_none_alg": True,
                "test_missing_header": True,
                "test_expired_token": True,
                "weak_secrets": _DEFAULT_WEAK_SECRETS,
                "auth_token": self._auth_token,
            },
            use_exploit_module="jwt_exploit",
            reasoning="default API2 strategy: JWT manipulation and auth bypass",
        )
