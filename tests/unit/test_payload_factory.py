"""Unit tests for Phase 5: PayloadFactory + exploit modules."""
from __future__ import annotations

import re
from unittest.mock import MagicMock

from core.agents.base_agent import AgentDecision
from core.coordinator.task_builder import Task
from core.parser.openapi_parser import EndpointInfo
from core.payload_factory.exploit_modules.bola_exploit import build_bola_payloads
from core.payload_factory.exploit_modules.jwt_exploit import (
    _make_none_alg_jwt,
    _make_hs256_jwt,
    build_jwt_payloads,
)
from core.payload_factory.exploit_modules.mass_assign_exploit import build_mass_assign_payloads
from core.payload_factory.factory import PayloadFactory
from core.payload_factory.models import PayloadRequest
from core.payload_factory.nuclei_parser import NucleiPayloadAdapter
from core.payload_factory.schema_mutator import get_string_fields, inject_fields, minimal_body

# ── Fixtures ──────────────────────────────────────────────────────────────── #

_SCHEMA_MIXED = {
    "type": "object",
    "required": ["username"],
    "properties": {
        "username": {"type": "string"},
        "email": {"type": "string"},
        "age": {"type": "integer"},
        "active": {"type": "boolean"},
    },
}

_SCHEMA_NO_REQUIRED = {
    "type": "object",
    "properties": {
        "name": {"type": "string"},
        "count": {"type": "integer"},
    },
}


def _make_task(category: str = "API1", method: str = "GET", path: str = "/api/items/{id}") -> Task:
    return Task(
        task_id="T-001",
        vuln_category=category,
        owasp_ref=f"{category}:2023",
        target_endpoint=path,
        method=method,
        strategy="test",
        rag_context_tags=[],
        priority=2,
    )


def _make_decision(
    strategies: list[str] | None = None,
    module: str | None = None,
    config: dict | None = None,
) -> AgentDecision:
    return AgentDecision(
        task_id="T-001",
        chosen_strategies=strategies or ["baseline"],
        payload_config=config or {},
        use_exploit_module=module,
        reasoning="test",
    )


def _make_endpoint(
    path: str = "/api/items/{id}",
    method: str = "GET",
    params: list[dict] | None = None,
    body_schema: dict | None = None,
) -> EndpointInfo:
    return EndpointInfo(
        path=path,
        method=method,
        params=params or [{"name": "id", "in": "path", "type": "integer", "required": True}],
        body_schema=body_schema,
        response_schemas={},
        security=["bearerAuth"],
        tags=[],
        summary="",
    )


def _mock_adapter(payloads: dict | None = None) -> NucleiPayloadAdapter:
    adapter = MagicMock(spec=NucleiPayloadAdapter)
    adapter.get_payloads.side_effect = lambda cat: (payloads or {}).get(cat, [])
    adapter.get_matchers.return_value = []
    return adapter


# ── TestSchemaMutator ─────────────────────────────────────────────────────── #


class TestSchemaMutator:
    def test_get_string_fields_none_returns_empty(self):
        assert get_string_fields(None) == []

    def test_get_string_fields_empty_schema_returns_empty(self):
        assert get_string_fields({}) == []

    def test_get_string_fields_returns_only_string_types(self):
        fields = get_string_fields(_SCHEMA_MIXED)
        assert set(fields) == {"username", "email"}
        assert "age" not in fields
        assert "active" not in fields

    def test_get_string_fields_schema_with_no_properties(self):
        assert get_string_fields({"type": "object"}) == []

    def test_minimal_body_none_schema_returns_empty_dict(self):
        assert minimal_body(None) == {}

    def test_minimal_body_fills_required_fields(self):
        body = minimal_body(_SCHEMA_MIXED)
        assert "username" in body
        assert isinstance(body["username"], str)
        # non-required fields should not be present
        assert "email" not in body

    def test_minimal_body_fills_all_when_no_required(self):
        body = minimal_body(_SCHEMA_NO_REQUIRED)
        assert "name" in body
        assert "count" in body

    def test_minimal_body_correct_types(self):
        schema = {
            "type": "object",
            "required": ["n", "s", "b"],
            "properties": {
                "n": {"type": "integer"},
                "s": {"type": "string"},
                "b": {"type": "boolean"},
            },
        }
        body = minimal_body(schema)
        assert isinstance(body["n"], int)
        assert isinstance(body["s"], str)
        assert isinstance(body["b"], bool)

    def test_inject_fields_merges(self):
        result = inject_fields({"a": 1}, {"b": 2})
        assert result == {"a": 1, "b": 2}

    def test_inject_fields_extra_overrides_base(self):
        result = inject_fields({"role": "user"}, {"role": "admin"})
        assert result["role"] == "admin"

    def test_inject_fields_does_not_mutate_original(self):
        base = {"a": 1}
        inject_fields(base, {"b": 2})
        assert "b" not in base


# ── TestNucleiPayloadAdapter ──────────────────────────────────────────────── #


class TestNucleiPayloadAdapter:
    def test_unknown_category_returns_empty_list(self):
        from core.rag.nuclei_index import NucleiIndex
        import tempfile, os
        with tempfile.TemporaryDirectory() as tmp:
            idx = NucleiIndex(tmp)
            adapter = NucleiPayloadAdapter(idx)
            assert adapter.get_payloads("API99") == []

    def test_get_payloads_delegates_to_index(self):
        mock_idx = MagicMock()
        mock_idx.get_payloads.return_value = ["payload1"]
        adapter = NucleiPayloadAdapter(mock_idx)
        result = adapter.get_payloads("API8")
        mock_idx.get_payloads.assert_called_once_with("API8")
        assert result == ["payload1"]

    def test_get_matchers_delegates_to_index(self):
        mock_idx = MagicMock()
        mock_idx.get_matchers.return_value = [{"type": "status"}]
        adapter = NucleiPayloadAdapter(mock_idx)
        result = adapter.get_matchers("API2")
        mock_idx.get_matchers.assert_called_once_with("API2")
        assert result == [{"type": "status"}]


# ── TestJWTExploit ────────────────────────────────────────────────────────── #


class TestJWTExploit:
    def _jwt_decision(self, **overrides) -> AgentDecision:
        config = {
            "test_none_alg": True,
            "test_missing_header": True,
            "test_expired_token": True,
            "weak_secrets": ["secret", "password"],
        }
        config.update(overrides.get("config", {}))
        return _make_decision(module="jwt_exploit", config=config)

    def test_none_alg_jwt_has_no_signature(self):
        token = _make_none_alg_jwt()
        parts = token.split(".")
        assert len(parts) == 3
        assert parts[2] == ""

    def test_none_alg_variant_present(self):
        ep = _make_endpoint(path="/api/login", method="POST", params=[])
        results = build_jwt_payloads(_make_task("API2", "POST", "/api/login"), self._jwt_decision(), ep)
        labels = [r.label for r in results]
        assert "jwt_none_algorithm" in labels

    def test_missing_auth_header_variant_has_empty_headers(self):
        ep = _make_endpoint(path="/api/login", method="POST", params=[])
        results = build_jwt_payloads(_make_task("API2", "POST", "/api/login"), self._jwt_decision(), ep)
        missing = next(r for r in results if r.label == "missing_auth_header")
        assert missing.headers == {}

    def test_expired_token_variant_present(self):
        ep = _make_endpoint(path="/api/me", method="GET", params=[])
        results = build_jwt_payloads(_make_task("API2", "GET", "/api/me"), self._jwt_decision(), ep)
        labels = [r.label for r in results]
        assert "expired_token_reuse" in labels

    def test_expired_token_is_bearer(self):
        ep = _make_endpoint(path="/api/me", method="GET", params=[])
        results = build_jwt_payloads(_make_task("API2", "GET", "/api/me"), self._jwt_decision(), ep)
        expired = next(r for r in results if r.label == "expired_token_reuse")
        assert expired.headers.get("Authorization", "").startswith("Bearer ")

    def test_weak_secrets_generate_one_variant_each(self):
        ep = _make_endpoint(path="/api/me", method="GET", params=[])
        results = build_jwt_payloads(_make_task("API2", "GET", "/api/me"), self._jwt_decision(), ep)
        weak_labels = [r.label for r in results if r.label.startswith("weak_secret:")]
        assert len(weak_labels) == 2  # "secret" and "password"

    def test_all_variants_have_correct_task_id(self):
        ep = _make_endpoint(path="/api/me", method="GET", params=[])
        results = build_jwt_payloads(_make_task("API2", "GET", "/api/me"), self._jwt_decision(), ep)
        assert all(r.task_id == "T-001" for r in results)

    def test_all_variants_have_correct_path(self):
        ep = _make_endpoint(path="/api/me", method="GET", params=[])
        results = build_jwt_payloads(_make_task("API2", "GET", "/api/me"), self._jwt_decision(), ep)
        assert all(r.path == "/api/me" for r in results)

    def test_hs256_jwt_has_three_parts_with_signature(self):
        token = _make_hs256_jwt({"sub": "1"}, "mysecret")
        parts = token.split(".")
        assert len(parts) == 3
        assert parts[2] != ""


# ── TestBOLAExploit ───────────────────────────────────────────────────────── #


class TestBOLAExploit:
    def _bola_decision(self, **config_overrides) -> AgentDecision:
        config = {"id_range": 5, "test_unauthenticated": True, "test_other_user_token": True}
        config.update(config_overrides)
        return _make_decision(module="bola_exploit", config=config)

    def test_substitutes_id_in_path(self):
        ep = _make_endpoint()
        results = build_bola_payloads(_make_task(), self._bola_decision(), ep)
        assert any("/api/items/1" in r.path for r in results)

    def test_generates_id_range(self):
        ep = _make_endpoint()
        results = build_bola_payloads(_make_task(), self._bola_decision(id_range=5), ep)
        paths = {r.path for r in results if "X-ARIA-Skip-Auth" not in r.headers and "X-ARIA-Other-User" not in r.headers}
        assert len(paths) == 5

    def test_unauthenticated_variant_present(self):
        ep = _make_endpoint()
        results = build_bola_payloads(_make_task(), self._bola_decision(), ep)
        assert any("X-ARIA-Skip-Auth" in r.headers for r in results)

    def test_other_user_variant_present(self):
        ep = _make_endpoint()
        results = build_bola_payloads(_make_task(), self._bola_decision(), ep)
        assert any("X-ARIA-Other-User" in r.headers for r in results)

    def test_no_unauth_when_disabled(self):
        ep = _make_endpoint()
        results = build_bola_payloads(_make_task(), self._bola_decision(test_unauthenticated=False), ep)
        assert not any("X-ARIA-Skip-Auth" in r.headers for r in results)

    def test_uuid_param_generates_uuid_format(self):
        ep = _make_endpoint(
            path="/api/objects/{uuid}",
            params=[{"name": "uuid", "in": "path", "type": "string", "required": True}],
        )
        results = build_bola_payloads(_make_task(path="/api/objects/{uuid}"), self._bola_decision(), ep)
        uuid_re = re.compile(r"[0-9a-f\-]{36}", re.IGNORECASE)
        assert any(uuid_re.search(r.path) for r in results)

    def test_all_results_have_correct_task_id(self):
        ep = _make_endpoint()
        results = build_bola_payloads(_make_task(), self._bola_decision(), ep)
        assert all(r.task_id == "T-001" for r in results)

    def test_no_path_params_returns_empty(self):
        ep = _make_endpoint(path="/api/items", params=[])
        results = build_bola_payloads(_make_task(path="/api/items"), self._bola_decision(), ep)
        assert results == []


# ── TestMassAssignExploit ─────────────────────────────────────────────────── #


class TestMassAssignExploit:
    def _ma_decision(self, fields: list[str] | None = None) -> AgentDecision:
        return _make_decision(
            module="mass_assign_exploit",
            config={"inject_fields": fields or ["role", "isAdmin", "balance"]},
        )

    def test_one_variant_per_field(self):
        ep = _make_endpoint(path="/api/users", method="POST", params=[], body_schema=_SCHEMA_MIXED)
        results = build_mass_assign_payloads(_make_task("API6", "POST", "/api/users"), self._ma_decision(), ep)
        field_labels = [r.label for r in results if "all_privileged" not in r.label]
        assert len(field_labels) == 3  # role, isAdmin, balance

    def test_combined_variant_always_present(self):
        ep = _make_endpoint(path="/api/users", method="POST", params=[], body_schema=_SCHEMA_MIXED)
        results = build_mass_assign_payloads(_make_task("API6", "POST", "/api/users"), self._ma_decision(), ep)
        labels = [r.label for r in results]
        assert "mass_assign:all_privileged_fields" in labels

    def test_injects_into_base_body(self):
        schema = {
            "type": "object",
            "required": ["username"],
            "properties": {"username": {"type": "string"}},
        }
        ep = _make_endpoint(path="/api/users", method="POST", params=[], body_schema=schema)
        results = build_mass_assign_payloads(
            _make_task("API6", "POST", "/api/users"),
            self._ma_decision(["role"]),
            ep,
        )
        role_variant = next(r for r in results if "role" in r.label and "all" not in r.label)
        assert role_variant.body is not None
        assert "username" in role_variant.body
        assert "role" in role_variant.body

    def test_all_have_json_content_type(self):
        ep = _make_endpoint(path="/api/users", method="POST", params=[], body_schema=None)
        results = build_mass_assign_payloads(_make_task("API6", "POST", "/api/users"), self._ma_decision(), ep)
        assert all(r.headers.get("Content-Type") == "application/json" for r in results)

    def test_combined_has_all_injected_fields(self):
        ep = _make_endpoint(path="/api/users", method="POST", params=[], body_schema=None)
        results = build_mass_assign_payloads(
            _make_task("API6", "POST", "/api/users"),
            self._ma_decision(["role", "isAdmin"]),
            ep,
        )
        combined = next(r for r in results if r.label == "mass_assign:all_privileged_fields")
        assert combined.body is not None
        assert "role" in combined.body
        assert "isAdmin" in combined.body


# ── TestPayloadFactory ────────────────────────────────────────────────────── #


class TestPayloadFactory:
    def _factory(self, payloads: dict | None = None) -> PayloadFactory:
        return PayloadFactory(_mock_adapter(payloads))

    def test_delegates_to_exploit_module(self):
        factory = self._factory()
        task = _make_task("API2", "GET", "/api/me")
        decision = _make_decision(
            module="jwt_exploit",
            config={"test_none_alg": True, "test_missing_header": False,
                    "test_expired_token": False, "weak_secrets": []},
        )
        ep = _make_endpoint(path="/api/me", method="GET", params=[])
        results = factory.build(task, decision, ep)
        assert any(r.label == "jwt_none_algorithm" for r in results)

    def test_unknown_exploit_module_falls_back_to_strategies(self):
        factory = self._factory()
        task = _make_task("API4", "GET", "/api/items")
        decision = _make_decision(
            strategies=["rate_limit_absence_check"],
            module="nonexistent_module",
            config={"request_count": 3},
        )
        ep = _make_endpoint(path="/api/items", method="GET", params=[])
        results = factory.build(task, decision, ep)
        assert len(results) == 3

    def test_rate_limit_generates_exact_count(self):
        factory = self._factory()
        task = _make_task("API4", "GET", "/api/items")
        decision = _make_decision(
            strategies=["rate_limit_absence_check"],
            config={"request_count": 10},
        )
        ep = _make_endpoint(path="/api/items", method="GET", params=[])
        results = factory.build(task, decision, ep)
        assert len(results) == 10

    def test_rate_limit_all_have_same_path(self):
        factory = self._factory()
        task = _make_task("API4", "GET", "/api/items")
        decision = _make_decision(
            strategies=["rate_limit_absence_check"],
            config={"request_count": 5},
        )
        ep = _make_endpoint(path="/api/items", method="GET", params=[])
        results = factory.build(task, decision, ep)
        assert all(r.path == "/api/items" for r in results)

    def test_injection_uses_default_payloads_when_nuclei_empty(self):
        factory = self._factory()  # adapter returns [] for all categories
        task = _make_task("API8", "POST", "/api/search")
        decision = _make_decision(strategies=["sqli"])
        ep = _make_endpoint(
            path="/api/search",
            method="POST",
            params=[{"name": "q", "in": "query", "type": "string", "required": False}],
            body_schema=None,
        )
        results = factory.build(task, decision, ep)
        assert len(results) > 0
        assert all(r.strategy == "sqli" for r in results)

    def test_injection_uses_nuclei_payloads_when_available(self):
        nuclei_sqli = ["' OR 1=1--", "custom_nuclei_payload"]
        factory = self._factory({"API8": nuclei_sqli})
        task = _make_task("API8", "POST", "/api/search")
        decision = _make_decision(strategies=["sqli"])
        ep = _make_endpoint(
            path="/api/search",
            method="POST",
            params=[{"name": "q", "in": "query", "type": "string", "required": False}],
            body_schema=None,
        )
        results = factory.build(task, decision, ep)
        query_values = [r.query_params.get("q", "") for r in results]
        assert "custom_nuclei_payload" in query_values

    def test_injection_targets_string_body_fields(self):
        factory = self._factory()
        task = _make_task("API8", "POST", "/api/users")
        decision = _make_decision(strategies=["sqli"])
        ep = _make_endpoint(
            path="/api/users",
            method="POST",
            params=[],
            body_schema={
                "type": "object",
                "properties": {"username": {"type": "string"}, "age": {"type": "integer"}},
            },
        )
        results = factory.build(task, decision, ep)
        body_labels = [r.label for r in results if r.body]
        assert any("username" in lbl for lbl in body_labels)
        assert not any("age" in lbl for lbl in body_labels)

    def test_admin_access_generates_no_auth_and_role_spoof(self):
        factory = self._factory()
        task = _make_task("API5", "GET", "/admin/users")
        decision = _make_decision(
            strategies=["admin_endpoint_access"],
            config={"role_headers": {"X-Role": "admin"}},
        )
        ep = _make_endpoint(path="/admin/users", method="GET", params=[])
        results = factory.build(task, decision, ep)
        labels = [r.label for r in results]
        assert "admin_access:no_auth" in labels
        assert "admin_access:role_spoof" in labels

    def test_admin_access_role_spoof_has_headers(self):
        factory = self._factory()
        task = _make_task("API5", "GET", "/admin/users")
        decision = _make_decision(
            strategies=["admin_endpoint_access"],
            config={"role_headers": {"X-Role": "admin"}},
        )
        ep = _make_endpoint(path="/admin/users", method="GET", params=[])
        results = factory.build(task, decision, ep)
        spoof = next(r for r in results if r.label == "admin_access:role_spoof")
        assert spoof.headers.get("X-Role") == "admin"

    def test_method_enum_generates_all_seven_methods(self):
        factory = self._factory()
        task = _make_task("API5", "GET", "/api/items")
        decision = _make_decision(strategies=["http_method_enumeration"])
        ep = _make_endpoint(path="/api/items", method="GET", params=[])
        results = factory.build(task, decision, ep)
        methods = {r.method for r in results}
        assert methods == {"GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"}

    def test_always_returns_at_least_one_request(self):
        factory = self._factory()
        task = _make_task()
        decision = _make_decision(strategies=["unknown_strategy_xyz"])
        ep = _make_endpoint()
        results = factory.build(task, decision, ep)
        assert len(results) >= 1

    def test_unknown_strategy_returns_baseline(self):
        factory = self._factory()
        task = _make_task()
        decision = _make_decision(strategies=["unknown_strategy_xyz"])
        ep = _make_endpoint()
        results = factory.build(task, decision, ep)
        assert results[0].label == "baseline"

    def test_empty_strategies_returns_baseline(self):
        factory = self._factory()
        task = _make_task()
        decision = _make_decision(strategies=[])
        ep = _make_endpoint()
        results = factory.build(task, decision, ep)
        assert len(results) == 1
        assert results[0].label == "baseline"

    def test_all_results_are_payload_request_instances(self):
        factory = self._factory()
        task = _make_task("API2", "GET", "/api/me")
        decision = _make_decision(
            module="jwt_exploit",
            config={"test_none_alg": True, "test_missing_header": True,
                    "test_expired_token": True, "weak_secrets": ["secret"]},
        )
        ep = _make_endpoint(path="/api/me", method="GET", params=[])
        results = factory.build(task, decision, ep)
        assert all(isinstance(r, PayloadRequest) for r in results)
