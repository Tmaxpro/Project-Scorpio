"""Unit tests for core/parser/enricher.py."""
from __future__ import annotations

import pytest

from core.parser.enricher import OpenAPIEnricher
from core.parser.openapi_parser import EndpointInfo


# ── Helpers ───────────────────────────────────────────────────────────────── #

def _ep(
    path: str = "/items",
    method: str = "GET",
    params: list[dict] | None = None,
    body_schema: dict | None = None,
    response_schemas: dict | None = None,
    security: list[str] | None = None,
    tags: list[str] | None = None,
    summary: str = "",
) -> EndpointInfo:
    return EndpointInfo(
        path=path,
        method=method,
        params=params or [],
        body_schema=body_schema,
        response_schemas=response_schemas or {},
        security=security or [],
        tags=tags or [],
        summary=summary,
    )


@pytest.fixture()
def enricher() -> OpenAPIEnricher:
    return OpenAPIEnricher()


# ── Risk hint detection ───────────────────────────────────────────────────── #

class TestRiskHints:
    def test_has_resource_id_param_on_id_suffix(self, enricher: OpenAPIEnricher):
        ep = _ep(params=[{"name": "user_id", "in": "path", "type": "integer", "required": True}])
        result = enricher.enrich([ep])[0]
        assert "has_resource_id_param" in result.risk_hints

    def test_has_resource_id_param_on_uuid(self, enricher: OpenAPIEnricher):
        ep = _ep(params=[{"name": "uuid", "in": "path", "type": "string", "required": True}])
        result = enricher.enrich([ep])[0]
        assert "has_resource_id_param" in result.risk_hints

    def test_has_resource_id_param_on_object_id(self, enricher: OpenAPIEnricher):
        ep = _ep(params=[{"name": "object_id", "in": "path", "type": "string", "required": True}])
        result = enricher.enrich([ep])[0]
        assert "has_resource_id_param" in result.risk_hints

    def test_no_resource_id_param_on_plain_name(self, enricher: OpenAPIEnricher):
        ep = _ep(params=[{"name": "status", "in": "query", "type": "string", "required": False}])
        result = enricher.enrich([ep])[0]
        assert "has_resource_id_param" not in result.risk_hints

    def test_auth_required_when_security_present(self, enricher: OpenAPIEnricher):
        ep = _ep(security=["bearerAuth"])
        result = enricher.enrich([ep])[0]
        assert "auth_required" in result.risk_hints
        assert "no_auth_required" not in result.risk_hints

    def test_no_auth_required_when_security_empty(self, enricher: OpenAPIEnricher):
        ep = _ep(security=[])
        result = enricher.enrich([ep])[0]
        assert "no_auth_required" in result.risk_hints
        assert "auth_required" not in result.risk_hints

    def test_accepts_user_controlled_body_post_with_body(self, enricher: OpenAPIEnricher):
        ep = _ep(
            method="POST",
            body_schema={"type": "object", "properties": {"name": {"type": "string"}}},
        )
        result = enricher.enrich([ep])[0]
        assert "accepts_user_controlled_body" in result.risk_hints

    def test_accepts_user_controlled_body_put_with_body(self, enricher: OpenAPIEnricher):
        ep = _ep(
            method="PUT",
            body_schema={"type": "object", "properties": {"name": {"type": "string"}}},
        )
        result = enricher.enrich([ep])[0]
        assert "accepts_user_controlled_body" in result.risk_hints

    def test_accepts_user_controlled_body_patch_with_body(self, enricher: OpenAPIEnricher):
        ep = _ep(
            method="PATCH",
            body_schema={"type": "object", "properties": {"name": {"type": "string"}}},
        )
        result = enricher.enrich([ep])[0]
        assert "accepts_user_controlled_body" in result.risk_hints

    def test_no_body_hint_for_get(self, enricher: OpenAPIEnricher):
        ep = _ep(
            method="GET",
            body_schema={"type": "object"},
        )
        result = enricher.enrich([ep])[0]
        assert "accepts_user_controlled_body" not in result.risk_hints

    def test_no_body_hint_when_no_schema(self, enricher: OpenAPIEnricher):
        ep = _ep(method="POST", body_schema=None)
        result = enricher.enrich([ep])[0]
        assert "accepts_user_controlled_body" not in result.risk_hints

    def test_returns_sensitive_data_email(self, enricher: OpenAPIEnricher):
        ep = _ep(
            response_schemas={
                "200": {
                    "type": "object",
                    "properties": {"email": {"type": "string"}, "id": {"type": "integer"}},
                }
            }
        )
        result = enricher.enrich([ep])[0]
        assert "returns_sensitive_data" in result.risk_hints

    def test_returns_sensitive_data_password(self, enricher: OpenAPIEnricher):
        ep = _ep(
            response_schemas={
                "200": {
                    "type": "object",
                    "properties": {"password": {"type": "string"}},
                }
            }
        )
        result = enricher.enrich([ep])[0]
        assert "returns_sensitive_data" in result.risk_hints

    def test_returns_sensitive_data_token(self, enricher: OpenAPIEnricher):
        ep = _ep(
            response_schemas={
                "200": {
                    "type": "object",
                    "properties": {"access_token": {"type": "string"}},
                }
            }
        )
        result = enricher.enrich([ep])[0]
        assert "returns_sensitive_data" in result.risk_hints

    def test_no_sensitive_data_hint_for_benign_schema(self, enricher: OpenAPIEnricher):
        ep = _ep(
            response_schemas={
                "200": {
                    "type": "object",
                    "properties": {"name": {"type": "string"}, "age": {"type": "integer"}},
                }
            }
        )
        result = enricher.enrich([ep])[0]
        assert "returns_sensitive_data" not in result.risk_hints

    def test_returns_sensitive_data_in_array_items(self, enricher: OpenAPIEnricher):
        ep = _ep(
            response_schemas={
                "200": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {"secret": {"type": "string"}},
                    },
                }
            }
        )
        result = enricher.enrich([ep])[0]
        assert "returns_sensitive_data" in result.risk_hints

    def test_sequential_id_integer_id_param(self, enricher: OpenAPIEnricher):
        ep = _ep(
            params=[{"name": "user_id", "in": "path", "type": "integer", "required": True}]
        )
        result = enricher.enrich([ep])[0]
        assert "sequential_id" in result.risk_hints

    def test_no_sequential_id_for_string_uuid(self, enricher: OpenAPIEnricher):
        ep = _ep(
            params=[{"name": "uuid", "in": "path", "type": "string", "required": True}]
        )
        result = enricher.enrich([ep])[0]
        assert "sequential_id" not in result.risk_hints

    def test_admin_endpoint_by_path(self, enricher: OpenAPIEnricher):
        ep = _ep(path="/admin/users")
        result = enricher.enrich([ep])[0]
        assert "admin_endpoint" in result.risk_hints

    def test_admin_endpoint_by_summary(self, enricher: OpenAPIEnricher):
        ep = _ep(summary="Admin: list all accounts")
        result = enricher.enrich([ep])[0]
        assert "admin_endpoint" in result.risk_hints

    def test_no_admin_hint_for_regular_endpoint(self, enricher: OpenAPIEnricher):
        ep = _ep(path="/users", summary="List users")
        result = enricher.enrich([ep])[0]
        assert "admin_endpoint" not in result.risk_hints


# ── OWASP candidate mapping ───────────────────────────────────────────────── #

class TestOWASPCandidates:
    def test_api1_requires_resource_id_and_auth(self, enricher: OpenAPIEnricher):
        ep = _ep(
            params=[{"name": "user_id", "in": "path", "type": "integer", "required": True}],
            security=["bearerAuth"],
        )
        result = enricher.enrich([ep])[0]
        assert "API1" in result.owasp_candidates

    def test_api1_absent_without_id_param(self, enricher: OpenAPIEnricher):
        ep = _ep(security=["bearerAuth"])
        result = enricher.enrich([ep])[0]
        assert "API1" not in result.owasp_candidates

    def test_api1_absent_without_auth(self, enricher: OpenAPIEnricher):
        ep = _ep(
            params=[{"name": "user_id", "in": "path", "type": "integer", "required": True}],
            security=[],
        )
        result = enricher.enrich([ep])[0]
        assert "API1" not in result.owasp_candidates

    def test_api2_when_no_auth_required(self, enricher: OpenAPIEnricher):
        ep = _ep(security=[])
        result = enricher.enrich([ep])[0]
        assert "API2" in result.owasp_candidates

    def test_api2_when_bearer_jwt_scheme(self, enricher: OpenAPIEnricher):
        ep = _ep(security=["bearerAuth"])
        result = enricher.enrich([ep])[0]
        assert "API2" in result.owasp_candidates

    def test_api2_when_jwt_in_scheme_name(self, enricher: OpenAPIEnricher):
        ep = _ep(security=["jwtToken"])
        result = enricher.enrich([ep])[0]
        assert "API2" in result.owasp_candidates

    def test_api3_when_sensitive_data(self, enricher: OpenAPIEnricher):
        ep = _ep(
            response_schemas={
                "200": {
                    "type": "object",
                    "properties": {"email": {"type": "string"}},
                }
            }
        )
        result = enricher.enrich([ep])[0]
        assert "API3" in result.owasp_candidates

    def test_api4_always_present(self, enricher: OpenAPIEnricher):
        for method in ("GET", "POST", "DELETE"):
            ep = _ep(method=method)
            result = enricher.enrich([ep])[0]
            assert "API4" in result.owasp_candidates

    def test_api5_for_admin_endpoint(self, enricher: OpenAPIEnricher):
        ep = _ep(path="/admin/users")
        result = enricher.enrich([ep])[0]
        assert "API5" in result.owasp_candidates

    def test_api5_absent_for_regular_endpoint(self, enricher: OpenAPIEnricher):
        ep = _ep(path="/users")
        result = enricher.enrich([ep])[0]
        assert "API5" not in result.owasp_candidates

    def test_api6_for_post_with_body(self, enricher: OpenAPIEnricher):
        ep = _ep(
            method="POST",
            body_schema={"type": "object", "properties": {"name": {"type": "string"}}},
        )
        result = enricher.enrich([ep])[0]
        assert "API6" in result.owasp_candidates

    def test_api6_absent_for_get(self, enricher: OpenAPIEnricher):
        ep = _ep(method="GET")
        result = enricher.enrich([ep])[0]
        assert "API6" not in result.owasp_candidates

    def test_api8_for_string_query_param(self, enricher: OpenAPIEnricher):
        ep = _ep(params=[{"name": "search", "in": "query", "type": "string", "required": False}])
        result = enricher.enrich([ep])[0]
        assert "API8" in result.owasp_candidates

    def test_api8_for_string_body_field(self, enricher: OpenAPIEnricher):
        ep = _ep(
            method="POST",
            body_schema={
                "type": "object",
                "properties": {"username": {"type": "string"}},
            },
        )
        result = enricher.enrich([ep])[0]
        assert "API8" in result.owasp_candidates

    def test_api8_absent_for_integer_only_inputs(self, enricher: OpenAPIEnricher):
        ep = _ep(
            params=[{"name": "limit", "in": "query", "type": "integer", "required": False}]
        )
        result = enricher.enrich([ep])[0]
        assert "API8" not in result.owasp_candidates


# ── Priority calculation ──────────────────────────────────────────────────── #

class TestPriority:
    def test_zero_hints_gives_priority_3(self, enricher: OpenAPIEnricher):
        # A bare GET endpoint with no security, no params, no body, no sensitive data
        # gives: no_auth_required (1 hint) → priority 3
        ep = _ep()
        result = enricher.enrich([ep])[0]
        assert result.suggested_priority == 3

    def test_two_hints_gives_priority_2(self, enricher: OpenAPIEnricher):
        # has_resource_id_param + auth_required = exactly 2 hints.
        # Use a string uuid param so sequential_id is NOT also triggered
        # (sequential_id requires integer type).
        ep = _ep(
            params=[{"name": "uuid", "in": "path", "type": "string", "required": True}],
            security=["apiKeyScheme"],  # non-bearer name → no API2 via jwt path
        )
        result = enricher.enrich([ep])[0]
        assert result.risk_hints == ["has_resource_id_param", "auth_required"]
        assert result.suggested_priority == 2

    def test_three_or_more_hints_gives_priority_1(self, enricher: OpenAPIEnricher):
        # has_resource_id_param + auth_required + returns_sensitive_data + sequential_id = 4 hints
        ep = _ep(
            params=[{"name": "user_id", "in": "path", "type": "integer", "required": True}],
            security=["bearerAuth"],
            response_schemas={
                "200": {
                    "type": "object",
                    "properties": {"email": {"type": "string"}, "password": {"type": "string"}},
                }
            },
        )
        result = enricher.enrich([ep])[0]
        assert result.suggested_priority == 1

    def test_priority_is_int(self, enricher: OpenAPIEnricher):
        ep = _ep()
        result = enricher.enrich([ep])[0]
        assert isinstance(result.suggested_priority, int)

    def test_priority_capped_at_3(self, enricher: OpenAPIEnricher):
        # Even with many hints, priority can't exceed 3 (which would be meaningless)
        # Actually 3 is the minimum urgency; the cap is 1 (highest urgency).
        # Verify it never goes below 1 or above 3.
        ep = _ep(
            params=[{"name": "user_id", "in": "path", "type": "integer", "required": True}],
            security=["bearerAuth"],
            response_schemas={
                "200": {
                    "type": "object",
                    "properties": {
                        "email": {"type": "string"},
                        "token": {"type": "string"},
                        "password": {"type": "string"},
                    },
                }
            },
            path="/admin/users",
            method="POST",
            body_schema={"type": "object", "properties": {"name": {"type": "string"}}},
        )
        result = enricher.enrich([ep])[0]
        assert 1 <= result.suggested_priority <= 3


# ── EnrichedEndpoint is a proper superset of EndpointInfo ────────────────── #

class TestEnrichedEndpointInheritance:
    def test_enriched_endpoint_is_endpoint_info(self, enricher: OpenAPIEnricher):
        from core.parser.openapi_parser import EndpointInfo
        ep = _ep()
        result = enricher.enrich([ep])[0]
        assert isinstance(result, EndpointInfo)

    def test_original_fields_preserved(self, enricher: OpenAPIEnricher):
        ep = _ep(
            path="/test",
            method="DELETE",
            params=[{"name": "id", "in": "path", "type": "string", "required": True}],
            tags=["test"],
            summary="Delete resource",
        )
        result = enricher.enrich([ep])[0]
        assert result.path == "/test"
        assert result.method == "DELETE"
        assert result.tags == ["test"]
        assert result.summary == "Delete resource"
