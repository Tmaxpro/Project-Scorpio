"""Unit tests for core/parser/openapi_parser.py."""
from __future__ import annotations

import pytest

from core.parser.openapi_parser import EndpointInfo, OpenAPIParser

# ── Shared fixture YAML ───────────────────────────────────────────────────── #

PETSTORE_YAML = """
openapi: "3.0.3"
info:
  title: TestAPI
  version: "1.0.0"
paths:
  /users:
    get:
      operationId: listUsers
      tags: [users]
      summary: List all users
      parameters:
        - name: limit
          in: query
          schema:
            type: integer
      responses:
        "200":
          description: OK
          content:
            application/json:
              schema:
                type: array
                items:
                  $ref: '#/components/schemas/User'
    post:
      operationId: createUser
      tags: [users]
      summary: Create a user
      requestBody:
        required: true
        content:
          application/json:
            schema:
              $ref: '#/components/schemas/UserInput'
      responses:
        "201":
          description: Created

  /users/{user_id}:
    parameters:
      - name: user_id
        in: path
        required: true
        schema:
          type: integer
    get:
      operationId: getUser
      tags: [users]
      summary: Get user by ID
      security:
        - bearerAuth: []
      responses:
        "200":
          description: OK
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/User'
    put:
      operationId: updateUser
      tags: [users]
      summary: Update user
      security:
        - bearerAuth: []
      requestBody:
        required: true
        content:
          application/json:
            schema:
              $ref: '#/components/schemas/UserInput'
      responses:
        "200":
          description: OK

  /admin/settings:
    get:
      operationId: getAdminSettings
      tags: [admin]
      summary: Get admin settings
      security:
        - bearerAuth: []
      responses:
        "200":
          description: OK

components:
  schemas:
    User:
      type: object
      properties:
        id:
          type: integer
        email:
          type: string
        password:
          type: string
    UserInput:
      type: object
      properties:
        name:
          type: string
        email:
          type: string
  securitySchemes:
    bearerAuth:
      type: http
      scheme: bearer
      bearerFormat: JWT
"""


@pytest.fixture()
def parser() -> OpenAPIParser:
    p = OpenAPIParser()
    p.parse(PETSTORE_YAML)
    return p


@pytest.fixture()
def endpoints(parser: OpenAPIParser) -> list[EndpointInfo]:
    return parser.get_endpoints()


# ── parse() ───────────────────────────────────────────────────────────────── #

class TestParse:
    def test_returns_dict(self):
        p = OpenAPIParser()
        result = p.parse(PETSTORE_YAML)
        assert isinstance(result, dict)
        assert "paths" in result

    def test_malformed_yaml_raises_value_error(self):
        with pytest.raises(ValueError, match="Invalid YAML"):
            OpenAPIParser().parse("key: [unclosed")

    def test_missing_paths_raises_value_error(self):
        with pytest.raises(ValueError, match="paths"):
            OpenAPIParser().parse("openapi: '3.0.0'\ninfo:\n  title: X\n  version: '1.0'")

    def test_swagger_2x_raises_value_error(self):
        swagger = "swagger: '2.0'\ninfo:\n  title: X\n  version: '1.0'\npaths: {}"
        with pytest.raises(ValueError, match="Swagger 2.x"):
            OpenAPIParser().parse(swagger)

    def test_non_mapping_raises_value_error(self):
        with pytest.raises(ValueError, match="mapping"):
            OpenAPIParser().parse("- item1\n- item2")

    def test_get_endpoints_before_parse_raises(self):
        with pytest.raises(RuntimeError):
            OpenAPIParser().get_endpoints()


# ── get_endpoints() — counts and fields ──────────────────────────────────── #

class TestGetEndpoints:
    def test_correct_endpoint_count(self, endpoints: list[EndpointInfo]):
        # /users GET, /users POST, /users/{user_id} GET, PUT, /admin/settings GET = 5
        assert len(endpoints) == 5

    def test_all_paths_present(self, endpoints: list[EndpointInfo]):
        paths = {ep.path for ep in endpoints}
        assert "/users" in paths
        assert "/users/{user_id}" in paths
        assert "/admin/settings" in paths

    def test_methods_uppercase(self, endpoints: list[EndpointInfo]):
        assert all(ep.method == ep.method.upper() for ep in endpoints)

    def test_expected_methods_present(self, endpoints: list[EndpointInfo]):
        method_pairs = {(ep.path, ep.method) for ep in endpoints}
        assert ("/users", "GET") in method_pairs
        assert ("/users", "POST") in method_pairs
        assert ("/users/{user_id}", "GET") in method_pairs
        assert ("/users/{user_id}", "PUT") in method_pairs
        assert ("/admin/settings", "GET") in method_pairs

    def test_tags_extracted(self, endpoints: list[EndpointInfo]):
        admin_ep = next(ep for ep in endpoints if ep.path == "/admin/settings")
        assert "admin" in admin_ep.tags

    def test_summary_extracted(self, endpoints: list[EndpointInfo]):
        list_ep = next(ep for ep in endpoints if ep.path == "/users" and ep.method == "GET")
        assert list_ep.summary == "List all users"


# ── Parameter extraction ──────────────────────────────────────────────────── #

class TestParams:
    def test_query_param_extracted(self, endpoints: list[EndpointInfo]):
        list_ep = next(ep for ep in endpoints if ep.path == "/users" and ep.method == "GET")
        names = [p["name"] for p in list_ep.params]
        assert "limit" in names

    def test_query_param_type(self, endpoints: list[EndpointInfo]):
        list_ep = next(ep for ep in endpoints if ep.path == "/users" and ep.method == "GET")
        limit = next(p for p in list_ep.params if p["name"] == "limit")
        assert limit["type"] == "integer"
        assert limit["in"] == "query"

    def test_path_level_param_inherited_by_get(self, endpoints: list[EndpointInfo]):
        get_ep = next(
            ep for ep in endpoints if ep.path == "/users/{user_id}" and ep.method == "GET"
        )
        names = [p["name"] for p in get_ep.params]
        assert "user_id" in names

    def test_path_level_param_inherited_by_put(self, endpoints: list[EndpointInfo]):
        put_ep = next(
            ep for ep in endpoints if ep.path == "/users/{user_id}" and ep.method == "PUT"
        )
        names = [p["name"] for p in put_ep.params]
        assert "user_id" in names

    def test_path_param_required(self, endpoints: list[EndpointInfo]):
        get_ep = next(
            ep for ep in endpoints if ep.path == "/users/{user_id}" and ep.method == "GET"
        )
        user_id_param = next(p for p in get_ep.params if p["name"] == "user_id")
        assert user_id_param["required"] is True
        assert user_id_param["in"] == "path"

    def test_path_param_type_integer(self, endpoints: list[EndpointInfo]):
        get_ep = next(
            ep for ep in endpoints if ep.path == "/users/{user_id}" and ep.method == "GET"
        )
        user_id_param = next(p for p in get_ep.params if p["name"] == "user_id")
        assert user_id_param["type"] == "integer"

    def test_no_header_or_cookie_params_in_output(self, endpoints: list[EndpointInfo]):
        for ep in endpoints:
            for p in ep.params:
                assert p["in"] in ("path", "query")


# ── Body schema extraction ────────────────────────────────────────────────── #

class TestBodySchema:
    def test_post_has_body_schema(self, endpoints: list[EndpointInfo]):
        post_ep = next(ep for ep in endpoints if ep.path == "/users" and ep.method == "POST")
        assert post_ep.body_schema is not None

    def test_get_has_no_body(self, endpoints: list[EndpointInfo]):
        get_ep = next(ep for ep in endpoints if ep.path == "/users" and ep.method == "GET")
        assert get_ep.body_schema is None

    def test_body_schema_ref_resolved(self, endpoints: list[EndpointInfo]):
        post_ep = next(ep for ep in endpoints if ep.path == "/users" and ep.method == "POST")
        # $ref to UserInput should be resolved
        assert "$ref" not in str(post_ep.body_schema)
        assert "properties" in post_ep.body_schema

    def test_body_schema_contains_expected_fields(self, endpoints: list[EndpointInfo]):
        post_ep = next(ep for ep in endpoints if ep.path == "/users" and ep.method == "POST")
        props = post_ep.body_schema.get("properties", {})
        assert "name" in props
        assert "email" in props


# ── Response schema extraction ────────────────────────────────────────────── #

class TestResponseSchemas:
    def test_get_user_has_200_schema(self, endpoints: list[EndpointInfo]):
        get_ep = next(
            ep for ep in endpoints if ep.path == "/users/{user_id}" and ep.method == "GET"
        )
        assert "200" in get_ep.response_schemas

    def test_response_schema_ref_resolved(self, endpoints: list[EndpointInfo]):
        get_ep = next(
            ep for ep in endpoints if ep.path == "/users/{user_id}" and ep.method == "GET"
        )
        schema = get_ep.response_schemas["200"]
        assert "$ref" not in str(schema)
        assert "properties" in schema

    def test_response_schema_contains_expected_fields(self, endpoints: list[EndpointInfo]):
        get_ep = next(
            ep for ep in endpoints if ep.path == "/users/{user_id}" and ep.method == "GET"
        )
        props = get_ep.response_schemas["200"].get("properties", {})
        assert "email" in props
        assert "password" in props

    def test_array_response_ref_resolved(self, endpoints: list[EndpointInfo]):
        list_ep = next(ep for ep in endpoints if ep.path == "/users" and ep.method == "GET")
        # The 200 response is an array of User — $ref inside items should resolve
        schema = list_ep.response_schemas.get("200", {})
        assert "$ref" not in str(schema)

    def test_no_response_schema_when_no_content(self, endpoints: list[EndpointInfo]):
        # /admin/settings 200 has no content block
        admin_ep = next(ep for ep in endpoints if ep.path == "/admin/settings")
        assert admin_ep.response_schemas == {}


# ── Security extraction ───────────────────────────────────────────────────── #

class TestSecurity:
    def test_secured_endpoint_has_scheme(self, endpoints: list[EndpointInfo]):
        get_ep = next(
            ep for ep in endpoints if ep.path == "/users/{user_id}" and ep.method == "GET"
        )
        assert "bearerAuth" in get_ep.security

    def test_unauthenticated_endpoint_has_empty_security(self, endpoints: list[EndpointInfo]):
        list_ep = next(ep for ep in endpoints if ep.path == "/users" and ep.method == "GET")
        assert list_ep.security == []

    def test_global_security_applied_when_no_operation_security(self):
        """Global security at spec root should propagate to operations that don't override."""
        yaml_with_global = """
openapi: "3.0.0"
info:
  title: X
  version: "1.0"
security:
  - globalKey: []
paths:
  /items:
    get:
      summary: List items
      responses:
        "200":
          description: OK
components:
  securitySchemes:
    globalKey:
      type: apiKey
      in: header
      name: X-API-Key
"""
        p = OpenAPIParser()
        p.parse(yaml_with_global)
        eps = p.get_endpoints()
        assert "globalKey" in eps[0].security

    def test_empty_operation_security_overrides_global(self):
        """An explicit ``security: []`` on an operation means no auth."""
        yaml_with_override = """
openapi: "3.0.0"
info:
  title: X
  version: "1.0"
security:
  - globalKey: []
paths:
  /public:
    get:
      summary: Public endpoint
      security: []
      responses:
        "200":
          description: OK
"""
        p = OpenAPIParser()
        p.parse(yaml_with_override)
        eps = p.get_endpoints()
        assert eps[0].security == []


# ── get_endpoint_detail() ─────────────────────────────────────────────────── #

class TestGetEndpointDetail:
    def test_returns_correct_endpoint(self, parser: OpenAPIParser):
        ep = parser.get_endpoint_detail("/users/{user_id}", "GET")
        assert ep.path == "/users/{user_id}"
        assert ep.method == "GET"

    def test_case_insensitive_method(self, parser: OpenAPIParser):
        ep = parser.get_endpoint_detail("/users/{user_id}", "get")
        assert ep.method == "GET"

    def test_raises_key_error_for_unknown(self, parser: OpenAPIParser):
        with pytest.raises(KeyError):
            parser.get_endpoint_detail("/nonexistent", "GET")
