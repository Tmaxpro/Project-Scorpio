"""OpenAPI 3.x YAML parser for ARIA.

Parses a spec string into typed EndpointInfo objects, resolving $ref pointers
so downstream components always work with plain dicts (no $ref in outputs).
"""
from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any

import yaml

logger = logging.getLogger(__name__)

_HTTP_METHODS = frozenset(
    {"get", "put", "post", "delete", "options", "head", "patch", "trace"}
)


@dataclass
class EndpointInfo:
    """Typed representation of a single API endpoint operation."""

    path: str
    method: str                  # uppercase, e.g. "GET"
    params: list[dict]           # path + query params: {name, in, type, required}
    body_schema: dict | None     # fully resolved JSON schema for the request body
    response_schemas: dict       # {status_code: resolved_schema}
    security: list[str]          # security scheme names required (empty = no auth)
    tags: list[str]
    summary: str


class OpenAPIParser:
    """Parse an OpenAPI 3.x YAML string into EndpointInfo objects.

    Usage::

        parser = OpenAPIParser()
        parser.parse(yaml_string)
        endpoints = parser.get_endpoints()
    """

    def __init__(self) -> None:
        self._spec: dict | None = None

    # ── Public API ──────────────────────────────────────────────────────── #

    def parse(self, yaml_str: str) -> dict:
        """Parse *yaml_str* and store the spec internally.

        Returns the raw parsed dict.
        Raises ValueError with a descriptive message on any structural error.
        """
        try:
            spec = yaml.safe_load(yaml_str)
        except yaml.YAMLError as exc:
            raise ValueError(f"Invalid YAML: {exc}") from exc

        if not isinstance(spec, dict):
            raise ValueError("OpenAPI spec must be a YAML mapping at the top level.")

        if "swagger" in spec:
            raise ValueError(
                "Swagger 2.x specs are not supported. Provide an OpenAPI 3.x spec."
            )

        if "paths" not in spec:
            raise ValueError("Missing required 'paths' field in OpenAPI spec.")

        self._spec = spec
        return spec

    def get_endpoints(self) -> list[EndpointInfo]:
        """Return all endpoint operations found in the parsed spec."""
        if self._spec is None:
            raise RuntimeError("Call parse() before get_endpoints().")

        endpoints: list[EndpointInfo] = []
        for path, path_item in self._spec.get("paths", {}).items():
            if not isinstance(path_item, dict):
                continue
            for method, operation in path_item.items():
                if method.lower() not in _HTTP_METHODS:
                    continue
                if not isinstance(operation, dict):
                    continue
                endpoints.append(
                    self._build_endpoint(path, method.upper(), operation, path_item)
                )
        return endpoints

    def get_endpoint_detail(self, path: str, method: str) -> EndpointInfo:
        """Return the EndpointInfo for a specific path + method combination.

        Raises KeyError if the combination is not found in the spec.
        """
        for ep in self.get_endpoints():
            if ep.path == path and ep.method == method.upper():
                return ep
        raise KeyError(f"Endpoint not found: {method.upper()} {path}")

    # ── Internal builders ───────────────────────────────────────────────── #

    def _build_endpoint(
        self, path: str, method: str, operation: dict, path_item: dict
    ) -> EndpointInfo:
        return EndpointInfo(
            path=path,
            method=method,
            params=self._extract_params(operation, path_item),
            body_schema=self._extract_body_schema(operation),
            response_schemas=self._extract_response_schemas(operation),
            security=self._extract_security(operation),
            tags=operation.get("tags", []),
            summary=operation.get("summary", ""),
        )

    def _extract_params(self, operation: dict, path_item: dict) -> list[dict]:
        """Merge path-level and operation-level parameters.

        Operation-level parameters override path-level ones for the same
        (name, in) combination.  Only path and query params are returned.
        """
        # Collect path-level params first, then operation-level (overrides)
        merged: dict[tuple[str, str], dict] = {}
        for raw in path_item.get("parameters", []):
            p = self._resolve_ref_shallow(raw)
            key = (p.get("name", ""), p.get("in", ""))
            merged[key] = p
        for raw in operation.get("parameters", []):
            p = self._resolve_ref_shallow(raw)
            key = (p.get("name", ""), p.get("in", ""))
            merged[key] = p

        result = []
        for p in merged.values():
            location = p.get("in", "")
            if location not in ("path", "query"):
                continue
            schema = p.get("schema", {})
            if isinstance(schema, dict) and "$ref" in schema:
                schema = self._follow_ref(schema["$ref"])
            result.append(
                {
                    "name": p.get("name", ""),
                    "in": location,
                    "type": schema.get("type", "string"),
                    "required": p.get("required", location == "path"),
                }
            )
        return result

    def _extract_body_schema(self, operation: dict) -> dict | None:
        """Extract and resolve the request body JSON schema, if any."""
        raw_body = operation.get("requestBody")
        if not raw_body:
            return None
        body = self._resolve_ref_shallow(raw_body)
        content = body.get("content", {})

        schema_holder = content.get("application/json") or next(
            iter(content.values()), None
        )
        if not schema_holder:
            return None

        schema = schema_holder.get("schema")
        return self._deep_resolve(schema) if schema else None

    def _extract_response_schemas(self, operation: dict) -> dict:
        """Extract and resolve response body JSON schemas keyed by status code."""
        result: dict[str, dict] = {}
        for status_code, raw_resp in operation.get("responses", {}).items():
            resp = self._resolve_ref_shallow(raw_resp)
            content = resp.get("content", {})
            schema_holder = content.get("application/json") or next(
                iter(content.values()), None
            )
            if schema_holder and "schema" in schema_holder:
                resolved = self._deep_resolve(schema_holder["schema"])
                if resolved:
                    result[str(status_code)] = resolved
        return result

    def _extract_security(self, operation: dict) -> list[str]:
        """Return the list of security scheme names required by this operation.

        Returns an empty list when the operation is explicitly unsecured
        (``security: []``) or when neither the operation nor the global spec
        defines any security requirement.
        """
        if "security" in operation:
            sec_list = operation["security"]
        else:
            sec_list = self._spec.get("security", []) if self._spec else []

        names: list[str] = []
        for req in sec_list:
            if isinstance(req, dict):
                names.extend(req.keys())
        return names

    # ── $ref resolution helpers ─────────────────────────────────────────── #

    def _follow_ref(self, ref: str) -> dict:
        """Follow a JSON Pointer ``#/a/b/c`` within the current spec."""
        if not ref.startswith("#/"):
            logger.debug("External $ref not supported, skipping: %s", ref)
            return {}
        parts = ref[2:].split("/")
        node: Any = self._spec
        for part in parts:
            part = part.replace("~1", "/").replace("~0", "~")
            if isinstance(node, dict) and part in node:
                node = node[part]
            else:
                logger.debug("$ref not found in spec: %s (missing part: %s)", ref, part)
                return {}
        return node if isinstance(node, dict) else {}

    def _resolve_ref_shallow(self, obj: Any) -> dict:
        """If *obj* is a ``{"$ref": "..."}`` dict, follow it; else return as-is."""
        if isinstance(obj, dict) and "$ref" in obj:
            return self._follow_ref(obj["$ref"])
        return obj if isinstance(obj, dict) else {}

    def _deep_resolve(self, obj: Any, _depth: int = 0) -> Any:
        """Recursively resolve all ``$ref`` pointers in a JSON schema tree.

        Stops at depth 10 to guard against circular references.
        """
        if _depth > 10:
            return obj
        if isinstance(obj, dict):
            if "$ref" in obj:
                resolved = self._follow_ref(obj["$ref"])
                return self._deep_resolve(resolved, _depth + 1)
            return {k: self._deep_resolve(v, _depth + 1) for k, v in obj.items()}
        if isinstance(obj, list):
            return [self._deep_resolve(item, _depth + 1) for item in obj]
        return obj
