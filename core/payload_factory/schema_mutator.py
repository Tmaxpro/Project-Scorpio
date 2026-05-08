"""Helpers for mutating OpenAPI JSON schemas into test payloads."""
from __future__ import annotations

from typing import Any

_FUZZ_VALUES: dict[str, Any] = {
    "string": "test_value",
    "integer": 1,
    "number": 1.0,
    "boolean": True,
    "array": [],
    "object": {},
}


def get_string_fields(schema: dict | None) -> list[str]:
    """Return names of string-type top-level properties from a JSON schema."""
    if not schema or not isinstance(schema, dict):
        return []
    return [
        name
        for name, spec in schema.get("properties", {}).items()
        if isinstance(spec, dict) and spec.get("type") == "string"
    ]


def minimal_body(schema: dict | None) -> dict:
    """Build a minimal body dict from a JSON schema.

    Fills required fields if specified; otherwise fills all properties.
    """
    if not schema or not isinstance(schema, dict):
        return {}
    props = schema.get("properties", {})
    required: set[str] = set(schema.get("required", []))
    to_fill = set(props.keys()) if not required else required
    return {
        name: _FUZZ_VALUES.get(
            props[name].get("type", "string") if isinstance(props.get(name), dict) else "string",
            "test_value",
        )
        for name in to_fill
        if name in props
    }


def inject_fields(base_body: dict, extra_fields: dict) -> dict:
    """Return a shallow-copy of *base_body* with *extra_fields* merged in."""
    return {**base_body, **extra_fields}
