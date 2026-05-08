"""Shared data models for the payload factory."""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class PayloadRequest:
    """A single HTTP request to be executed by the HTTP engine."""

    task_id: str
    method: str
    path: str
    headers: dict[str, str] = field(default_factory=dict)
    body: dict | list | None = None
    query_params: dict[str, str] = field(default_factory=dict)
    strategy: str = ""
    label: str = ""
