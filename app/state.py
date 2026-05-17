"""Process-wide singletons shared across requests."""
from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from core.rag.owasp_rag import OWASPRag

# Populated by the lifespan handler in main.py — None until startup completes.
owasp_rag: "OWASPRag | None" = None
