"""Thin adapter over NucleiIndex for the PayloadFactory."""
from __future__ import annotations

from core.rag.nuclei_index import NucleiIndex


class NucleiPayloadAdapter:
    """Provides per-OWASP-category payloads and matchers from a NucleiIndex."""

    def __init__(self, nuclei_index: NucleiIndex) -> None:
        self._index = nuclei_index

    def get_payloads(self, category: str) -> list[str]:
        return self._index.get_payloads(category)

    def get_matchers(self, category: str) -> list[dict]:
        return self._index.get_matchers(category)
