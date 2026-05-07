"""Nuclei template index for ARIA.

NOT a vector RAG — this is a deterministic, structured dict index that maps
OWASP categories to payloads and matchers extracted from Nuclei YAML templates.
Used by the PayloadFactory to source real-world attack payloads.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

logger = logging.getLogger(__name__)

# Maps each OWASP API category to the Nuclei tags that indicate relevance.
OWASP_TAG_MAP: dict[str, list[str]] = {
    "API1": ["bola", "idor", "broken-access-control"],
    "API2": ["jwt", "auth-bypass", "broken-auth", "authentication"],
    "API3": ["excessive-data-exposure", "info-leak"],
    "API4": ["rate-limit", "dos"],
    "API5": ["privilege-escalation", "auth-bypass"],
    "API6": ["mass-assignment"],
    "API7": ["security-misconfiguration", "default-credentials"],
    "API8": ["sqli", "nosqli", "injection", "xss", "ssti", "xxe"],
    "API9": ["api-discovery"],
    "API10": ["ssrf"],
}


@dataclass
class _ParsedTemplate:
    template_id: str
    tags: list[str]
    payloads: list[str] = field(default_factory=list)
    matchers: list[dict] = field(default_factory=list)


class NucleiIndex:
    """Structured index of Nuclei templates organised by OWASP category.

    Call ``index()`` once at startup, then use ``get_payloads()`` and
    ``get_matchers()`` in the PayloadFactory.  Returns empty lists when the
    templates directory is absent or empty — the system degrades gracefully.
    """

    def __init__(self, templates_dir: str) -> None:
        self._templates_dir = Path(templates_dir)
        self._payloads: dict[str, list[str]] = {cat: [] for cat in OWASP_TAG_MAP}
        self._matchers: dict[str, list[dict]] = {cat: [] for cat in OWASP_TAG_MAP}
        self._indexed = False

    # ── Public API ──────────────────────────────────────────────────────── #

    def index(self) -> None:
        """Walk *templates_dir*, parse all .yaml files, build category → data maps."""
        if not self._templates_dir.exists():
            logger.warning(
                "Nuclei templates directory not found: %s — using empty index.",
                self._templates_dir,
            )
            self._indexed = True
            return

        template_count = 0
        mapping_count = 0

        for yaml_path in sorted(self._templates_dir.rglob("*.yaml")):
            template = self._parse_template(yaml_path)
            if template is None:
                continue
            template_count += 1

            for category, tags in OWASP_TAG_MAP.items():
                if any(tag in template.tags for tag in tags):
                    self._payloads[category].extend(template.payloads)
                    self._matchers[category].extend(template.matchers)
                    mapping_count += 1

        # Deduplicate payloads while preserving order
        for cat in self._payloads:
            self._payloads[cat] = list(dict.fromkeys(self._payloads[cat]))

        logger.info(
            "NucleiIndex: parsed %d templates → %d category mappings from %s",
            template_count,
            mapping_count,
            self._templates_dir,
        )
        self._indexed = True

    def get_payloads(self, owasp_category: str) -> list[str]:
        """Return all payload strings associated with *owasp_category*."""
        if not self._indexed:
            self.index()
        return list(self._payloads.get(owasp_category, []))

    def get_matchers(self, owasp_category: str) -> list[dict]:
        """Return all matcher dicts associated with *owasp_category*."""
        if not self._indexed:
            self.index()
        return list(self._matchers.get(owasp_category, []))

    def categories_with_data(self) -> list[str]:
        """Return the OWASP categories that have at least one payload indexed."""
        if not self._indexed:
            self.index()
        return [cat for cat, payloads in self._payloads.items() if payloads]

    # ── Internal ──────────────────────────────────────────────────────────── #

    def _parse_template(self, yaml_path: Path) -> _ParsedTemplate | None:
        """Parse a single Nuclei YAML template; return None on any parse error."""
        try:
            with yaml_path.open(encoding="utf-8") as fh:
                data = yaml.safe_load(fh)
            if not isinstance(data, dict):
                return None

            template_id: str = data.get("id", yaml_path.stem)
            tags = self._extract_tags(data)
            if not tags:
                return None  # templates without tags can't map to any category

            payloads = self._extract_payloads(data)
            matchers = self._extract_matchers(data)

            return _ParsedTemplate(
                template_id=template_id,
                tags=tags,
                payloads=payloads,
                matchers=matchers,
            )
        except Exception as exc:  # noqa: BLE001
            logger.debug("Skipping unreadable Nuclei template %s: %s", yaml_path, exc)
            return None

    @staticmethod
    def _extract_tags(data: dict) -> list[str]:
        """Extract and normalise tags from the ``info`` section."""
        info = data.get("info", {})
        raw = info.get("tags", "")
        if isinstance(raw, str):
            return [t.strip().lower() for t in raw.split(",") if t.strip()]
        if isinstance(raw, list):
            return [str(t).strip().lower() for t in raw if str(t).strip()]
        return []

    @staticmethod
    def _extract_payloads(data: dict) -> list[str]:
        """Collect payload strings from ``requests`` and ``http`` sections."""
        results: list[str] = []
        for section_key in ("requests", "http"):
            for request in data.get(section_key, []):
                if not isinstance(request, dict):
                    continue
                # payloads: {name: [value, ...], ...}
                for payload_list in request.get("payloads", {}).values():
                    if isinstance(payload_list, list):
                        results.extend(str(p) for p in payload_list if p is not None)
        return results

    @staticmethod
    def _extract_matchers(data: dict) -> list[dict[str, Any]]:
        """Collect matcher dicts from ``requests`` and ``http`` sections."""
        results: list[dict] = []
        for section_key in ("requests", "http"):
            for request in data.get(section_key, []):
                if not isinstance(request, dict):
                    continue
                for matcher in request.get("matchers", []):
                    if isinstance(matcher, dict):
                        results.append(matcher)
        return results
