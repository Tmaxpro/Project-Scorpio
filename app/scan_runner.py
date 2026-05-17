"""Top-level scan pipeline orchestrator for ARIA."""
from __future__ import annotations

import logging
from collections.abc import Awaitable, Callable
from typing import Any

from core.agents.auth_agent import AuthAgent
from core.agents.bola_agent import BOLAAgent
from core.agents.injection_agent import InjectionAgent
from core.agents.mass_assign_agent import MassAssignAgent
from core.agents.property_auth_agent import PropertyAuthAgent
from core.agents.rate_limit_agent import RateLimitAgent
from core.coordinator.coordinator import Coordinator
from core.coordinator.dispatcher import Dispatcher
from core.http_engine.auth_injector import AuthConfig, AuthInjector
from core.http_engine.client import HTTPEngineClient
from core.http_engine.rate_controller import RateController
from core.parser.enricher import OpenAPIEnricher
from core.parser.openapi_parser import OpenAPIParser
from core.payload_factory.factory import PayloadFactory
from core.payload_factory.nuclei_parser import NucleiPayloadAdapter
from core.rag.nuclei_index import NucleiIndex
from core.rag.owasp_rag import OWASPRag
from core.validator.rule_validator import RuleValidator, ValidationResult

logger = logging.getLogger(__name__)

_EventCB = Callable[[str, dict[str, Any]], Awaitable[None]]

_OWASP_REFS: dict[str, str] = {
    "API1":  "API1:2023 — Broken Object Level Authorization",
    "API2":  "API2:2023 — Broken Authentication",
    "API3":  "API3:2023 — Broken Object Property Level Authorization",
    "API4":  "API4:2023 — Unrestricted Resource Consumption",
    "API5":  "API5:2023 — Broken Function Level Authorization",
    "API6":  "API6:2023 — Unrestricted Access to Sensitive Business Flows",
    "API7":  "API7:2023 — Server Side Request Forgery",
    "API8":  "API8:2023 — Security Misconfiguration",
    "API9":  "API9:2023 — Improper Inventory Management",
    "API10": "API10:2023 — Unsafe Consumption of APIs",
}

_REMEDIATIONS: dict[str, str] = {
    "API1": "Validate object ownership for every request. Use indirect object references and enforce authorization at the data layer.",
    "API2": "Implement strong authentication (MFA, short-lived tokens). Rotate secrets. Enforce brute-force protection.",
    "API3": "Apply property-level authorization. Never expose or accept properties the caller is not allowed to read/write.",
    "API4": "Enforce rate limits, payload size caps, and resource quotas per user/key. Return 429 on excess.",
    "API5": "Check function-level permissions explicitly; do not rely on UI hiding. Deny by default.",
    "API6": "Identify sensitive business flows (checkout, invite, transfer) and add per-flow rate limits and bot detection.",
    "API7": "Validate and whitelist URLs/IPs before making outbound requests. Block internal IP ranges.",
    "API8": "Harden HTTP headers (CSP, HSTS, X-Frame-Options). Disable debug endpoints. Remove stack traces from error responses.",
    "API9": "Maintain an up-to-date API inventory. Retire unused endpoints. Document all versions.",
    "API10": "Validate and sanitise all data received from third-party APIs. Apply the same security standards to upstream APIs.",
}


class ScanRunner:
    """Orchestrates the full ARIA pipeline end-to-end."""

    def __init__(
        self,
        config_path: str = "config.yaml",
        chroma_dir: str = "./data/chroma",
        docs_dir: str = "./data/owasp",
        templates_dir: str = "./data/nuclei-templates",
    ) -> None:
        self._config_path = config_path
        self._chroma_dir = chroma_dir
        self._docs_dir = docs_dir
        self._templates_dir = templates_dir

    async def run(
        self,
        spec: str,
        target_url: str,
        auth_token: str = "",
        auth_type: str = "bearer",
        auth_header_name: str = "Authorization",
        owasp_filter: list[str] | None = None,
        max_payloads_per_endpoint: int = 20,
        context: str = "",
        scan_id: str | None = None,
        progress_cb: Callable[[float, str], None] | None = None,
        event_cb: _EventCB | None = None,
    ) -> list[ValidationResult]:
        async def _emit(event_type: str, data: dict[str, Any]) -> None:
            if event_cb:
                await event_cb(event_type, data)

        async def _p(progress: float, msg: str) -> None:
            logger.info("[%s] %.0f%% — %s", scan_id or "scan", progress * 100, msg)
            if progress_cb:
                progress_cb(progress, msg)
            await _emit("pipeline_phase", {"progress": progress, "message": msg})

        # ── 1. Parse + enrich ─────────────────────────────────────────────── #
        await _p(0.05, "Parsing OpenAPI spec...")
        parser = OpenAPIParser()
        parser.parse(spec)
        enriched = OpenAPIEnricher().enrich(parser.get_endpoints())
        await _p(0.10, f"Enriched {len(enriched)} endpoints")

        # ── 2. Knowledge base ─────────────────────────────────────────────── #
        await _p(0.15, "Loading knowledge base...")
        from app import state
        if state.owasp_rag is not None:
            owasp_rag = state.owasp_rag
        else:
            # Fallback: lifespan didn't run (e.g. tests) — create and cache on first scan
            owasp_rag = OWASPRag(persist_dir=self._chroma_dir)
            owasp_rag.index_documents(self._docs_dir)
            state.owasp_rag = owasp_rag
        nuclei_adapter = NucleiPayloadAdapter(NucleiIndex(self._templates_dir))

        # ── 3. Plan tasks (Coordinator) ───────────────────────────────────── #
        await _p(0.20, "Planning tasks with coordinator...")
        from core.llm.client import LLMClient
        llm = LLMClient(config_path=self._config_path, scan_id=scan_id)
        coordinator = Coordinator(llm=llm, rag=owasp_rag)
        tasks = await coordinator.plan(
            enriched_endpoints=enriched,
            context=context or "Automated ARIA scan",
            owasp_filter=owasp_filter or [],
        )
        await _p(0.30, f"Planned {len(tasks)} tasks")

        task_map = {t.task_id: t for t in tasks}

        # Announce total tasks and emit task_started events
        await _emit("scan_info", {"total_tasks": len(tasks)})
        for task in tasks:
            await _emit("task_started", {
                "task_id": task.task_id,
                "endpoint": task.target_endpoint,
                "method": task.method,
                "vuln_category": task.vuln_category,
                "agent": f"{task.vuln_category}-Agent",
            })

        # ── 4. Agent decisions (Dispatcher) ──────────────────────────────── #
        await _p(0.35, "Running attack agents...")
        agents = {
            "API1": BOLAAgent(llm, owasp_rag),
            "API2": AuthAgent(llm, owasp_rag),
            "API3": PropertyAuthAgent(llm, owasp_rag),
            "API4": RateLimitAgent(llm, owasp_rag),
            "API5": AuthAgent(llm, owasp_rag),
            "API6": MassAssignAgent(llm, owasp_rag),
            "API8": InjectionAgent(llm, owasp_rag),
        }
        endpoint_map = {(ep.path, ep.method): ep for ep in enriched}
        decisions = await Dispatcher(agents=agents, max_concurrent=3).dispatch(
            tasks, enriched
        )
        await _p(0.50, f"Got {len(decisions)} agent decisions")

        # ── 5. Build payloads ─────────────────────────────────────────────── #
        await _p(0.55, "Building payloads...")
        factory = PayloadFactory(nuclei_adapter)
        all_requests = []
        for decision in decisions:
            task = task_map.get(decision.task_id)
            if not task:
                continue
            endpoint = endpoint_map.get(
                (task.target_endpoint, task.method)
            ) or next(iter(endpoint_map.values()), None)
            if not endpoint:
                continue
            all_requests.extend(
                factory.build(task, decision, endpoint)[:max_payloads_per_endpoint]
            )
        await _p(0.60, f"Built {len(all_requests)} payload requests")

        # ── 6. HTTP execution ─────────────────────────────────────────────── #
        await _p(0.65, f"Sending {len(all_requests)} requests to {target_url}...")
        auth_cfg = _build_auth_config(
            auth_type=auth_type,
            auth_token=auth_token,
            auth_header_name=auth_header_name,
        )

        async def _on_http_result(r: Any) -> None:
            status = r.status_code if not r.error else "ERR"
            await _emit("http_request", {
                "method": r.request.method,
                "path": r.request.path,
                "status": status,
                "ms": round(r.response_time_ms),
                "error": r.error,
            })

        http_client = HTTPEngineClient(
            base_url=target_url,
            auth_injector=AuthInjector(auth_cfg),
            rate_controller=RateController(requests_per_second=10.0),
            timeout_s=10.0,
        )
        scan_results = await http_client.send_batch(all_requests, on_result=_on_http_result)
        await _p(0.85, f"Received {len(scan_results)} responses")

        # ── 7. Validate ───────────────────────────────────────────────────── #
        await _p(0.90, "Validating findings...")
        rule_validator = RuleValidator()
        validation_results: list[ValidationResult] = []
        total = len(scan_results)
        for i, result in enumerate(scan_results):
            checks = rule_validator.check(result)
            vr = rule_validator.build_result(result, checks)
            validation_results.append(vr)
            progress_val = 0.90 + (i + 1) / max(total, 1) * 0.09
            await _emit("task_completed", {
                "task_id": vr.task_id,
                "endpoint": vr.scan_result.request.path,
                "progress": round(progress_val * 100, 1),
            })
            if vr.is_vulnerable:
                task = task_map.get(vr.task_id)
                await _emit("finding", {
                    "finding": _vr_to_task_result(vr, task),
                })

        # Rate-limit batch check grouped by task
        rl_task_ids = {
            r.task_id
            for r in scan_results
            if r.request.strategy == "rate_limit_absence_check"
        }
        for tid in rl_task_ids:
            rl_batch = [r for r in scan_results if r.task_id == tid]
            if len(rl_batch) > 10:
                rl_check = rule_validator.check_rate_limit_batch(rl_batch)
                if rl_check.triggered:
                    first_vr = next(
                        (vr for vr in validation_results if vr.task_id == tid), None
                    )
                    if first_vr:
                        first_vr.rule_checks.append(rl_check)
                        if rl_check.severity in ("high", "medium"):
                            first_vr.is_vulnerable = True
                            task = task_map.get(tid)
                            await _emit("finding", {
                                "finding": _vr_to_task_result(first_vr, task),
                            })

        await _p(1.0, "Done")
        return validation_results


def _build_auth_config(
    auth_type: str,
    auth_token: str,
    auth_header_name: str = "Authorization",
) -> AuthConfig:
    if not auth_token:
        return AuthConfig(type="none")
    if auth_type in ("apikey", "api_key"):
        return AuthConfig(type="api_key", token=auth_token, header_name=auth_header_name or "X-Api-Key")
    if auth_type == "basic":
        return AuthConfig(type="basic", token=auth_token)
    # Default: bearer
    return AuthConfig(type="bearer", token=auth_token)


def _vr_to_task_result(vr: ValidationResult, task: object | None) -> dict[str, Any]:
    from datetime import datetime, timezone
    triggered = vr.triggered_checks()
    category = triggered[0].owasp_category if triggered else (
        getattr(task, "vuln_category", "API8") if task else "API8"
    )
    rule_count = len([c for c in vr.rule_checks if c.triggered])
    confidence = "high" if vr.confirmed_by_slm else ("medium" if rule_count > 1 else "low")
    req = vr.scan_result.request
    sr = vr.scan_result
    return {
        "task_id": vr.task_id,
        "vuln_category": category,
        "endpoint": req.path,
        "method": req.method,
        "finding": vr.is_vulnerable,
        "severity": vr.highest_severity(),
        "confidence": confidence,
        "evidence": {
            "request": {
                "method": req.method,
                "url": req.path,
                "headers": req.headers,
                "body": str(req.body) if req.body else None,
            },
            "response": {
                "status_code": sr.status_code,
                "headers": sr.response_headers,
                "body_excerpt": sr.response_body[:500],
                "elapsed_ms": sr.response_time_ms,
            },
        },
        "remediation": _REMEDIATIONS.get(category, "Review OWASP API Security Top 10 for remediation guidance."),
        "owasp_ref": _OWASP_REFS.get(category, category),
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
