"""Top-level scan pipeline orchestrator for ARIA."""
from __future__ import annotations

import asyncio
import logging
from collections.abc import Awaitable, Callable
from typing import Any

import yaml

from core.agents.api_consumption_agent import APIConsumptionAgent
from core.agents.auth_agent import AuthAgent
from core.agents.base_agent import AgentDecision
from core.agents.bola_agent import BOLAAgent
from core.agents.injection_agent import InjectionAgent
from core.agents.inventory_agent import InventoryAgent
from core.agents.mass_assign_agent import MassAssignAgent
from core.agents.property_auth_agent import PropertyAuthAgent
from core.agents.rate_limit_agent import RateLimitAgent
from core.agents.ssrf_agent import SSRFAgent
from core.coordinator.coordinator import Coordinator
from core.coordinator.task_builder import Task
from core.http_engine.auth_injector import AuthConfig, AuthInjector
from core.http_engine.client import HTTPEngineClient
from core.http_engine.rate_controller import RateController
from core.parser.enricher import OpenAPIEnricher
from core.parser.openapi_parser import OpenAPIParser
from core.payload_factory.factory import PayloadFactory
from core.payload_factory.schema_mutator import minimal_body
from core.payload_factory.nuclei_parser import NucleiPayloadAdapter
from core.rag.nuclei_index import NucleiIndex
from core.rag.owasp_rag import OWASPRag
from core.validator.rule_validator import RuleValidator, ValidationResult
from core.validator.severity_scorer import apply_contextual_severity
from core.validator.slm_validator import SLMValidator

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
        login_username: str = "",
        login_password: str = "",
        user2_token: str = "",
        user2_login_username: str = "",
        user2_login_password: str = "",
        owasp_filter: list[str] | None = None,
        max_payloads_per_endpoint: int = 20,
        context: str = "",
        scan_id: str | None = None,
        scan_mode: str = "fast",
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

        with open(self._config_path) as fh:
            cfg = yaml.safe_load(fh)
        max_slots: int = cfg.get("scan", {}).get("max_concurrent_http_slots", 5)

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

        # ── 3. Auto-login (both users) before planning so coordinator has real tokens ─ #
        login_path = _detect_login_endpoint(enriched)

        if login_username and login_password and login_path:
            await _p(0.20, f"Authenticating as {login_username}…")
            fresh = await _auto_login(target_url, login_path, login_username, login_password)
            if fresh:
                auth_token = fresh
                logger.info("Auto-login succeeded — fresh token acquired.")
            else:
                logger.warning("Auto-login failed — proceeding with original token.")

        if user2_login_username and user2_login_password and login_path:
            await _p(0.22, f"Authenticating second user {user2_login_username}…")
            fresh2 = await _auto_login(target_url, login_path, user2_login_username, user2_login_password)
            if fresh2:
                user2_token = fresh2
                logger.info("User2 auto-login succeeded — victim token acquired.")
            else:
                logger.warning("User2 auto-login failed — BOLA cross-user tests will be skipped.")

        # Build credentials dict — passed to coordinator so the LLM and rule-based
        # fallback can resolve path parameters to concrete values.
        creds_dict: dict[str, str] = {}
        if login_username:
            creds_dict["username"] = login_username
            creds_dict["user"] = login_username
        if auth_token:
            creds_dict["auth_token"] = auth_token
            creds_dict["user1_token"] = auth_token
        if user2_token:
            creds_dict["user2_token"] = user2_token
        if user2_login_username:
            creds_dict["user2_username"] = user2_login_username
            creds_dict["user2_user"] = user2_login_username

        # ── 4. Plan tasks (Coordinator) ───────────────────────────────────── #
        await _p(0.25, "Planning tasks with coordinator...")
        from core.llm.client import LLMClient
        llm = LLMClient(config_path=self._config_path, scan_id=scan_id, scan_mode=scan_mode)
        llm.set_event_cb(_emit)
        coordinator = Coordinator(llm=llm, rag=owasp_rag)
        tasks = await coordinator.plan(
            enriched_endpoints=enriched,
            context=context or "Automated ARIA scan",
            owasp_filter=owasp_filter or [],
            credentials=creds_dict,
        )
        await _p(0.35, f"Planned {len(tasks)} tasks")

        task_map = {t.task_id: t for t in tasks}
        endpoint_map = {(ep.path, ep.method.upper()): ep for ep in enriched}

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

        # ── 5-8. Streaming per-task pipeline ─────────────────────────────── #
        await _p(0.38, f"Starting {scan_mode} scan pipeline ({len(tasks)} tasks, {max_slots} slots)...")

        agents = {
            "API1":  BOLAAgent(llm, owasp_rag),
            "API2":  AuthAgent(llm, owasp_rag),
            "API3":  PropertyAuthAgent(llm, owasp_rag),
            "API4":  RateLimitAgent(llm, owasp_rag),
            "API5":  AuthAgent(llm, owasp_rag),
            "API6":  MassAssignAgent(llm, owasp_rag),
            "API7":  SSRFAgent(llm, owasp_rag),
            "API8":  InjectionAgent(llm, owasp_rag),
            "API9":  InventoryAgent(llm, owasp_rag),
            "API10": APIConsumptionAgent(llm, owasp_rag),
        }

        # Give the auth agent the real token so JWT forge uses real claims
        if auth_token:
            for key in ("API2", "API5"):
                a = agents.get(key)
                if a:
                    a.set_auth_token(auth_token)

        auth_cfg = _build_auth_config(
            auth_type=auth_type,
            auth_token=auth_token,
            auth_header_name=auth_header_name,
            other_user_token=user2_token,
        )
        http_client = HTTPEngineClient(
            base_url=target_url,
            auth_injector=AuthInjector(auth_cfg),
            rate_controller=RateController(requests_per_second=10.0),
            timeout_s=10.0,
        )
        # Build known_values from credentials so path params use real usernames
        known_values: dict[str, str] = {}
        if login_username:
            known_values["username"] = login_username
            known_values["user"] = login_username
        factory = PayloadFactory(nuclei_adapter, known_values=known_values)
        rule_validator = RuleValidator()
        slm_validator = SLMValidator(llm)

        semaphore = asyncio.Semaphore(max_slots)
        all_scan_results: list[Any] = []
        total_tasks = len(tasks)
        completed = [0]

        async def run_task(task: Task) -> list[ValidationResult]:
            async with semaphore:
                try:
                    agent = agents.get(task.vuln_category)
                    ep = endpoint_map.get((task.target_endpoint, task.method.upper()))
                    if ep is None:
                        ep = next(iter(endpoint_map.values()), None)
                    if ep is None:
                        return []

                    # ── Step 1: Baseline probe ──────────────────────────── #
                    # Send one authenticated request to the first resolved URL
                    # BEFORE asking the agent, so the LLM can adapt its strategy
                    # based on what the API actually returns.
                    baseline_result = None
                    baseline_url = _pick_baseline_url(task)
                    if baseline_url:
                        from core.payload_factory.models import PayloadRequest as _PR
                        _baseline_body = task.valid_body
                        if _baseline_body is None and ep is not None and ep.body_schema:
                            _baseline_body = minimal_body(ep.body_schema) or None
                        baseline_req = _PR(
                            task_id=task.task_id,
                            method=task.method,
                            path=baseline_url,
                            headers={},
                            body=_baseline_body,
                            query_params={},
                            strategy="baseline",
                            label="baseline",
                        )
                        baseline_result = await http_client.send(baseline_req)
                        await _emit("http_request", {
                            "method": baseline_result.request.method,
                            "path": baseline_result.request.path,
                            "status": baseline_result.status_code if not baseline_result.error else "ERR",
                            "ms": round(baseline_result.response_time_ms),
                            "label": "baseline",
                        })
                        logger.info(
                            "Baseline [%s] %s %s → %s",
                            task.task_id, task.method, baseline_url,
                            baseline_result.status_code if not baseline_result.error else f"ERR:{baseline_result.error}",
                        )

                    # ── Step 2: Agent decision with baseline context ──────── #
                    if agent:
                        decision = await agent.analyze(task, ep, baseline_result=baseline_result)
                    else:
                        decision = AgentDecision(
                            task_id=task.task_id,
                            chosen_strategies=[task.strategy],
                            payload_config={},
                            use_exploit_module=None,
                            reasoning="no agent for category",
                        )

                    # ── Step 2.5: Discover victim resources for BOLA ─────── #
                    # When the coordinator flagged requires_victim_resources, call
                    # the discovery endpoint with the VICTIM's token to get their
                    # actual resource IDs, then test those URLs with the ATTACKER's
                    # token (standard auth injector — no special headers needed).
                    victim_resource_payloads: list[Any] = []
                    if (
                        getattr(task, "requires_victim_resources", False)
                        and getattr(task, "victim_token_key", None)
                        and getattr(task, "resource_discovery_endpoint", None)
                    ):
                        victim_token_val = creds_dict.get(task.victim_token_key, "")
                        if victim_token_val:
                            discovery_url = (
                                f"{target_url.rstrip('/')}"
                                f"{task.resource_discovery_endpoint}"
                            )
                            victim_urls = await _discover_victim_resources(
                                discovery_endpoint=discovery_url,
                                victim_token=victim_token_val,
                                id_field=task.resource_id_field,
                                endpoint_template=task.target_endpoint,
                            )
                            if victim_urls:
                                logger.info(
                                    "BOLA discovery [%s]: %d victim resources found → %s",
                                    task.task_id, len(victim_urls), victim_urls[:3],
                                )
                                await _emit("bola_discovery", {
                                    "task_id": task.task_id,
                                    "victim_resources": victim_urls,
                                    "count": len(victim_urls),
                                })
                                from core.payload_factory.models import PayloadRequest as _PR3
                                for v_url in victim_urls:
                                    victim_resource_payloads.append(_PR3(
                                        task_id=task.task_id,
                                        method=task.method,
                                        path=v_url,
                                        headers={},
                                        body=task.valid_body,
                                        query_params={},
                                        strategy="bola_victim_resource",
                                        label=f"bola_victim:{v_url}",
                                    ))

                    # ── Step 3: Factory-based attack payloads ─────────────── #
                    # Victim resource payloads are prepended so they're not
                    # crowded out by generic enumeration payloads when capped.
                    factory_payloads = factory.build(task, decision, ep)
                    payloads = (victim_resource_payloads + factory_payloads)[:max_payloads_per_endpoint]

                    async def _on_http_result(r: Any) -> None:
                        status = r.status_code if not r.error else "ERR"
                        await _emit("http_request", {
                            "method": r.request.method,
                            "path": r.request.path,
                            "status": status,
                            "ms": round(r.response_time_ms),
                            "error": r.error,
                        })

                    task_scan_results = await http_client.send_batch(payloads, on_result=_on_http_result)
                    all_scan_results.extend(task_scan_results)

                    # ── Step 4: Additional URLs suggested by the agent ────── #
                    # The agent may suggest extra paths to probe based on the
                    # baseline response (e.g. sibling objects, admin variants).
                    if decision.additional_test_urls:
                        from core.payload_factory.models import PayloadRequest as _PR2
                        extra_payloads = []
                        for extra_url in decision.additional_test_urls[:5]:
                            bodies = [task.valid_body] + decision.request_bodies[:3]
                            for body in bodies:
                                extra_payloads.append(_PR2(
                                    task_id=task.task_id,
                                    method=task.method,
                                    path=extra_url,
                                    headers={},
                                    body=body,
                                    query_params={},
                                    strategy=decision.chosen_strategies[0] if decision.chosen_strategies else task.strategy,
                                    label=f"agent_suggested:{extra_url}",
                                ))
                        if extra_payloads:
                            extra_results = await http_client.send_batch(extra_payloads, on_result=_on_http_result)
                            task_scan_results = task_scan_results + extra_results
                            all_scan_results.extend(extra_results)

                    # ── Step 5: Validate all results ──────────────────────── #
                    task_vrs: list[ValidationResult] = []
                    for result in task_scan_results:
                        vr, needs_slm = rule_validator.validate(
                            result,
                            baseline_result=baseline_result,
                            interpretation_rules=decision.interpretation_rules,
                        )
                        apply_contextual_severity(vr, ep)

                        if needs_slm:
                            confirmed, reasoning = await slm_validator.confirm(
                                result, vr.rule_checks, task
                            )
                            vr.confirmed_by_slm = confirmed
                            vr.slm_reasoning = reasoning
                            if confirmed and not vr.is_vulnerable:
                                vr.is_vulnerable = True
                            elif not confirmed and vr.is_vulnerable:
                                vr.is_vulnerable = False

                        task_vrs.append(vr)
                        if vr.is_vulnerable:
                            await _emit("finding", {
                                "finding": _vr_to_task_result(vr, task),
                            })

                    completed[0] += 1
                    progress_val = 0.38 + (completed[0] / max(total_tasks, 1)) * 0.57
                    await _emit("task_completed", {
                        "task_id": task.task_id,
                        "endpoint": task.target_endpoint,
                        "progress": round(progress_val * 100, 1),
                    })
                    return task_vrs

                except Exception as exc:  # noqa: BLE001
                    logger.error("Task %s failed: %s", task.task_id, exc)
                    completed[0] += 1
                    return []

        batches = await asyncio.gather(*[run_task(t) for t in tasks])
        validation_results: list[ValidationResult] = [vr for batch in batches for vr in batch]

        # Rate-limit batch check grouped by task
        rl_task_ids = {
            r.task_id
            for r in all_scan_results
            if r.request.strategy == "rate_limit_absence_check"
        }
        for tid in rl_task_ids:
            rl_batch = [r for r in all_scan_results if r.task_id == tid]
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
                            task_obj = task_map.get(tid)
                            await _emit("finding", {
                                "finding": _vr_to_task_result(first_vr, task_obj),
                            })

        await _p(1.0, "Done")
        return validation_results


def _build_auth_config(
    auth_type: str,
    auth_token: str,
    auth_header_name: str = "Authorization",
    other_user_token: str = "",
) -> AuthConfig:
    if not auth_token:
        return AuthConfig(type="none", other_user_token=other_user_token)
    if auth_type in ("apikey", "api_key"):
        return AuthConfig(type="api_key", token=auth_token, header_name=auth_header_name or "X-Api-Key", other_user_token=other_user_token)
    if auth_type == "basic":
        return AuthConfig(type="basic", token=auth_token, other_user_token=other_user_token)
    # Default: bearer
    return AuthConfig(type="bearer", token=auth_token, other_user_token=other_user_token)


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


# ── BOLA victim resource discovery ───────────────────────────────────────────

async def _discover_victim_resources(
    discovery_endpoint: str,
    victim_token: str,
    id_field: str | None,
    endpoint_template: str,
    timeout_s: float = 8.0,
) -> list[str]:
    """Call the victim's list endpoint, extract resource IDs, return resolved URLs.

    Uses the victim's token to fetch their resource list, then builds concrete
    paths the ATTACKER can try. Works on any REST API — no app-specific logic.

    Args:
        discovery_endpoint: full URL of the collection endpoint (e.g. http://host/books/v1)
        victim_token:        Bearer token belonging to the victim account
        id_field:            JSON key that holds the resource identifier (e.g. "book_title")
        endpoint_template:   path template with {placeholder} (e.g. /books/v1/{book_title})
        timeout_s:           HTTP timeout for the discovery request
    """
    import httpx
    import re as _re

    _ph = _re.compile(r"\{([^}]+)\}")

    try:
        async with httpx.AsyncClient(timeout=timeout_s) as client:
            resp = await client.get(
                discovery_endpoint,
                headers={"Authorization": f"Bearer {victim_token}"},
            )
        if resp.status_code != 200:
            logger.debug(
                "BOLA discovery: %s returned %d — skipping", discovery_endpoint, resp.status_code
            )
            return []
        data = resp.json()
    except Exception as exc:  # noqa: BLE001
        logger.debug("BOLA discovery request failed: %s", exc)
        return []

    # Recursively extract all values for id_field (or heuristic ID fields)
    identifiers: list[str] = []
    _ID_CANDIDATES = ("id", "uuid", "slug", "name", "title", "username", "key", "ref")

    def _extract(obj: Any) -> None:
        if isinstance(obj, dict):
            if id_field and id_field in obj and obj[id_field] is not None:
                identifiers.append(str(obj[id_field]))
            elif not id_field:
                for candidate in _ID_CANDIDATES:
                    if candidate in obj and obj[candidate]:
                        identifiers.append(str(obj[candidate]))
                        break
            for v in obj.values():
                if isinstance(v, (dict, list)):
                    _extract(v)
        elif isinstance(obj, list):
            for item in obj:
                _extract(item)

    _extract(data)

    if not identifiers:
        logger.debug("BOLA discovery: no identifiers found in response from %s", discovery_endpoint)
        return []

    # Find the first {placeholder} in the template and substitute identifiers
    match = _ph.search(endpoint_template)
    if not match:
        return []

    placeholder = match.group(0)   # e.g. "{book_title}"
    resolved: list[str] = []
    seen: set[str] = set()
    for ident in identifiers:
        url = endpoint_template.replace(placeholder, str(ident), 1)
        # Resolve any remaining placeholders with the placeholder name itself
        url = _ph.sub(lambda m: m.group(1).replace("_", "-"), url)
        if url not in seen:
            resolved.append(url)
            seen.add(url)

    return resolved[:10]   # cap: avoid excessive requests


# ── Baseline URL helper ───────────────────────────────────────────────────────

def _pick_baseline_url(task: object) -> str:
    """Return the first concrete URL to use as a baseline probe.

    Prefers task.resolved_test_urls[0]; falls back to task.target_endpoint with
    any remaining {placeholder} stripped to a plain string so we never send a
    literal brace in an HTTP request.
    """
    import re as _re
    resolved = getattr(task, "resolved_test_urls", [])
    if resolved:
        return resolved[0]
    template: str = getattr(task, "target_endpoint", "")
    # Replace any leftover {placeholder} with the placeholder name itself
    return _re.sub(r"\{([^}]+)\}", lambda m: m.group(1).replace("_", "-"), template)


# ── Auto-login helpers ────────────────────────────────────────────────────────

def _detect_login_endpoint(endpoints: list) -> str:
    """Return the path of a POST endpoint whose path contains 'login', or ''."""
    for ep in endpoints:
        if ep.method.upper() == "POST" and "login" in ep.path.lower():
            return ep.path
    return ""


async def _auto_login(base_url: str, login_path: str, username: str, password: str) -> str:
    """POST credentials to the login endpoint and return the auth token, or ''."""
    import httpx
    url = f"{base_url.rstrip('/')}{login_path}"
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            r = await client.post(url, json={"username": username, "password": password})
        if r.status_code in (200, 201):
            data = r.json()
            for key in ("auth_token", "access_token", "token", "jwt"):
                if isinstance(data.get(key), str) and data[key]:
                    return data[key]
            nested = data.get("data") or data.get("result") or {}
            if isinstance(nested, dict):
                for key in ("auth_token", "access_token", "token", "jwt"):
                    if isinstance(nested.get(key), str) and nested[key]:
                        return nested[key]
    except Exception as exc:  # noqa: BLE001
        logger.warning("Auto-login to %s failed: %s", url, exc)
    return ""
