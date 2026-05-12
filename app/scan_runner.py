"""Top-level scan pipeline orchestrator for ARIA."""
from __future__ import annotations

import logging
from typing import Callable

from core.agents.auth_agent import AuthAgent
from core.agents.bola_agent import BOLAAgent
from core.agents.injection_agent import InjectionAgent
from core.agents.mass_assign_agent import MassAssignAgent
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

_ProgressCB = Callable[[float, str], None]


class ScanRunner:
    """Orchestrates the full ARIA pipeline end-to-end.

    Each component degrades gracefully: if Ollama is not running the
    coordinator falls back to rule-based task planning and agents use their
    deterministic default decisions.
    """

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
        owasp_filter: list[str] | None = None,
        max_payloads_per_endpoint: int = 20,
        scan_id: str | None = None,
        progress_cb: _ProgressCB | None = None,
    ) -> list[ValidationResult]:
        def _p(progress: float, msg: str) -> None:
            logger.info("[%s] %.0f%% — %s", scan_id or "scan", progress * 100, msg)
            if progress_cb:
                progress_cb(progress, msg)

        # ── 1. Parse + enrich ────────────────────────────────────────────── #
        _p(0.05, "Parsing OpenAPI spec...")
        parser = OpenAPIParser()
        parser.parse(spec)
        enriched = OpenAPIEnricher().enrich(parser.get_endpoints())
        _p(0.10, f"Enriched {len(enriched)} endpoints")

        # ── 2. Knowledge base ────────────────────────────────────────────── #
        _p(0.15, "Loading knowledge base...")
        owasp_rag = OWASPRag(persist_dir=self._chroma_dir)
        owasp_rag.index_documents(self._docs_dir)
        nuclei_adapter = NucleiPayloadAdapter(NucleiIndex(self._templates_dir))

        # ── 3. Plan tasks (Coordinator) ──────────────────────────────────── #
        _p(0.20, "Planning tasks with coordinator...")
        from core.llm.client import LLMClient
        llm = LLMClient(config_path=self._config_path, scan_id=scan_id)
        coordinator = Coordinator(llm=llm, rag=owasp_rag)
        tasks = await coordinator.plan(
            enriched_endpoints=enriched,
            context="Automated ARIA scan",
            owasp_filter=owasp_filter or [],
        )
        _p(0.30, f"Planned {len(tasks)} tasks")

        # ── 4. Agent decisions (Dispatcher) ──────────────────────────────── #
        _p(0.35, "Running attack agents...")
        agents = {
            "API1": BOLAAgent(llm, owasp_rag),
            "API2": AuthAgent(llm, owasp_rag),
            "API4": RateLimitAgent(llm, owasp_rag),
            "API5": AuthAgent(llm, owasp_rag),
            "API6": MassAssignAgent(llm, owasp_rag),
            "API8": InjectionAgent(llm, owasp_rag),
        }
        endpoint_map = {(ep.path, ep.method): ep for ep in enriched}
        decisions = await Dispatcher(agents=agents, max_concurrent=3).dispatch(
            tasks, endpoint_map
        )
        task_map = {t.task_id: t for t in tasks}
        _p(0.50, f"Got {len(decisions)} agent decisions")

        # ── 5. Build payloads ─────────────────────────────────────────────── #
        _p(0.55, "Building payloads...")
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
        _p(0.60, f"Built {len(all_requests)} payload requests")

        # ── 6. HTTP execution ─────────────────────────────────────────────── #
        _p(0.65, f"Sending {len(all_requests)} requests to {target_url}...")
        auth_cfg = (
            AuthConfig(type="bearer", token=auth_token)
            if auth_token
            else AuthConfig(type="none")
        )
        http_client = HTTPEngineClient(
            base_url=target_url,
            auth_injector=AuthInjector(auth_cfg),
            rate_controller=RateController(requests_per_second=10.0),
            timeout_s=10.0,
        )
        scan_results = await http_client.send_batch(all_requests)
        _p(0.85, f"Received {len(scan_results)} responses")

        # ── 7. Validate ───────────────────────────────────────────────────── #
        _p(0.90, "Validating findings...")
        rule_validator = RuleValidator()
        validation_results: list[ValidationResult] = []
        for result in scan_results:
            checks = rule_validator.check(result)
            validation_results.append(rule_validator.build_result(result, checks))

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

        _p(1.0, "Done")
        return validation_results
