"""ARIA benchmark runner — measures detection coverage and pipeline timing.

Runs in "dry" mode by default (no HTTP requests, no Ollama required):
  parse → enrich → plan (rule-based) → dispatch (defaults) → build payloads

Usage:
    python benchmarks/run_benchmark.py
    python benchmarks/run_benchmark.py --spec benchmarks/fixtures/vampi_like.yaml
    python benchmarks/run_benchmark.py --target http://localhost:5000
"""
from __future__ import annotations

import argparse
import asyncio
import json
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

# ── Ground truth for the built-in fixture ─────────────────────────────────── #

_FIXTURE_PATH = Path(__file__).parent / "fixtures" / "vampi_like.yaml"

# Expected OWASP categories per endpoint in the fixture spec
GROUND_TRUTH: dict[str, list[str]] = {
    "/api/v1/users/{id}":    ["API1", "API3", "API4"],
    "/api/v1/admin/users":   ["API4", "API5"],
    "/api/v1/auth/login":    ["API2", "API4", "API8"],
    "/api/v1/users":         ["API4", "API6", "API8"],
    "/api/v1/search":        ["API4", "API8"],
}


# ── Result types ──────────────────────────────────────────────────────────── #

@dataclass
class PhaseResult:
    name: str
    duration_ms: float
    count: int          # endpoints / tasks / payloads
    details: str = ""


@dataclass
class BenchmarkResult:
    spec_name: str
    scan_id: str
    total_endpoints: int
    total_tasks: int
    owasp_categories_covered: set[str]
    total_payloads: int
    phases: list[PhaseResult]
    planned_per_endpoint: dict[str, list[str]]  # path → [categories planned]

    def coverage_vs_ground_truth(self) -> dict[str, Any]:
        """Compare planned tasks against ground truth for the fixture spec."""
        true_positives = false_negatives = 0
        per_endpoint: dict[str, dict] = {}
        for path, expected in GROUND_TRUTH.items():
            planned = set(self.planned_per_endpoint.get(path, []))
            expected_set = set(expected)
            tp = planned & expected_set
            fn = expected_set - planned
            true_positives += len(tp)
            false_negatives += len(fn)
            per_endpoint[path] = {
                "expected": sorted(expected_set),
                "planned": sorted(planned),
                "missed": sorted(fn),
            }
        total_expected = sum(len(v) for v in GROUND_TRUTH.values())
        recall = true_positives / total_expected if total_expected else 0.0
        return {
            "recall": recall,
            "true_positives": true_positives,
            "false_negatives": false_negatives,
            "total_expected": total_expected,
            "per_endpoint": per_endpoint,
        }


# ── Stubs (no Ollama / ChromaDB required for dry run) ─────────────────────── #

class _MockLLM:
    """Returns error immediately → coordinator falls back to rule-based planning."""

    async def reason(self, *args: Any, **kwargs: Any) -> dict:
        return {"error": "benchmark dry-run: no LLM"}

    async def instruct(self, *args: Any, **kwargs: Any) -> dict:
        return {"error": "benchmark dry-run: no LLM"}

    def set_scan_id(self, _: str) -> None:
        pass

    def get_usage_log(self) -> list:
        return []


class _MockRag:
    """Returns empty RAG context — agents still work via defaults."""

    def query(self, owasp_category: str, query: str, top_k: int = 3) -> list[str]:
        return []

    def index_documents(self, *args: Any, **kwargs: Any) -> None:
        pass


# ── Core benchmark function ───────────────────────────────────────────────── #

async def run_benchmark(
    spec: str = "",
    spec_name: str = "fixture",
    owasp_filter: list[str] | None = None,
    max_payloads: int = 10,
) -> BenchmarkResult:
    """Run the planning pipeline and return a BenchmarkResult.

    Uses mock LLM/RAG so Ollama and ChromaDB are not required.
    """
    from core.agents.auth_agent import AuthAgent
    from core.agents.bola_agent import BOLAAgent
    from core.agents.injection_agent import InjectionAgent
    from core.agents.mass_assign_agent import MassAssignAgent
    from core.agents.rate_limit_agent import RateLimitAgent
    from core.coordinator.coordinator import Coordinator
    from core.coordinator.dispatcher import Dispatcher
    from core.parser.enricher import OpenAPIEnricher
    from core.parser.openapi_parser import OpenAPIParser
    from core.payload_factory.factory import PayloadFactory
    from core.payload_factory.nuclei_parser import NucleiPayloadAdapter
    from core.rag.nuclei_index import NucleiIndex

    if not spec:
        spec = _FIXTURE_PATH.read_text(encoding="utf-8")

    scan_id = str(uuid.uuid4())
    phases: list[PhaseResult] = []
    llm = _MockLLM()
    rag = _MockRag()

    # Phase 1 — parse + enrich
    t0 = time.monotonic()
    parser = OpenAPIParser()
    parser.parse(spec)
    enriched = OpenAPIEnricher().enrich(parser.get_endpoints())
    phases.append(PhaseResult("parse+enrich", (time.monotonic() - t0) * 1000, len(enriched)))

    # Phase 2 — coordinate (rule-based fallback since LLM is mocked)
    t0 = time.monotonic()
    coordinator = Coordinator(llm=llm, rag=rag)  # type: ignore[arg-type]
    tasks = await coordinator.plan(
        enriched_endpoints=enriched,
        context="benchmark",
        owasp_filter=owasp_filter or [],
    )
    phases.append(PhaseResult("coordinate", (time.monotonic() - t0) * 1000, len(tasks)))

    # Phase 3 — dispatch (all agents use default decisions)
    t0 = time.monotonic()
    agents = {
        "API1": BOLAAgent(llm, rag),          # type: ignore[arg-type]
        "API2": AuthAgent(llm, rag),           # type: ignore[arg-type]
        "API4": RateLimitAgent(llm, rag),      # type: ignore[arg-type]
        "API5": AuthAgent(llm, rag),           # type: ignore[arg-type]
        "API6": MassAssignAgent(llm, rag),     # type: ignore[arg-type]
        "API8": InjectionAgent(llm, rag),      # type: ignore[arg-type]
    }
    endpoint_map = {(ep.path, ep.method): ep for ep in enriched}
    decisions = await Dispatcher(agents=agents, max_concurrent=3).dispatch(tasks, enriched)
    task_map = {t.task_id: t for t in tasks}
    phases.append(PhaseResult("dispatch", (time.monotonic() - t0) * 1000, len(decisions)))

    # Phase 4 — build payloads
    t0 = time.monotonic()
    nuclei_adapter = NucleiPayloadAdapter(NucleiIndex("/nonexistent"))  # empty index
    factory = PayloadFactory(nuclei_adapter)
    total_payloads = 0
    planned_per_endpoint: dict[str, list[str]] = {}
    for decision in decisions:
        task = task_map.get(decision.task_id)
        if not task:
            continue
        endpoint = endpoint_map.get((task.target_endpoint, task.method))
        if not endpoint:
            continue
        reqs = factory.build(task, decision, endpoint)[:max_payloads]
        total_payloads += len(reqs)
        planned_per_endpoint.setdefault(task.target_endpoint, [])
        if task.vuln_category not in planned_per_endpoint[task.target_endpoint]:
            planned_per_endpoint[task.target_endpoint].append(task.vuln_category)
    phases.append(PhaseResult("build-payloads", (time.monotonic() - t0) * 1000, total_payloads))

    categories_covered = {t.vuln_category for t in tasks}
    return BenchmarkResult(
        spec_name=spec_name,
        scan_id=scan_id,
        total_endpoints=len(enriched),
        total_tasks=len(tasks),
        owasp_categories_covered=categories_covered,
        total_payloads=total_payloads,
        phases=phases,
        planned_per_endpoint=planned_per_endpoint,
    )


def print_result(result: BenchmarkResult) -> None:
    print(f"\n{'═' * 60}")
    print(f"  ARIA Benchmark — {result.spec_name}")
    print(f"  Scan ID: {result.scan_id}")
    print(f"{'═' * 60}")
    print(f"  Endpoints:  {result.total_endpoints}")
    print(f"  Tasks:      {result.total_tasks}")
    print(f"  Categories: {sorted(result.owasp_categories_covered)}")
    print(f"  Payloads:   {result.total_payloads}")
    print(f"{'─' * 60}")
    print("  Phase timing:")
    for p in result.phases:
        print(f"    {p.name:<20} {p.duration_ms:>8.1f} ms   count={p.count}")
    print(f"{'─' * 60}")
    cov = result.coverage_vs_ground_truth()
    print(
        f"  Coverage vs ground truth:  "
        f"recall={cov['recall']:.0%}  "
        f"TP={cov['true_positives']}  "
        f"FN={cov['false_negatives']}  "
        f"(of {cov['total_expected']} expected)"
    )
    print(f"{'═' * 60}\n")


async def _main_async(spec_file: str) -> None:
    spec = Path(spec_file).read_text(encoding="utf-8") if spec_file else ""
    result = await run_benchmark(
        spec=spec,
        spec_name=Path(spec_file).stem if spec_file else "fixture",
    )
    print_result(result)


def main() -> None:
    parser = argparse.ArgumentParser(description="ARIA benchmark runner")
    parser.add_argument(
        "--spec", default="",
        help="Path to OpenAPI YAML spec (default: built-in fixture)"
    )
    args = parser.parse_args()
    asyncio.run(_main_async(args.spec))


if __name__ == "__main__":
    main()
