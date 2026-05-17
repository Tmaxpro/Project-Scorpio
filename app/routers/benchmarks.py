"""FastAPI router — benchmark runs listing and triggering."""
from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from pathlib import Path

from fastapi import APIRouter
from pydantic import BaseModel

router = APIRouter(prefix="/api/benchmarks", tags=["benchmarks"])

_RUNS_DIR = Path("./benchmarks/runs")


class BenchmarkModelMetrics(BaseModel):
    model_name: str
    true_positives: int
    false_positives: int
    precision: float
    recall: float
    f1_score: float
    avg_latency_ms: float
    total_tokens: int
    fallback_count: int


class BenchmarkRun(BaseModel):
    run_id: str
    target_api: str
    timestamp: str
    models: list[BenchmarkModelMetrics]


class RunBenchmarkRequest(BaseModel):
    scan_id: str = ""
    spec_name: str = "fixture"
    owasp_filter: list[str] = []


@router.get("", response_model=list[BenchmarkRun])
async def list_benchmarks() -> list[BenchmarkRun]:
    """List all stored benchmark runs from benchmarks/runs/*.benchmark.json."""
    runs: list[BenchmarkRun] = []
    if not _RUNS_DIR.exists():
        return runs
    for f in sorted(_RUNS_DIR.glob("*.benchmark.json"), reverse=True):
        try:
            data = json.loads(f.read_text(encoding="utf-8"))
            runs.append(BenchmarkRun(**data))
        except Exception:  # noqa: BLE001
            pass
    return runs


@router.post("/run", response_model=dict)
async def run_benchmark(body: RunBenchmarkRequest) -> dict:
    """Trigger a dry-run benchmark (no Ollama/live target required)."""
    from benchmarks.run_benchmark import run_benchmark as _run

    result = await _run(
        spec_name=body.spec_name or "fixture",
        owasp_filter=body.owasp_filter or None,
    )
    cov = result.coverage_vs_ground_truth()

    # Compute phase latency for avg_latency_ms
    total_ms = sum(p.duration_ms for p in result.phases)
    total_tasks = max(result.total_tasks, 1)

    recall = cov["recall"]
    precision = 1.0 if cov["true_positives"] == 0 else (
        cov["true_positives"] / (cov["true_positives"] + max(0, result.total_tasks - cov["true_positives"]))
    )
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) > 0 else 0.0

    run_id = str(uuid.uuid4())
    timestamp = datetime.now(timezone.utc).isoformat()

    run_data = BenchmarkRun(
        run_id=run_id,
        target_api=body.spec_name or "fixture",
        timestamp=timestamp,
        models=[BenchmarkModelMetrics(
            model_name="rule-based-fallback",
            true_positives=cov["true_positives"],
            false_positives=0,
            precision=round(precision, 4),
            recall=round(recall, 4),
            f1_score=round(f1, 4),
            avg_latency_ms=round(total_ms / total_tasks, 2),
            total_tokens=0,
            fallback_count=0,
        )],
    )

    # Persist result
    _RUNS_DIR.mkdir(parents=True, exist_ok=True)
    out_path = _RUNS_DIR / f"{run_id}.benchmark.json"
    out_path.write_text(run_data.model_dump_json(indent=2), encoding="utf-8")

    return {"run_id": run_id}
