"""Unit tests for Phase 8: benchmark runner and metrics module."""
from __future__ import annotations

import json
import tempfile
from pathlib import Path

import pytest

from benchmarks.metrics import (
    ModelStats,
    compute_stats,
    compute_task_type_stats,
    format_summary,
    load_dir,
    load_file,
)
from benchmarks.run_benchmark import (
    GROUND_TRUTH,
    BenchmarkResult,
    _MockLLM,
    _MockRag,
    run_benchmark,
)

# ── Fixtures ──────────────────────────────────────────────────────────────── #

_ENTRY_OK = {
    "timestamp": "2026-01-01T00:00:00+00:00",
    "task_id": "T-001",
    "model_used": "foundation-sec-8b",
    "task_type": "reason",
    "tokens_in": 100,
    "tokens_out": 50,
    "latency_ms": 120.5,
    "success": True,
}
_ENTRY_FAIL = {
    **_ENTRY_OK,
    "task_id": "T-002",
    "task_type": "reason",
    "latency_ms": 5.0,
    "success": False,
    "reason": "connection refused",
}
_ENTRY_INSTRUCT = {
    **_ENTRY_OK,
    "task_id": "T-003",
    "model_used": "foundation-sec-1.1-instruct",
    "task_type": "instruct",
    "latency_ms": 80.0,
}


def _write_jsonl(path: Path, entries: list[dict]) -> None:
    path.write_text("\n".join(json.dumps(e) for e in entries), encoding="utf-8")


# ── TestMetricsLoader ─────────────────────────────────────────────────────── #


class TestMetricsLoader:
    def test_load_file_returns_entries(self, tmp_path):
        f = tmp_path / "run.jsonl"
        _write_jsonl(f, [_ENTRY_OK, _ENTRY_FAIL])
        entries = load_file(f)
        assert len(entries) == 2

    def test_load_file_skips_malformed_lines(self, tmp_path):
        f = tmp_path / "run.jsonl"
        f.write_text('{"ok": true}\nNOT JSON\n{"ok": true}\n')
        entries = load_file(f)
        assert len(entries) == 2

    def test_load_file_skips_empty_lines(self, tmp_path):
        f = tmp_path / "run.jsonl"
        f.write_text('\n\n{"ok": true}\n\n')
        entries = load_file(f)
        assert len(entries) == 1

    def test_load_dir_reads_all_jsonl(self, tmp_path):
        _write_jsonl(tmp_path / "a.jsonl", [_ENTRY_OK])
        _write_jsonl(tmp_path / "b.jsonl", [_ENTRY_FAIL, _ENTRY_INSTRUCT])
        entries = load_dir(tmp_path)
        assert len(entries) == 3

    def test_load_dir_missing_dir_returns_empty(self, tmp_path):
        entries = load_dir(tmp_path / "nonexistent")
        assert entries == []

    def test_load_dir_ignores_non_jsonl_files(self, tmp_path):
        (tmp_path / "notes.txt").write_text("not jsonl")
        _write_jsonl(tmp_path / "run.jsonl", [_ENTRY_OK])
        entries = load_dir(tmp_path)
        assert len(entries) == 1


# ── TestMetricsCompute ────────────────────────────────────────────────────── #


class TestMetricsCompute:
    def test_compute_stats_empty_returns_empty(self):
        assert compute_stats([]) == []

    def test_compute_stats_counts_calls(self):
        stats = compute_stats([_ENTRY_OK, _ENTRY_FAIL])
        assert stats[0].calls == 2

    def test_compute_stats_counts_successes(self):
        stats = compute_stats([_ENTRY_OK, _ENTRY_FAIL])
        assert stats[0].successes == 1

    def test_compute_stats_success_rate(self):
        stats = compute_stats([_ENTRY_OK, _ENTRY_FAIL])
        assert stats[0].success_rate == pytest.approx(0.5)

    def test_compute_stats_avg_latency(self):
        stats = compute_stats([_ENTRY_OK, _ENTRY_FAIL])  # 120.5 + 5.0 = 125.5 / 2
        assert stats[0].avg_latency_ms == pytest.approx(62.75)

    def test_compute_stats_separates_models(self):
        stats = compute_stats([_ENTRY_OK, _ENTRY_INSTRUCT])
        models = {s.model for s in stats}
        assert "foundation-sec-8b" in models
        assert "foundation-sec-1.1-instruct" in models

    def test_compute_stats_sums_tokens(self):
        entries = [_ENTRY_OK, {**_ENTRY_OK, "tokens_in": 50, "tokens_out": 25}]
        stats = compute_stats(entries)
        assert stats[0].total_tokens_in == 150
        assert stats[0].total_tokens_out == 75

    def test_compute_task_type_stats(self):
        entries = [_ENTRY_OK, _ENTRY_FAIL, _ENTRY_INSTRUCT]
        tt = compute_task_type_stats(entries)
        assert tt["reason"]["calls"] == 2
        assert tt["instruct"]["calls"] == 1

    def test_format_summary_contains_model_name(self):
        stats = compute_stats([_ENTRY_OK])
        out = format_summary(stats, [_ENTRY_OK])
        assert "foundation-sec-8b" in out

    def test_format_summary_empty_data(self):
        out = format_summary([], [])
        assert "No data" in out

    def test_format_summary_shows_call_count(self):
        stats = compute_stats([_ENTRY_OK, _ENTRY_FAIL])
        out = format_summary(stats, [_ENTRY_OK, _ENTRY_FAIL])
        assert "2" in out


# ── TestBenchmarkRun ──────────────────────────────────────────────────────── #


class TestBenchmarkRun:
    async def test_dry_run_returns_benchmark_result(self):
        result = await run_benchmark(spec_name="unit-test")
        assert isinstance(result, BenchmarkResult)

    async def test_dry_run_detects_endpoints(self):
        result = await run_benchmark(spec_name="unit-test")
        assert result.total_endpoints == 5  # fixture has 5 endpoints

    async def test_dry_run_plans_tasks(self):
        result = await run_benchmark(spec_name="unit-test")
        assert result.total_tasks > 0

    async def test_dry_run_builds_payloads(self):
        result = await run_benchmark(spec_name="unit-test")
        assert result.total_payloads > 0

    async def test_dry_run_covers_multiple_categories(self):
        result = await run_benchmark(spec_name="unit-test")
        assert len(result.owasp_categories_covered) >= 3

    async def test_dry_run_covers_api4_always(self):
        result = await run_benchmark(spec_name="unit-test")
        assert "API4" in result.owasp_categories_covered

    async def test_dry_run_phase_timings_non_negative(self):
        result = await run_benchmark(spec_name="unit-test")
        assert all(p.duration_ms >= 0 for p in result.phases)

    async def test_dry_run_four_phases(self):
        result = await run_benchmark(spec_name="unit-test")
        phase_names = {p.name for p in result.phases}
        assert "parse+enrich" in phase_names
        assert "coordinate" in phase_names
        assert "build-payloads" in phase_names

    async def test_owasp_filter_limits_categories(self):
        result = await run_benchmark(spec_name="unit-test", owasp_filter=["API1", "API4"])
        assert result.owasp_categories_covered.issubset({"API1", "API4"})

    async def test_coverage_vs_ground_truth_recall(self):
        result = await run_benchmark(spec_name="unit-test")
        cov = result.coverage_vs_ground_truth()
        assert 0.0 <= cov["recall"] <= 1.0
        assert cov["total_expected"] == sum(len(v) for v in GROUND_TRUTH.values())

    async def test_coverage_has_per_endpoint_breakdown(self):
        result = await run_benchmark(spec_name="unit-test")
        cov = result.coverage_vs_ground_truth()
        assert "per_endpoint" in cov
        assert len(cov["per_endpoint"]) == len(GROUND_TRUTH)


# ── TestMockComponents ────────────────────────────────────────────────────── #


class TestMockComponents:
    async def test_mock_llm_reason_returns_error(self):
        llm = _MockLLM()
        result = await llm.reason("prompt")
        assert "error" in result

    async def test_mock_llm_instruct_returns_error(self):
        llm = _MockLLM()
        result = await llm.instruct("prompt")
        assert "error" in result

    def test_mock_rag_query_returns_empty(self):
        rag = _MockRag()
        assert rag.query("API1", "test") == []

    def test_mock_llm_usage_log_empty(self):
        assert _MockLLM().get_usage_log() == []
