"""Unit tests for core/llm/client.py.

All tests mock the ollama.AsyncClient so no live Ollama instance is required.
A single live smoke-test is skipped when Ollama is unreachable.
"""
from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest

from core.llm.client import LLMClient

CONFIG = Path(__file__).parent.parent.parent / "config.yaml"


# ── Helpers ──────────────────────────────────────────────────────────────── #

def _mock_response(content: str, tokens_in: int = 10, tokens_out: int = 20) -> MagicMock:
    """Build a mock that mimics an ollama ChatResponse."""
    msg = MagicMock()
    msg.content = content
    resp = MagicMock()
    resp.message = msg
    resp.prompt_eval_count = tokens_in
    resp.eval_count = tokens_out
    return resp


@pytest.fixture()
def client() -> LLMClient:
    return LLMClient(config_path=str(CONFIG))


# ── _parse_json ───────────────────────────────────────────────────────────── #

class TestParseJson:
    def test_plain_object(self):
        assert LLMClient._parse_json('{"key": "value"}') == {"key": "value"}

    def test_plain_array(self):
        assert LLMClient._parse_json('[{"a": 1}]') == [{"a": 1}]

    def test_strips_json_fence(self):
        assert LLMClient._parse_json('```json\n{"k": 1}\n```') == {"k": 1}

    def test_strips_generic_fence(self):
        assert LLMClient._parse_json('```\n{"k": 1}\n```') == {"k": 1}

    def test_extracts_from_prose(self):
        result = LLMClient._parse_json('Here you go: {"confirmed": true} done.')
        assert result == {"confirmed": True}

    def test_returns_none_on_garbage(self):
        assert LLMClient._parse_json("not json at all") is None

    def test_returns_none_on_empty(self):
        assert LLMClient._parse_json("") is None

    def test_nested_object(self):
        payload = '{"outer": {"inner": [1, 2, 3]}}'
        assert LLMClient._parse_json(payload) == {"outer": {"inner": [1, 2, 3]}}


# ── reason() ─────────────────────────────────────────────────────────────── #

class TestReason:
    async def test_returns_parsed_json(self, client: LLMClient):
        payload = {"task_id": "T-001", "strategy": "test"}
        client._client.chat = AsyncMock(return_value=_mock_response(json.dumps(payload)))

        result = await client.reason("plan this", task_id="T-001")

        assert result == payload

    async def test_escalates_to_fallback_after_3_json_failures(self, client: LLMClient):
        good = {"result": "fallback_worked"}
        call_count = 0

        async def side_effect(**kwargs):
            nonlocal call_count
            call_count += 1
            # First max_retries calls (primary model) → bad JSON
            # Next call (fallback model) → valid JSON
            if call_count <= client._max_retries:
                return _mock_response("not json")
            return _mock_response(json.dumps(good))

        client._client.chat = AsyncMock(side_effect=side_effect)

        result = await client.reason("prompt", task_id="T-002")

        assert result == good
        assert call_count == client._max_retries + 1  # 3 primary + 1 fallback

    async def test_returns_error_dict_on_total_failure(self, client: LLMClient):
        client._client.chat = AsyncMock(return_value=_mock_response("bad json"))

        async def always_error(*args, **kwargs):
            return {"error": "fallback also failed"}

        client.fallback = always_error  # intercept escalation

        result = await client.reason("prompt", task_id="T-003")
        assert "error" in result

    async def test_usage_logged_on_success(self, client: LLMClient):
        payload = {"ping": "pong"}
        client._client.chat = AsyncMock(return_value=_mock_response(json.dumps(payload)))

        await client.reason("test", task_id="T-004")

        log = client.get_usage_log()
        assert len(log) >= 1
        entry = log[-1]
        assert entry["task_id"] == "T-004"
        assert entry["success"] is True
        assert "timestamp" in entry
        assert "latency_ms" in entry
        assert entry["model_used"] == client._reasoning_model

    async def test_failure_reason_logged(self, client: LLMClient):
        client._client.chat = AsyncMock(side_effect=ConnectionError("connection refused"))

        async def stub_fallback(*args, **kwargs):
            return {"error": "x"}

        client.fallback = stub_fallback

        await client.reason("test", task_id="T-005")

        failures = [e for e in client.get_usage_log() if not e["success"]]
        assert len(failures) >= 1
        assert "connection refused" in failures[0].get("reason", "")


# ── instruct() ───────────────────────────────────────────────────────────── #

class TestInstruct:
    async def test_uses_instruct_model(self, client: LLMClient):
        payload = {"confirmed": False, "confidence": "low", "reasoning": "ok"}
        client._client.chat = AsyncMock(return_value=_mock_response(json.dumps(payload)))

        result = await client.instruct("validate this", task_id="T-010")

        assert result == payload
        called_model = client._client.chat.call_args.kwargs["model"]
        assert called_model == client._instruct_model


# ── fallback() ───────────────────────────────────────────────────────────── #

class TestFallback:
    async def test_uses_fallback_model(self, client: LLMClient):
        payload = {"ok": True}
        client._client.chat = AsyncMock(return_value=_mock_response(json.dumps(payload)))

        result = await client.fallback("prompt", task_id="T-020")

        assert result == payload
        called_model = client._client.chat.call_args.kwargs["model"]
        assert called_model == client._fallback_model

    async def test_no_further_escalation_on_failure(self, client: LLMClient):
        """fallback() must not recursively call itself."""
        client._client.chat = AsyncMock(return_value=_mock_response("bad json"))

        result = await client.fallback("prompt", task_id="T-021")

        assert "error" in result
        # max_retries calls, never more
        assert client._client.chat.call_count == client._max_retries


# ── JSONL persistence ─────────────────────────────────────────────────────── #

class TestUsageLogPersistence:
    async def test_writes_jsonl_when_scan_id_set(self, client: LLMClient, tmp_path):
        client.scan_id = "scan-abc"
        client._log_dir = tmp_path

        payload = {"result": "ok"}
        client._client.chat = AsyncMock(return_value=_mock_response(json.dumps(payload)))

        await client.reason("test", task_id="T-030")

        log_file = tmp_path / "scan-abc.jsonl"
        assert log_file.exists()
        entry = json.loads(log_file.read_text().strip().splitlines()[0])
        assert entry["task_id"] == "T-030"
        assert entry["success"] is True

    async def test_no_file_written_without_scan_id(self, client: LLMClient, tmp_path):
        client.scan_id = None
        client._log_dir = tmp_path

        payload = {"result": "ok"}
        client._client.chat = AsyncMock(return_value=_mock_response(json.dumps(payload)))

        await client.reason("test", task_id="T-031")

        assert not any(tmp_path.iterdir())


# ── Live smoke test (skipped if Ollama not reachable) ────────────────────── #

def _ollama_available() -> bool:
    try:
        import httpx
        r = httpx.get("http://localhost:11434/api/tags", timeout=2)
        return r.status_code == 200
    except Exception:
        return False


@pytest.mark.skipif(not _ollama_available(), reason="Ollama not running at localhost:11434")
async def test_live_instruct_returns_json():
    """Confirm a real Ollama call produces a parseable JSON dict."""
    c = LLMClient(config_path=str(CONFIG))
    result = await c.instruct('Return exactly this JSON: {"ping": "pong"}', task_id="live")
    assert isinstance(result, dict)
    assert "error" not in result
