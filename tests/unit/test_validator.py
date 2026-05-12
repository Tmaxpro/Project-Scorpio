"""Unit tests for Phase 6: HTTP engine + validator."""
from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from core.coordinator.task_builder import Task
from core.http_engine.auth_injector import AuthConfig, AuthInjector
from core.http_engine.client import HTTPEngineClient, ScanResult
from core.http_engine.rate_controller import RateController
from core.payload_factory.models import PayloadRequest
from core.validator.rule_validator import RuleCheckResult, RuleValidator, ValidationResult
from core.validator.slm_validator import SLMValidator

# ── Helpers ───────────────────────────────────────────────────────────────── #


def _req(
    method: str = "GET",
    path: str = "/api/items",
    headers: dict | None = None,
    body: dict | None = None,
    strategy: str = "baseline",
    label: str = "baseline",
    query_params: dict | None = None,
) -> PayloadRequest:
    return PayloadRequest(
        task_id="T-001",
        method=method,
        path=path,
        headers=headers or {},
        body=body,
        query_params=query_params or {},
        strategy=strategy,
        label=label,
    )


def _result(
    status_code: int = 200,
    body: str = "",
    request: PayloadRequest | None = None,
    error: str | None = None,
) -> ScanResult:
    return ScanResult(
        task_id="T-001",
        request=request or _req(),
        status_code=status_code,
        response_headers={},
        response_body=body,
        response_time_ms=50.0,
        error=error,
    )


def _task(category: str = "API1") -> Task:
    return Task(
        task_id="T-001",
        vuln_category=category,
        owasp_ref=f"{category}:2023",
        target_endpoint="/api/items",
        method="GET",
        strategy="test strategy",
        rag_context_tags=[],
        priority=2,
    )


# ── TestAuthInjector ──────────────────────────────────────────────────────── #


class TestAuthInjector:
    def test_bearer_injected_when_no_existing_auth(self):
        injector = AuthInjector(AuthConfig(type="bearer", token="mytoken"))
        result = injector.inject(_req())
        assert result["Authorization"] == "Bearer mytoken"

    def test_api_key_injected_into_custom_header(self):
        cfg = AuthConfig(type="api_key", token="k123", header_name="X-API-Key")
        injector = AuthInjector(cfg)
        result = injector.inject(_req())
        assert result["X-API-Key"] == "k123"

    def test_basic_auth_injected(self):
        injector = AuthInjector(AuthConfig(type="basic", token="dXNlcjpwYXNz"))
        result = injector.inject(_req())
        assert result["Authorization"] == "Basic dXNlcjpwYXNz"

    def test_existing_auth_header_not_overridden(self):
        injector = AuthInjector(AuthConfig(type="bearer", token="session_token"))
        req = _req(headers={"Authorization": "Bearer crafted_jwt"})
        result = injector.inject(req)
        assert result["Authorization"] == "Bearer crafted_jwt"

    def test_skip_auth_returns_no_auth(self):
        injector = AuthInjector(AuthConfig(type="bearer", token="t"))
        req = _req(headers={"X-ARIA-Skip-Auth": "true"})
        result = injector.inject(req)
        assert "Authorization" not in result

    def test_other_user_token_used_when_flag_set(self):
        cfg = AuthConfig(type="bearer", token="user1_token", other_user_token="user2_token")
        injector = AuthInjector(cfg)
        req = _req(headers={"X-ARIA-Other-User": "true"})
        result = injector.inject(req)
        assert result["Authorization"] == "Bearer user2_token"

    def test_primary_token_used_when_no_other_user_flag(self):
        cfg = AuthConfig(type="bearer", token="user1_token", other_user_token="user2_token")
        injector = AuthInjector(cfg)
        result = injector.inject(_req())
        assert result["Authorization"] == "Bearer user1_token"

    def test_aria_meta_headers_stripped(self):
        injector = AuthInjector(AuthConfig(type="none"))
        req = _req(headers={"X-ARIA-Skip-Auth": "true", "X-ARIA-Other-User": "true", "Content-Type": "application/json"})
        result = injector.inject(req)
        assert "X-ARIA-Skip-Auth" not in result
        assert "X-ARIA-Other-User" not in result
        assert result.get("Content-Type") == "application/json"

    def test_none_auth_type_returns_stripped_headers_only(self):
        injector = AuthInjector(AuthConfig(type="none"))
        req = _req(headers={"Accept": "application/json"})
        result = injector.inject(req)
        assert "Authorization" not in result
        assert result.get("Accept") == "application/json"


# ── TestRateController ────────────────────────────────────────────────────── #


class TestRateController:
    async def test_acquire_completes(self):
        rc = RateController(requests_per_second=1000.0)
        await rc.acquire("localhost:8080")

    async def test_acquire_multiple_hosts_independent(self):
        rc = RateController(requests_per_second=1000.0)
        await rc.acquire("host-a:8080")
        await rc.acquire("host-b:8080")
        assert "host-a:8080" in rc._last
        assert "host-b:8080" in rc._last

    async def test_two_rapid_acquires_same_host_complete(self):
        rc = RateController(requests_per_second=10000.0)
        await rc.acquire("localhost")
        await rc.acquire("localhost")

    def test_invalid_rate_raises(self):
        with pytest.raises(ValueError):
            RateController(requests_per_second=0)


# ── TestHTTPEngineClient ──────────────────────────────────────────────────── #


def _mock_http_response(status: int = 200, body: str = '{"ok":true}') -> MagicMock:
    resp = MagicMock()
    resp.status_code = status
    resp.headers = {"content-type": "application/json"}
    resp.text = body
    return resp


def _build_client(base_url: str = "http://localhost:8080") -> HTTPEngineClient:
    injector = AuthInjector(AuthConfig(type="bearer", token="token"))
    rc = RateController(requests_per_second=10000.0)
    return HTTPEngineClient(base_url, injector, rc, timeout_s=5.0)


class TestHTTPEngineClient:
    async def test_send_returns_scan_result(self):
        client = _build_client()
        mock_resp = _mock_http_response(200)
        mock_http = AsyncMock()
        mock_http.request.return_value = mock_resp
        mock_class = MagicMock()
        mock_class.return_value.__aenter__ = AsyncMock(return_value=mock_http)
        mock_class.return_value.__aexit__ = AsyncMock(return_value=False)

        with patch("core.http_engine.client.httpx.AsyncClient", mock_class):
            result = await client.send(_req())

        assert isinstance(result, ScanResult)
        assert result.status_code == 200
        assert result.task_id == "T-001"

    async def test_send_passes_correct_method_and_url(self):
        client = _build_client("http://target:9000")
        mock_resp = _mock_http_response(201)
        mock_http = AsyncMock()
        mock_http.request.return_value = mock_resp
        mock_class = MagicMock()
        mock_class.return_value.__aenter__ = AsyncMock(return_value=mock_http)
        mock_class.return_value.__aexit__ = AsyncMock(return_value=False)

        req = _req(method="POST", path="/api/users")
        with patch("core.http_engine.client.httpx.AsyncClient", mock_class):
            await client.send(req)

        call_kwargs = mock_http.request.call_args
        assert call_kwargs.kwargs["method"] == "POST"
        assert "http://target:9000/api/users" in call_kwargs.kwargs["url"]

    async def test_send_returns_error_result_on_network_failure(self):
        client = _build_client()
        mock_class = MagicMock()
        mock_class.return_value.__aenter__ = AsyncMock(side_effect=Exception("connection refused"))
        mock_class.return_value.__aexit__ = AsyncMock(return_value=False)

        with patch("core.http_engine.client.httpx.AsyncClient", mock_class):
            result = await client.send(_req())

        assert result.is_error
        assert result.status_code == 0
        assert "connection refused" in result.error

    async def test_send_batch_returns_all_results(self):
        client = _build_client()
        mock_resp = _mock_http_response(200)
        mock_http = AsyncMock()
        mock_http.request.return_value = mock_resp
        mock_class = MagicMock()
        mock_class.return_value.__aenter__ = AsyncMock(return_value=mock_http)
        mock_class.return_value.__aexit__ = AsyncMock(return_value=False)

        requests = [_req(path=f"/api/items/{i}") for i in range(3)]
        with patch("core.http_engine.client.httpx.AsyncClient", mock_class):
            results = await client.send_batch(requests)

        assert len(results) == 3
        assert all(isinstance(r, ScanResult) for r in results)

    def test_is_success_true_for_2xx(self):
        assert _result(200).is_success is True
        assert _result(201).is_success is True

    def test_is_success_false_for_4xx(self):
        assert _result(404).is_success is False

    def test_is_error_true_when_error_set(self):
        assert _result(error="timeout").is_error is True
        assert _result(200).is_error is False


# ── TestRuleValidator ─────────────────────────────────────────────────────── #


class TestRuleValidator:
    def setup_method(self):
        self.v = RuleValidator()

    def _run(self, result: ScanResult, rule_id: str) -> RuleCheckResult:
        checks = self.v.check(result)
        return next(c for c in checks if c.rule_id == rule_id)

    # auth_bypass
    def test_auth_bypass_triggered_on_200_no_auth(self):
        req = _req(headers={}, strategy="jwt_exploit", label="missing_auth_header")
        check = self._run(_result(200, request=req), "auth_bypass")
        assert check.triggered
        assert check.severity == "high"

    def test_auth_bypass_not_triggered_on_401(self):
        req = _req(headers={}, strategy="jwt_exploit", label="missing_auth_header")
        check = self._run(_result(401, request=req), "auth_bypass")
        assert not check.triggered

    def test_auth_bypass_not_triggered_for_normal_request(self):
        req = _req(headers={"Authorization": "Bearer tok"}, strategy="baseline", label="baseline")
        check = self._run(_result(200, request=req), "auth_bypass")
        assert not check.triggered

    # error_disclosure
    def test_error_disclosure_triggered_on_500_with_stacktrace(self):
        body = "Traceback (most recent call last):\n  File app.py line 42"
        check = self._run(_result(500, body=body), "error_disclosure")
        assert check.triggered
        assert check.severity == "medium"

    def test_error_disclosure_not_triggered_on_200(self):
        check = self._run(_result(200, "Traceback..."), "error_disclosure")
        assert not check.triggered

    def test_error_disclosure_not_triggered_on_500_without_trace(self):
        check = self._run(_result(500, "Internal Server Error"), "error_disclosure")
        assert not check.triggered

    # sensitive_data
    def test_sensitive_data_triggered_on_password_in_response(self):
        body = '{"password": "supersecret123", "user": "alice"}'
        check = self._run(_result(200, body), "sensitive_data_exposure")
        assert check.triggered

    def test_sensitive_data_triggered_on_email(self):
        check = self._run(_result(200, "contact: alice@example.com"), "sensitive_data_exposure")
        assert check.triggered

    def test_sensitive_data_not_triggered_on_404(self):
        body = '{"email": "alice@example.com"}'
        check = self._run(_result(404, body), "sensitive_data_exposure")
        assert not check.triggered

    # injection_error
    def test_injection_sql_error_triggered(self):
        body = "You have an error in your SQL syntax near 'OR 1=1'"
        check = self._run(_result(200, body), "injection_error")
        assert check.triggered
        assert check.severity == "high"

    def test_injection_nosql_error_triggered(self):
        body = "MongoError: Cast to ObjectId failed for value"
        check = self._run(_result(200, body), "injection_error")
        assert check.triggered

    def test_injection_ssti_triggered(self):
        req = _req(strategy="ssti")
        check = self._run(_result(200, "Result: 49 items found", request=req), "injection_error")
        assert check.triggered

    def test_injection_not_triggered_on_clean_response(self):
        check = self._run(_result(200, '{"id": 1, "name": "test"}'), "injection_error")
        assert not check.triggered

    # admin endpoint
    def test_admin_endpoint_exposed_triggered(self):
        req = _req(path="/admin/users", label="admin_access:role_spoof", strategy="admin_endpoint_access")
        check = self._run(_result(200, request=req), "admin_endpoint_exposed")
        assert check.triggered
        assert check.severity == "high"

    def test_admin_endpoint_not_triggered_on_403(self):
        req = _req(path="/admin/users", label="admin_access:role_spoof")
        check = self._run(_result(403, request=req), "admin_endpoint_exposed")
        assert not check.triggered

    # bola
    def test_bola_triggered_on_200_bola_strategy(self):
        req = _req(path="/api/items/2", strategy="bola_exploit", label="bola:id=2")
        check = self._run(_result(200, request=req), "bola_object_access")
        assert check.triggered

    def test_bola_not_triggered_on_404(self):
        req = _req(path="/api/items/999", strategy="bola_exploit", label="bola:id=999")
        check = self._run(_result(404, request=req), "bola_object_access")
        assert not check.triggered

    # rate limit batch
    def test_rate_limit_batch_triggered_when_no_429(self):
        results = [_result(200) for _ in range(20)]
        check = self.v.check_rate_limit_batch(results)
        assert check.triggered
        assert check.owasp_category == "API4"

    def test_rate_limit_batch_not_triggered_when_429_present(self):
        results = [_result(200) for _ in range(5)] + [_result(429)]
        check = self.v.check_rate_limit_batch(results)
        assert not check.triggered

    def test_rate_limit_batch_not_triggered_for_small_sample(self):
        results = [_result(200) for _ in range(5)]
        check = self.v.check_rate_limit_batch(results)
        assert not check.triggered

    # error results skipped
    def test_error_result_returns_empty_checks(self):
        result = _result(error="timeout")
        checks = self.v.check(result)
        assert checks == []

    # build_result
    def test_build_result_is_vulnerable_when_high_triggered(self):
        checks = [RuleCheckResult("auth_bypass", True, "high", "evidence", "API2")]
        vr = self.v.build_result(_result(200), checks)
        assert vr.is_vulnerable

    def test_build_result_not_vulnerable_when_no_high_medium(self):
        checks = [RuleCheckResult("bola_object_access", True, "low", "evidence", "API1")]
        vr = self.v.build_result(_result(200), checks)
        assert not vr.is_vulnerable

    def test_highest_severity(self):
        checks = [
            RuleCheckResult("r1", True, "medium", "", "API3"),
            RuleCheckResult("r2", True, "high", "", "API2"),
            RuleCheckResult("r3", False, "low", "", "API1"),
        ]
        vr = ValidationResult(task_id="T-001", scan_result=_result(), rule_checks=checks, is_vulnerable=True)
        assert vr.highest_severity() == "high"


# ── TestSLMValidator ──────────────────────────────────────────────────────── #


class TestSLMValidator:
    async def test_confirm_returns_true_when_model_confirms(self):
        llm = MagicMock()
        llm.instruct = AsyncMock(return_value={"confirmed": True, "reasoning": "clear evidence"})
        validator = SLMValidator(llm)
        confirmed, reasoning = await validator.confirm(_result(), [], _task())
        assert confirmed is True
        assert "evidence" in reasoning

    async def test_confirm_returns_false_when_model_denies(self):
        llm = MagicMock()
        llm.instruct = AsyncMock(return_value={"confirmed": False, "reasoning": "no evidence"})
        validator = SLMValidator(llm)
        confirmed, reasoning = await validator.confirm(_result(), [], _task())
        assert confirmed is False

    async def test_confirm_returns_false_on_llm_error(self):
        llm = MagicMock()
        llm.instruct = AsyncMock(return_value={"error": "model unavailable"})
        validator = SLMValidator(llm)
        confirmed, reasoning = await validator.confirm(_result(), [], _task())
        assert confirmed is False
        assert "unavailable" in reasoning

    async def test_confirm_passes_task_id_to_llm(self):
        llm = MagicMock()
        llm.instruct = AsyncMock(return_value={"confirmed": False, "reasoning": ""})
        validator = SLMValidator(llm)
        task = _task("API2")
        await validator.confirm(_result(), [], task)
        call_kwargs = llm.instruct.call_args
        assert call_kwargs.kwargs.get("task_id") == "T-001" or "T-001" in str(call_kwargs)
