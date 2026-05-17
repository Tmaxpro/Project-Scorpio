"""Async HTTP engine — sends PayloadRequests and returns ScanResults."""
from __future__ import annotations

import asyncio
import logging
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from urllib.parse import urlparse

import httpx

from core.http_engine.auth_injector import AuthInjector
from core.http_engine.rate_controller import RateController
from core.payload_factory.models import PayloadRequest

logger = logging.getLogger(__name__)

_MAX_RESPONSE_BODY = 4096


@dataclass
class ScanResult:
    """The outcome of executing a single PayloadRequest."""

    task_id: str
    request: PayloadRequest
    status_code: int
    response_headers: dict[str, str]
    response_body: str
    response_time_ms: float
    error: str | None = None

    @property
    def is_error(self) -> bool:
        return self.error is not None

    @property
    def is_success(self) -> bool:
        return not self.is_error and 200 <= self.status_code < 300


class HTTPEngineClient:
    """Sends PayloadRequests over HTTP, applying rate limiting and auth injection."""

    def __init__(
        self,
        base_url: str,
        auth_injector: AuthInjector,
        rate_controller: RateController,
        timeout_s: float = 10.0,
    ) -> None:
        self._base_url = base_url.rstrip("/")
        self._auth_injector = auth_injector
        self._rate_controller = rate_controller
        self._timeout = timeout_s

    async def send(
        self,
        request: PayloadRequest,
        on_result: Callable[[ScanResult], Awaitable[None]] | None = None,
    ) -> ScanResult:
        """Execute one PayloadRequest and return a ScanResult."""
        url = f"{self._base_url}{request.path}"
        host = urlparse(url).netloc

        await self._rate_controller.acquire(host)

        headers = self._auth_injector.inject(request)
        json_body = request.body if isinstance(request.body, (dict, list)) else None
        params = request.query_params if request.query_params else None

        start = time.monotonic()
        try:
            async with httpx.AsyncClient(timeout=self._timeout) as client:
                response = await client.request(
                    method=request.method,
                    url=url,
                    headers=headers,
                    json=json_body,
                    params=params,
                )
            elapsed_ms = (time.monotonic() - start) * 1000
            logger.info("→ %s %s  %d  %.0fms", request.method, url, response.status_code, elapsed_ms)
            result = ScanResult(
                task_id=request.task_id,
                request=request,
                status_code=response.status_code,
                response_headers=dict(response.headers),
                response_body=response.text[:_MAX_RESPONSE_BODY],
                response_time_ms=elapsed_ms,
            )
        except Exception as exc:  # noqa: BLE001
            elapsed_ms = (time.monotonic() - start) * 1000
            logger.info("→ %s %s  ERR  %.0fms  (%s)", request.method, url, elapsed_ms, exc)
            result = ScanResult(
                task_id=request.task_id,
                request=request,
                status_code=0,
                response_headers={},
                response_body="",
                response_time_ms=elapsed_ms,
                error=str(exc),
            )

        if on_result:
            await on_result(result)
        return result

    async def send_batch(
        self,
        requests: list[PayloadRequest],
        on_result: Callable[[ScanResult], Awaitable[None]] | None = None,
    ) -> list[ScanResult]:
        """Send all requests concurrently; rate limiter serialises per-host."""
        return list(await asyncio.gather(*[self.send(req, on_result) for req in requests]))
