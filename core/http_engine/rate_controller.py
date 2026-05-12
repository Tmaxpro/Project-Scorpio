"""Per-host token-bucket rate limiter for the HTTP engine."""
from __future__ import annotations

import asyncio
import time


class RateController:
    """Enforces a maximum requests-per-second rate on a per-host basis.

    Sleeps for the remainder of the minimum inter-request interval before
    each request to the same host.  Different hosts are tracked independently.
    """

    def __init__(self, requests_per_second: float = 10.0) -> None:
        if requests_per_second <= 0:
            raise ValueError("requests_per_second must be > 0")
        self._min_interval = 1.0 / requests_per_second
        self._last: dict[str, float] = {}
        self._locks: dict[str, asyncio.Lock] = {}

    async def acquire(self, host: str) -> None:
        """Wait, if necessary, to respect the per-host rate limit."""
        if host not in self._locks:
            self._locks[host] = asyncio.Lock()
        async with self._locks[host]:
            now = time.monotonic()
            wait = self._min_interval - (now - self._last.get(host, 0.0))
            if wait > 0:
                await asyncio.sleep(wait)
            self._last[host] = time.monotonic()
