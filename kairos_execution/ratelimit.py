"""Token-bucket rate limiter for EVEDEX heavy requests (30 per 60s)."""
from __future__ import annotations

import asyncio
import time


class TokenBucket:
    def __init__(self, capacity: int = 30, refill_period_s: float = 60.0) -> None:
        self.capacity = capacity
        self.refill_period_s = refill_period_s
        self._tokens = float(capacity)
        self._last = time.monotonic()
        self._lock = asyncio.Lock()

    def _refill(self) -> None:
        now = time.monotonic()
        elapsed = now - self._last
        self._tokens = min(self.capacity, self._tokens + elapsed * self.capacity / self.refill_period_s)
        self._last = now

    def try_acquire(self) -> bool:
        self._refill()
        if self._tokens >= 1.0:
            self._tokens -= 1.0
            return True
        return False

    async def acquire(self) -> None:
        async with self._lock:
            while not self.try_acquire():
                await asyncio.sleep(self.refill_period_s / self.capacity)
