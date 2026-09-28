"""Small bounded process-local sliding-window limits for the Community Web role."""

from __future__ import annotations

import time
from collections import OrderedDict, deque
from threading import Lock
from typing import Callable


class SlidingWindowRateLimiter:
    """Bound both event history and identity cardinality; forwarded headers are not involved."""

    def __init__(self, *, max_keys: int = 10_000, clock: Callable[[], float] = time.monotonic):
        if max_keys < 1:
            raise ValueError("rate limiter capacity must be positive")
        self._max_keys = max_keys
        self._clock = clock
        self._entries: OrderedDict[str, deque[float]] = OrderedDict()
        self._lock = Lock()

    def allow(self, key: str, *, limit: int, interval: float) -> bool:
        if limit < 1 or interval <= 0:
            raise ValueError("rate limit and interval must be positive")
        now = self._clock()
        with self._lock:
            entries = self._entries.get(key)
            if entries is None:
                while len(self._entries) >= self._max_keys:
                    self._entries.popitem(last=False)
                entries = deque()
                self._entries[key] = entries
            else:
                self._entries.move_to_end(key)
            while entries and now - entries[0] >= interval:
                entries.popleft()
            if len(entries) >= limit:
                return False
            entries.append(now)
            return True


__all__ = ["SlidingWindowRateLimiter"]
