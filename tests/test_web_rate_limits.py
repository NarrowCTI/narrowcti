"""Bounded, deterministic contracts for Web request throttles."""

from __future__ import annotations

import unittest
import asyncio
from threading import BoundedSemaphore

from narrowcti.api.web.rate_limits import SlidingWindowRateLimiter
from narrowcti.api.web.app import _ProviderBusy, _bounded_provider_call


class SlidingWindowRateLimiterTests(unittest.TestCase):
    def test_enforces_window_and_expires_old_attempts(self):
        now = [0.0]
        limiter = SlidingWindowRateLimiter(clock=lambda: now[0])
        self.assertTrue(limiter.allow("login:client", limit=2, interval=60))
        now[0] = 1
        self.assertTrue(limiter.allow("login:client", limit=2, interval=60))
        self.assertFalse(limiter.allow("login:client", limit=2, interval=60))
        now[0] = 60
        self.assertTrue(limiter.allow("login:client", limit=2, interval=60))

    def test_identity_cardinality_is_bounded(self):
        limiter = SlidingWindowRateLimiter(max_keys=2, clock=lambda: 1.0)
        self.assertTrue(limiter.allow("first", limit=1, interval=60))
        self.assertTrue(limiter.allow("second", limit=1, interval=60))
        self.assertTrue(limiter.allow("third", limit=1, interval=60))
        self.assertLessEqual(len(limiter._entries), 2)

    def test_provider_busy_is_immediate_and_does_not_queue(self):
        semaphore = BoundedSemaphore(1)
        self.assertTrue(semaphore.acquire(blocking=False))
        with self.assertRaises(_ProviderBusy):
            asyncio.run(_bounded_provider_call(semaphore, lambda: "must not execute"))
        semaphore.release()
        self.assertEqual("done", asyncio.run(_bounded_provider_call(semaphore, lambda: "done")))


if __name__ == "__main__":
    unittest.main()
