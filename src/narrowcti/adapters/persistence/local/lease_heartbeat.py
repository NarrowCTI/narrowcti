"""Small process-local helper for renewing SQLite-backed leases."""

from __future__ import annotations

import threading
from collections.abc import Callable


class LeaseHeartbeat:
    """Renew a lease in a daemon thread and expose loss to the owner."""

    def __init__(self, renew: Callable[[], bool], lease_seconds: float):
        self._renew = renew
        self._interval = max(float(lease_seconds) / 3.0, 0.05)
        self._stop = threading.Event()
        self._lost = threading.Event()
        self._thread = threading.Thread(target=self._run, name="narrowcti-lease-heartbeat", daemon=True)

    @property
    def lost(self) -> bool:
        return self._lost.is_set()

    def start(self):
        self._thread.start()
        return self

    def stop(self):
        self._stop.set()
        self._thread.join(timeout=max(self._interval * 2, 1.0))

    def _run(self):
        while not self._stop.wait(self._interval):
            try:
                if not self._renew():
                    self._lost.set()
                    return
            except Exception:
                self._lost.set()
                return


__all__ = ["LeaseHeartbeat"]
