"""Process-local browser sessions; no bearer secrets or persistence are retained."""

from __future__ import annotations

import secrets
import time
from dataclasses import dataclass, field
from threading import RLock
from typing import Callable

from narrowcti.domain.security.identity import LocalOperatorPrincipal


@dataclass(frozen=True)
class WebSession:
    principal: LocalOperatorPrincipal | None
    created_at: float
    last_activity: float
    absolute_expiry: float
    idle_timeout: int
    csrf_token: str = field(repr=False)

    @property
    def authenticated(self) -> bool:
        return self.principal is not None


class InMemoryWebSessionStore:
    """Ephemeral server-side session store, intentionally lost on process restart."""

    def __init__(
        self,
        idle_timeout: int = 1800,
        absolute_timeout: int = 28800,
        *,
        max_sessions: int = 10000,
        clock: Callable[[], float] = time.time,
    ):
        if idle_timeout < 1 or absolute_timeout < idle_timeout:
            raise ValueError("session expiration settings are invalid")
        if max_sessions < 1:
            raise ValueError("session capacity must be positive")
        self._idle_timeout = idle_timeout
        self._absolute_timeout = absolute_timeout
        self._max_sessions = max_sessions
        self._clock = clock
        self._sessions: dict[str, WebSession] = {}
        self._lock = RLock()

    def create_anonymous(self) -> tuple[str, WebSession]:
        now = self._clock()
        session_id = secrets.token_urlsafe(32)
        session = WebSession(
            principal=None,
            created_at=now,
            last_activity=now,
            absolute_expiry=now + self._absolute_timeout,
            idle_timeout=self._idle_timeout,
            csrf_token=secrets.token_urlsafe(32),
        )
        with self._lock:
            self._prune_expired(now)
            if len(self._sessions) >= self._max_sessions:
                raise RuntimeError("Web session capacity reached")
            self._sessions[session_id] = session
        return session_id, session

    def authenticate(self, session_id: str, principal: LocalOperatorPrincipal) -> tuple[str, WebSession]:
        """Rotate the pre-auth session identifier to prevent fixation."""
        now = self._clock()
        session = WebSession(
            principal=principal,
            created_at=now,
            last_activity=now,
            absolute_expiry=now + self._absolute_timeout,
            idle_timeout=self._idle_timeout,
            csrf_token=secrets.token_urlsafe(32),
        )
        new_id = secrets.token_urlsafe(32)
        with self._lock:
            self._sessions.pop(session_id, None)
            self._prune_expired(now)
            if len(self._sessions) >= self._max_sessions:
                raise RuntimeError("Web session capacity reached")
            self._sessions[new_id] = session
        return new_id, session

    def get(self, session_id: str | None, *, touch: bool = True) -> WebSession | None:
        if not session_id:
            return None
        now = self._clock()
        with self._lock:
            session = self._sessions.get(session_id)
            if not session:
                return None
            if now >= session.absolute_expiry or now - session.last_activity >= session.idle_timeout:
                self._sessions.pop(session_id, None)
                return None
            if touch:
                session = WebSession(
                    principal=session.principal,
                    created_at=session.created_at,
                    last_activity=now,
                    absolute_expiry=session.absolute_expiry,
                    idle_timeout=session.idle_timeout,
                    csrf_token=session.csrf_token,
                )
                self._sessions[session_id] = session
            return session

    def delete(self, session_id: str | None) -> None:
        if session_id:
            with self._lock:
                self._sessions.pop(session_id, None)

    def _prune_expired(self, now: float) -> None:
        expired = [
            key
            for key, session in self._sessions.items()
            if now >= session.absolute_expiry or now - session.last_activity >= session.idle_timeout
        ]
        for key in expired:
            self._sessions.pop(key, None)

    def __len__(self) -> int:
        with self._lock:
            return len(self._sessions)


__all__ = ["InMemoryWebSessionStore", "WebSession"]
