"""Safe application contract for bounded, explicit provider readiness checks."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from enum import StrEnum
from typing import Iterable

from narrowcti.ports.source_explorer import ExplorerError, ProviderDescriptor
from narrowcti.ports.provider_readiness import ProviderReadinessProbe


class ProviderReadinessState(StrEnum):
    NOT_CONFIGURED = "not_configured"
    CREDENTIAL_MISSING = "credential_missing"
    UNREACHABLE = "unreachable"
    TLS_FAILED = "tls_failed"
    AUTH_REJECTED = "auth_rejected"
    RATE_LIMITED = "rate_limited"
    DEGRADED = "degraded"
    READY = "ready"


@dataclass(frozen=True)
class ProviderReadinessResult:
    provider_key: str
    state: ProviderReadinessState
    checked_at: str
    message: str

    def to_dict(self) -> dict[str, str]:
        return {
            "provider": self.provider_key,
            "state": self.state.value,
            "checked_at": self.checked_at,
            "message": self.message,
        }


_MESSAGES = {
    ProviderReadinessState.NOT_CONFIGURED: "Configure the provider endpoint before checking readiness.",
    ProviderReadinessState.CREDENTIAL_MISSING: "Provide a readable, non-empty dedicated Explorer credential file.",
    ProviderReadinessState.UNREACHABLE: "The provider could not be reached within the bounded check.",
    ProviderReadinessState.TLS_FAILED: "TLS validation failed; verify the provider certificate and trust chain.",
    ProviderReadinessState.AUTH_REJECTED: "The provider rejected the configured Explorer credential or permissions.",
    ProviderReadinessState.RATE_LIMITED: "The provider rate-limited the readiness check; retry later.",
    ProviderReadinessState.DEGRADED: "The provider responded but the readiness check did not complete reliably.",
    ProviderReadinessState.READY: "The bounded, read-only provider readiness check succeeded.",
}


class ProviderReadinessService:
    """Run explicit probes and normalize all public outcomes to a fixed taxonomy."""

    def __init__(self, providers: Iterable[ProviderReadinessProbe] = ()) -> None:
        self._providers: dict[str, ProviderReadinessProbe] = {}
        for provider in providers:
            descriptor = provider.descriptor()
            if not descriptor.key or descriptor.key in self._providers:
                raise ValueError("provider readiness keys must be unique and non-empty")
            self._providers[descriptor.key] = provider

    def providers(self) -> tuple[ProviderDescriptor, ...]:
        return tuple(provider.descriptor() for _, provider in sorted(self._providers.items()))

    def check(self, provider_key: str) -> ProviderReadinessResult:
        key = str(provider_key or "").strip().lower()
        provider = self._providers.get(key)
        if provider is None:
            raise KeyError("provider readiness is unavailable")

        descriptor = provider.descriptor()
        reason = descriptor.unavailable_reason
        if not descriptor.available:
            state = (
                ProviderReadinessState.NOT_CONFIGURED
                if reason in {"endpoint_not_configured", "not_configured"}
                else ProviderReadinessState.CREDENTIAL_MISSING
            )
            return self._result(key, state)

        try:
            status = provider.probe_readiness()
        except ExplorerError as exc:
            state = {
                "provider_tls_failed": ProviderReadinessState.TLS_FAILED,
                "provider_timeout": ProviderReadinessState.UNREACHABLE,
                "provider_unavailable": ProviderReadinessState.UNREACHABLE,
            }.get(exc.code, ProviderReadinessState.DEGRADED)
            return self._result(key, state)
        except Exception:
            # Never expose raw exception text, paths, URLs or credential data.
            return self._result(key, ProviderReadinessState.DEGRADED)

        if 200 <= status < 300:
            state = ProviderReadinessState.READY
        elif status in {401, 403}:
            state = ProviderReadinessState.AUTH_REJECTED
        elif status == 429:
            state = ProviderReadinessState.RATE_LIMITED
        elif status >= 500:
            state = ProviderReadinessState.DEGRADED
        else:
            # Includes redirects: probes never follow redirects.
            state = ProviderReadinessState.DEGRADED
        return self._result(key, state)

    def check_all(self) -> tuple[ProviderReadinessResult, ...]:
        return tuple(self.check(key) for key in sorted(self._providers))

    @staticmethod
    def _result(key: str, state: ProviderReadinessState) -> ProviderReadinessResult:
        checked_at = datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
        return ProviderReadinessResult(key, state, checked_at, _MESSAGES[state])


__all__ = ["ProviderReadinessResult", "ProviderReadinessService", "ProviderReadinessState"]
