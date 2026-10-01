"""Validated dispatch and safe aggregation for Source Explorer providers."""

from __future__ import annotations

from collections.abc import Iterable
from types import MappingProxyType

from narrowcti.application.provider_readiness import (
    ProviderReadinessResult,
    ProviderReadinessService,
)
from narrowcti.ports.source_explorer import (
    ExplorerError,
    ExplorerItemDetail,
    ExplorerSearchRequest,
    ExplorerSearchResult,
    ProviderDescriptor,
    SourceExplorerProvider,
)


MAX_QUERY_LENGTH = 256
MAX_FILTERS = 10
MAX_FILTER_KEY_LENGTH = 64
MAX_FILTER_VALUE_LENGTH = 128
MAX_RESULTS = 10


class SourceExplorerService:
    """Aggregate individual providers without changing ingestion registry."""

    def __init__(self, providers: Iterable[SourceExplorerProvider] = ()) -> None:
        self._providers: dict[str, SourceExplorerProvider] = {}
        for provider in providers:
            descriptor = provider.descriptor()
            if not descriptor.key or descriptor.key in self._providers:
                raise ValueError("source explorer provider keys must be unique and non-empty")
            self._providers[descriptor.key] = provider
        self._readiness = ProviderReadinessService(self._providers.values())

    def providers(self) -> tuple[ProviderDescriptor, ...]:
        return tuple(
            provider.descriptor()
            for _, provider in sorted(self._providers.items())
        )

    def check_readiness(self, provider_key: str) -> ProviderReadinessResult:
        """Perform an explicit bounded probe, separate from configuration descriptors."""
        try:
            return self._readiness.check(provider_key)
        except KeyError:
            raise ExplorerError("provider_unknown", "The selected provider is not available.") from None

    def check_readiness_all(self) -> tuple[ProviderReadinessResult, ...]:
        return self._readiness.check_all()

    def search(self, request: ExplorerSearchRequest) -> ExplorerSearchResult:
        provider = self._get_provider(request.provider_key)
        descriptor = provider.descriptor()
        if not descriptor.available:
            raise ExplorerError("provider_unavailable", "This provider is unavailable.")
        if not any(operation.value == "search" for operation in descriptor.operations):
            raise ExplorerError("operation_unsupported", "Search is not supported by this provider.")
        normalized = self._validate_request(request, descriptor)
        return provider.search(normalized)

    def detail(self, provider_key: str, external_id: str) -> ExplorerItemDetail:
        provider = self._get_provider(provider_key)
        descriptor = provider.descriptor()
        if not descriptor.available:
            raise ExplorerError("provider_unavailable", "This provider is unavailable.")
        if not any(operation.value == "detail" for operation in descriptor.operations):
            raise ExplorerError("operation_unsupported", "Details are not supported by this provider.")
        identifier = str(external_id or "").strip()
        if not identifier or len(identifier) > 256 or any(ord(char) < 32 for char in identifier):
            raise ExplorerError("invalid_request", "The selected source identifier is invalid.")
        return provider.detail(identifier)

    def _get_provider(self, key: str) -> SourceExplorerProvider:
        provider = self._providers.get(str(key or "").strip().lower())
        if provider is None:
            raise ExplorerError("provider_unknown", "The selected provider is not available.")
        return provider

    @staticmethod
    def _validate_request(
        request: ExplorerSearchRequest,
        descriptor: ProviderDescriptor,
    ) -> ExplorerSearchRequest:
        query = str(request.query or "").strip()
        if not query or len(query) > MAX_QUERY_LENGTH:
            raise ExplorerError("invalid_request", "Search text must contain 1 to 256 characters.")
        if request.limit < 1 or request.limit > MAX_RESULTS:
            raise ExplorerError("invalid_request", "Result limit is outside the supported range.")
        supplied = dict(request.filters or {})
        if len(supplied) > MAX_FILTERS:
            raise ExplorerError("invalid_request", "Too many provider filters were supplied.")
        allowed = {item.key: item for item in descriptor.filters}
        normalized: dict[str, str | tuple[str, ...]] = {}
        for key, value in supplied.items():
            if not isinstance(key, str) or len(key) > MAX_FILTER_KEY_LENGTH or key not in allowed:
                raise ExplorerError("invalid_request", "An unsupported provider filter was supplied.")
            filter_spec = allowed[key]
            values = value if isinstance(value, (tuple, list)) else (value,)
            if len(values) > (10 if filter_spec.multiple else 1):
                raise ExplorerError("invalid_request", "A provider filter has too many values.")
            cleaned = tuple(str(item).strip() for item in values)
            if any(not item or len(item) > min(filter_spec.max_length, MAX_FILTER_VALUE_LENGTH) for item in cleaned):
                raise ExplorerError("invalid_request", "A provider filter value is invalid.")
            if filter_spec.choices and any(item not in filter_spec.choices for item in cleaned):
                raise ExplorerError("invalid_request", "A provider filter value is unsupported.")
            normalized[key] = cleaned if filter_spec.multiple else cleaned[0]
        for key, filter_spec in allowed.items():
            if filter_spec.required and key not in normalized:
                raise ExplorerError("invalid_request", "A required provider filter is missing.")
        return ExplorerSearchRequest(
            provider_key=descriptor.key,
            query=query,
            filters=MappingProxyType(normalized),
            limit=request.limit,
        )


__all__ = [
    "MAX_FILTERS",
    "MAX_FILTER_KEY_LENGTH",
    "MAX_FILTER_VALUE_LENGTH",
    "MAX_QUERY_LENGTH",
    "MAX_RESULTS",
    "SourceExplorerService",
]
