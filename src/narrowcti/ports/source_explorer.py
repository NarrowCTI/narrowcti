"""Provider-neutral contracts for bounded, read-only Source Explorer access."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Mapping, Protocol


class ProviderOperation(StrEnum):
    SEARCH = "search"
    DETAIL = "detail"


@dataclass(frozen=True)
class ProviderFilterDescriptor:
    key: str
    label: str
    value_type: str = "text"
    required: bool = False
    multiple: bool = False
    max_length: int = 128
    choices: tuple[str, ...] = ()


@dataclass(frozen=True)
class ProviderDescriptor:
    key: str
    display_name: str
    available: bool
    unavailable_reason: str | None = None
    operations: tuple[ProviderOperation, ...] = ()
    filters: tuple[ProviderFilterDescriptor, ...] = ()


@dataclass(frozen=True)
class ExplorerSearchRequest:
    provider_key: str
    query: str
    filters: Mapping[str, str | tuple[str, ...]] = field(default_factory=dict)
    limit: int = 10


@dataclass(frozen=True)
class ExplorerItemSummary:
    provider_key: str
    external_id: str
    title: str
    published_at: str | None = None
    tlp: str | None = None
    tags: tuple[str, ...] = ()
    revision_fingerprint: str | None = None


@dataclass(frozen=True)
class ExplorerSearchResult:
    provider_key: str
    items: tuple[ExplorerItemSummary, ...]
    truncated: bool | None = None
    has_more: bool | None = None
    source_total: int | None = None


@dataclass(frozen=True)
class ExplorerItemDetail:
    summary: ExplorerItemSummary
    fields: Mapping[str, object]
    provenance: Mapping[str, object]


@dataclass(frozen=True)
class ExplorerError(Exception):
    code: str
    public_message: str
    retryable: bool = False
    correlation_id: str = ""

    def __str__(self) -> str:
        return self.public_message


class SourceExplorerProvider(Protocol):
    """Contract implemented by exactly one configured provider."""

    def descriptor(self) -> ProviderDescriptor: ...

    def search(self, request: ExplorerSearchRequest) -> ExplorerSearchResult: ...

    def detail(self, external_id: str) -> ExplorerItemDetail: ...


__all__ = [
    "ExplorerError",
    "ExplorerItemDetail",
    "ExplorerItemSummary",
    "ExplorerSearchRequest",
    "ExplorerSearchResult",
    "ProviderDescriptor",
    "ProviderFilterDescriptor",
    "ProviderOperation",
    "SourceExplorerProvider",
]
