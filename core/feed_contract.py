import re
from dataclasses import dataclass, field
from typing import Mapping, Protocol, Sequence, runtime_checkable


def slugify(value):
    normalized = re.sub(r"[^a-z0-9]+", "-", value.strip().lower()).strip("-")
    return normalized or "unknown"


@dataclass(frozen=True)
class FeedSource:
    name: str
    source_type: str
    provider: str = ""
    default_confidence: int = 50

    @property
    def key(self):
        provider = slugify(self.provider or "local")
        return f"{provider}:{slugify(self.name)}"


@dataclass(frozen=True)
class FeedCandidate:
    source: FeedSource
    external_id: str
    title: str
    description: str = ""
    created: str | None = None
    indicators: Sequence[Mapping[str, object]] = field(default_factory=tuple)
    tags: Sequence[str] = field(default_factory=tuple)
    raw: Mapping[str, object] = field(default_factory=dict)

    def __post_init__(self):
        object.__setattr__(self, "indicators", tuple(self.indicators or ()))
        object.__setattr__(self, "tags", tuple(self.tags or ()))


@dataclass(frozen=True)
class FeedRunSummary:
    source: FeedSource
    query: str
    available: int = 0
    reviewed: int = 0
    ingested: int = 0
    dropped: int = 0
    quarantined: int = 0
    skipped: int = 0
    errors: int = 0

    @property
    def handled(self):
        return (
            self.ingested
            + self.dropped
            + self.quarantined
            + self.skipped
            + self.errors
        )


@runtime_checkable
class FeedAdapter(Protocol):
    source: FeedSource

    def search(self, query):
        """Return lightweight feed candidates for a query."""

    def enrich(self, candidate):
        """Return an enriched candidate, or None when enrichment fails."""
