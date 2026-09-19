"""Legacy feed contract compatibility surface.

The pure feed value objects are owned by the canonical domain module.  The
adapter protocol and run summary remain here until the source-port and
application ingestion waves are implemented.
"""

from dataclasses import dataclass
from typing import Protocol, runtime_checkable

from narrowcti.domain.intelligence.feed_contract import (
    FeedCandidate,
    FeedSource,
    slugify,
)

__all__ = [
    "FeedAdapter",
    "FeedCandidate",
    "FeedRunSummary",
    "FeedSource",
    "slugify",
]


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
    dry_run: int = 0

    @property
    def handled(self):
        return (
            self.ingested
            + self.dropped
            + self.quarantined
            + self.skipped
            + self.errors
            + self.dry_run
        )


@runtime_checkable
class FeedAdapter(Protocol):
    source: FeedSource

    def search(self, query):
        """Return lightweight feed candidates for a query."""

    def enrich(self, candidate):
        """Return an enriched candidate, or None when enrichment fails."""
