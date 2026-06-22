from dataclasses import dataclass, field
from typing import Mapping


@dataclass(frozen=True)
class PulseCandidate:
    pulse: dict
    name: str
    description: str
    indicators: list[dict]
    ioc_count: int
    age: int | None
    score: int
    score_details: Mapping[str, object] = field(default_factory=dict)


@dataclass(frozen=True)
class QuerySummary:
    query: str
    reviewed: int
    ingested: int
    available: int
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
