from dataclasses import dataclass


@dataclass(frozen=True)
class PulseCandidate:
    pulse: dict
    name: str
    description: str
    indicators: list[dict]
    ioc_count: int
    age: int | None
    score: int


@dataclass(frozen=True)
class QuerySummary:
    query: str
    reviewed: int
    ingested: int
    available: int
