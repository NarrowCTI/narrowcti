from dataclasses import dataclass


@dataclass(frozen=True)
class MISPEventCandidate:
    event: dict
    name: str
    description: str
    indicators: list[dict]
    ioc_count: int
    age: int | None
    score: int
