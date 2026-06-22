from dataclasses import dataclass, field
from typing import Mapping


@dataclass(frozen=True)
class MISPEventCandidate:
    event: dict
    name: str
    description: str
    indicators: list[dict]
    ioc_count: int
    age: int | None
    score: int
    score_details: Mapping[str, object] = field(default_factory=dict)
