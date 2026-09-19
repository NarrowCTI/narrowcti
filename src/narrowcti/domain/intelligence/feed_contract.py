"""Pure feed value objects shared by source adapters."""

import re
from dataclasses import dataclass, field
from typing import Mapping, Sequence


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
