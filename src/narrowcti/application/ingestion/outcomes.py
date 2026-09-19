"""Stable candidate-level ingestion outcomes."""

from dataclasses import dataclass
from typing import Literal


INGESTION_OUTCOMES = (
    "ingest",
    "drop",
    "quarantine",
    "skip",
    "error",
    "dry_run",
)
OutcomeAction = Literal[
    "ingest",
    "drop",
    "quarantine",
    "skip",
    "error",
    "dry_run",
]


@dataclass(frozen=True)
class IngestionOutcome:
    """An application decision without source or audit implementation details."""

    action: OutcomeAction
    reason: str = ""

    def __post_init__(self):
        if self.action not in INGESTION_OUTCOMES:
            raise ValueError(f"unsupported ingestion outcome: {self.action}")


__all__ = ["INGESTION_OUTCOMES", "IngestionOutcome", "OutcomeAction"]
