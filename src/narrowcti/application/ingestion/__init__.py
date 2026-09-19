"""Candidate-level ingestion orchestration contracts."""

from .outcomes import INGESTION_OUTCOMES, IngestionOutcome
from .pipeline import run_candidate

__all__ = ["INGESTION_OUTCOMES", "IngestionOutcome", "run_candidate"]
