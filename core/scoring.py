"""Legacy compatibility exports for the canonical scoring primitives."""

from narrowcti.domain.intelligence.scoring import (
    BASE_SCORE,
    NEUTRAL_SOURCE_CONFIDENCE,
    age_days,
    calculate_score,
    calculate_score_details,
    clamp_score,
    has_query_term,
    query_terms,
    score_adjustment,
    source_confidence_adjustment,
)

__all__ = [
    "BASE_SCORE",
    "NEUTRAL_SOURCE_CONFIDENCE",
    "age_days",
    "calculate_score",
    "calculate_score_details",
    "clamp_score",
    "has_query_term",
    "query_terms",
    "score_adjustment",
    "source_confidence_adjustment",
]
