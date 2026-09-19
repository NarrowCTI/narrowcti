"""Compatibility surface for contextual scoring and settings adaptation.

The scoring/evidence functions are pure domain primitives.  The settings
adapter remains in this legacy runtime module until configuration ownership is
migrated in a later wave.
"""

from narrowcti.domain.intelligence.contextual_scoring import (
    CATEGORY_BY_ENTITY_TYPE,
    CONTEXTUAL_SCORING_MODE_ALIASES,
    CONTEXTUAL_SCORING_MODES,
    CONTEXTUAL_SCORING_VERSION,
    DEFAULT_CATEGORY_IMPACTS,
    accepted_candidate_count,
    accepted_candidates,
    build_contextual_score_evidence,
    clean_string,
    coerce_int,
    contextual_adjustments,
    contextual_score_result,
    finalize_contextual_score_evidence,
    normalize_category_impacts,
    normalize_contextual_scoring_max_impact,
    normalize_contextual_scoring_mode,
    parse_contextual_scoring_impacts,
)


def contextual_scoring_config_from_settings(settings):
    """Adapt typed/runtime settings into the pure scoring configuration."""
    return {
        "mode": normalize_contextual_scoring_mode(
            getattr(settings, "contextual_scoring_mode", "shadow")
        ),
        "category_impacts": parse_contextual_scoring_impacts(
            getattr(settings, "contextual_scoring_impacts", {})
        ),
        "max_impact": normalize_contextual_scoring_max_impact(
            getattr(settings, "contextual_scoring_max_impact", 100)
        ),
    }


__all__ = [
    "CATEGORY_BY_ENTITY_TYPE",
    "CONTEXTUAL_SCORING_MODE_ALIASES",
    "CONTEXTUAL_SCORING_MODES",
    "CONTEXTUAL_SCORING_VERSION",
    "DEFAULT_CATEGORY_IMPACTS",
    "accepted_candidate_count",
    "accepted_candidates",
    "build_contextual_score_evidence",
    "clean_string",
    "coerce_int",
    "contextual_adjustments",
    "contextual_score_result",
    "contextual_scoring_config_from_settings",
    "finalize_contextual_score_evidence",
    "normalize_category_impacts",
    "normalize_contextual_scoring_max_impact",
    "normalize_contextual_scoring_mode",
    "parse_contextual_scoring_impacts",
]
