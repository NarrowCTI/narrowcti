"""Legacy compatibility exports for indicator filtering policy."""

from narrowcti.domain.intelligence.indicator_policy import (
    filter_indicators_by_type,
    normalize_allowed_indicator_types,
)

__all__ = ["filter_indicators_by_type", "normalize_allowed_indicator_types"]
