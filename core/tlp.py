"""Legacy compatibility exports for TLP primitives."""

from narrowcti.domain.intelligence.tlp import (
    TLP_EQUIVALENTS,
    TLP_PREFIX,
    extract_tlp_values,
    normalize_allowed_tlp,
    normalize_tlp,
    tlp_is_allowed,
)

__all__ = [
    "TLP_EQUIVALENTS",
    "TLP_PREFIX",
    "extract_tlp_values",
    "normalize_allowed_tlp",
    "normalize_tlp",
    "tlp_is_allowed",
]
