"""Compatibility boundary for quarantine domain and local persistence."""

import json

from narrowcti.adapters.persistence.local.quarantine_repository import (
    QuarantineRepository,
)
from narrowcti.domain.review.quarantine import (
    ACTIVE_STATUSES,
    EXPIRED,
    EXPORTABLE_STATUSES,
    FINAL_STATUSES,
    PARTIALLY_RELEASED,
    PENDING,
    REJECTED,
    RELEASED,
    VALID_STATUSES,
    QuarantineRecord,
    indicator_type,
    normalize_indicator_types,
    normalize_status,
    quarantine_id_for,
    released_indicators,
    utc_now,
)


def bounded_raw_snapshot(value, max_bytes=65536):
    """Bound raw evidence without changing the historical payload shape."""

    if value is None:
        return None, False
    try:
        encoded = json.dumps(value, sort_keys=True, default=str).encode("utf-8")
    except TypeError:
        value = str(value)
        encoded = value.encode("utf-8")
    limit = int(max_bytes or 0)
    if limit < 1:
        return None, True
    if len(encoded) <= limit:
        return value, False
    preview = encoded[:limit].decode("utf-8", errors="replace")
    return {"truncated": True, "preview": preview}, True


__all__ = [
    "ACTIVE_STATUSES",
    "EXPIRED",
    "EXPORTABLE_STATUSES",
    "FINAL_STATUSES",
    "PARTIALLY_RELEASED",
    "PENDING",
    "REJECTED",
    "RELEASED",
    "VALID_STATUSES",
    "QuarantineRecord",
    "QuarantineRepository",
    "bounded_raw_snapshot",
    "indicator_type",
    "normalize_indicator_types",
    "normalize_status",
    "quarantine_id_for",
    "released_indicators",
    "utc_now",
]
