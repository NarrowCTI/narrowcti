"""Pure quarantine records, normalization and transition semantics."""

from __future__ import annotations

import hashlib
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Mapping, Sequence


PENDING = "pending"
RELEASED = "released"
PARTIALLY_RELEASED = "partially-released"
REJECTED = "rejected"
EXPIRED = "expired"

ACTIVE_STATUSES = {PENDING}
FINAL_STATUSES = {RELEASED, PARTIALLY_RELEASED, REJECTED, EXPIRED}
VALID_STATUSES = ACTIVE_STATUSES | FINAL_STATUSES
EXPORTABLE_STATUSES = {RELEASED, PARTIALLY_RELEASED}


def utc_now():
    """Return the historical UTC representation without microseconds."""

    return (
        datetime.now(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


@dataclass(frozen=True)
class QuarantineRecord:
    source_key: str
    external_id: str
    title: str
    reason: str
    query: str = ""
    score: int | None = None
    age_days: int | None = None
    indicator_count: int = 0
    indicators: Sequence[Mapping[str, object]] = field(default_factory=tuple)
    metadata: Mapping[str, object] = field(default_factory=dict)
    raw_snapshot: object | None = None
    quarantine_id: str = ""
    status: str = PENDING
    created_at: str = field(default_factory=utc_now)
    updated_at: str = ""
    review: Mapping[str, object] = field(default_factory=dict)

    def to_dict(self):
        data = asdict(self)
        data["indicators"] = [dict(indicator) for indicator in self.indicators or ()]
        data["indicator_count"] = self.indicator_count or len(data["indicators"])
        data["metadata"] = dict(self.metadata or {})
        data["review"] = dict(self.review or {})
        data["quarantine_id"] = self.quarantine_id or quarantine_id_for(data)
        data["status"] = normalize_status(self.status)
        data["updated_at"] = self.updated_at or self.created_at
        return data


def quarantine_id_for(record):
    parts = [
        str(record.get("source_key", "")),
        str(record.get("external_id", "")),
        str(record.get("query", "")),
        str(record.get("title", "")),
    ]
    digest = hashlib.sha256("|".join(parts).encode("utf-8")).hexdigest()
    return f"q-{digest[:16]}"


def normalize_status(status):
    normalized = str(status or PENDING).strip().lower()
    if normalized not in VALID_STATUSES:
        raise ValueError(f"invalid quarantine status: {status}")
    return normalized


def normalize_indicator_types(indicator_types):
    if not indicator_types:
        return ()
    if isinstance(indicator_types, str):
        values = indicator_types.split(",")
    else:
        values = indicator_types
    return tuple(
        value.strip().lower()
        for value in values
        if str(value or "").strip()
    )


def indicator_type(indicator):
    if not isinstance(indicator, Mapping):
        return ""
    return str(
        indicator.get("type")
        or indicator.get("indicator_type")
        or indicator.get("observable_type")
        or ""
    ).strip().lower()


def released_indicators(record):
    status = normalize_status(record.get("status", PENDING))
    if status not in EXPORTABLE_STATUSES:
        return []
    indicators = [dict(indicator) for indicator in record.get("indicators") or []]
    if status == RELEASED:
        return indicators

    released_types = normalize_indicator_types(
        (record.get("review") or {}).get("released_indicator_types") or (),
    )
    if not released_types:
        return []
    return [
        indicator
        for indicator in indicators
        if indicator_type(indicator) in released_types
    ]


def validate_review_reason(reason, require_reason=True):
    if require_reason and not str(reason or "").strip():
        raise ValueError("review reason is required")


def _transition(
    record,
    *,
    action,
    status,
    reason,
    reviewer,
    require_reason,
    indicator_types,
    recorded_at,
):
    validate_review_reason(reason, require_reason)
    current = dict(record)
    current_status = normalize_status(current.get("status", PENDING))
    if current_status != PENDING:
        raise ValueError(
            f"quarantine record is not pending: {current.get('quarantine_id', '')} "
            f"status={current_status}"
        )

    indicators = [dict(indicator) for indicator in current.get("indicators") or []]
    selected_types = normalize_indicator_types(indicator_types)
    if selected_types:
        released = [
            indicator
            for indicator in indicators
            if indicator_type(indicator) in selected_types
        ]
        held = [
            indicator
            for indicator in indicators
            if indicator_type(indicator) not in selected_types
        ]
        if not released:
            raise ValueError("no indicators match the selected release types")
        next_status = PARTIALLY_RELEASED if held else RELEASED
    elif action == "reject":
        released = []
        held = indicators
        next_status = REJECTED
    else:
        released = indicators
        held = []
        next_status = status or RELEASED

    review = {
        "action": action,
        "reviewer": reviewer or "operator",
        "reason": str(reason or "").strip(),
        "recorded_at": recorded_at,
        "released_indicator_types": list(selected_types),
        "released_indicator_count": len(released),
        "held_indicator_count": len(held),
        "exported": False,
    }
    updated = dict(current)
    updated.update(
        {
            "status": next_status,
            "updated_at": recorded_at,
            "review": review,
        }
    )
    return updated


def transition_reject(record, reason, reviewer="operator", require_reason=True, *, recorded_at):
    return _transition(
        record,
        action="reject",
        status=REJECTED,
        reason=reason,
        reviewer=reviewer,
        require_reason=require_reason,
        indicator_types=(),
        recorded_at=recorded_at,
    )


def transition_release(record, reason, reviewer="operator", require_reason=True, *, recorded_at):
    return _transition(
        record,
        action="release",
        status=RELEASED,
        reason=reason,
        reviewer=reviewer,
        require_reason=require_reason,
        indicator_types=(),
        recorded_at=recorded_at,
    )


def transition_release_indicators(
    record,
    indicator_types,
    reason,
    reviewer="operator",
    require_reason=True,
    *,
    recorded_at,
):
    return _transition(
        record,
        action="release-indicators",
        status=None,
        reason=reason,
        reviewer=reviewer,
        require_reason=require_reason,
        indicator_types=indicator_types,
        recorded_at=recorded_at,
    )


def transition_mark_exported(
    record,
    exported_indicator_count,
    dedup_duplicate_count=0,
    exported_by="gateway.quarantine",
    *,
    recorded_at,
):
    current = dict(record)
    current_status = normalize_status(current.get("status", PENDING))
    if current_status not in EXPORTABLE_STATUSES:
        raise ValueError(
            f"quarantine record is not exportable: "
            f"{current.get('quarantine_id', '')} status={current_status}"
        )
    review = dict(current.get("review") or {})
    if review.get("exported"):
        raise ValueError(
            f"quarantine record is already exported: {current.get('quarantine_id', '')}"
        )

    review.update(
        {
            "exported": True,
            "exported_at": recorded_at,
            "exported_by": exported_by or "gateway.quarantine",
            "exported_indicator_count": int(exported_indicator_count or 0),
            "dedup_duplicate_count": int(dedup_duplicate_count or 0),
        }
    )
    updated = dict(current)
    updated.update(
        {
            "updated_at": recorded_at,
            "review": review,
        }
    )
    return updated


__all__ = [
    "ACTIVE_STATUSES",
    "EXPIRED",
    "EXPORTABLE_STATUSES",
    "FINAL_STATUSES",
    "PARTIALLY_RELEASED",
    "PENDING",
    "REJECTED",
    "RELEASED",
    "QuarantineRecord",
    "VALID_STATUSES",
    "indicator_type",
    "normalize_indicator_types",
    "normalize_status",
    "quarantine_id_for",
    "released_indicators",
    "transition_mark_exported",
    "transition_reject",
    "transition_release",
    "transition_release_indicators",
    "utc_now",
    "validate_review_reason",
]
