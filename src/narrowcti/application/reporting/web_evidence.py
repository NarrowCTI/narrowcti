"""Safe, bounded projections for the Community Web evidence view."""

from __future__ import annotations

from collections.abc import Callable, Mapping


_SAFE_FIELDS = (
    "recorded_at",
    "action",
    "reason",
    "source_key",
    "external_id",
    "title",
    "score",
    "age_days",
    "indicator_count",
)


class WebEvidenceService:
    """Expose only bounded audit fields; raw metadata and provider payloads stay private."""

    def __init__(self, read_records: Callable[[int], list[dict]] | None):
        self._read_records = read_records

    @property
    def available(self) -> bool:
        return self._read_records is not None

    def recent(self, limit: int = 100) -> list[dict]:
        if not 1 <= limit <= 100:
            raise ValueError("evidence limit must be between 1 and 100")
        if self._read_records is None:
            raise RuntimeError("decision evidence is unavailable")
        records = self._read_records(limit)
        projected = []
        for record in records[-limit:]:
            if not isinstance(record, Mapping):
                continue
            item = {}
            for key in _SAFE_FIELDS:
                value = record.get(key)
                if isinstance(value, str):
                    item[key] = value[:256]
                elif key in {"score", "age_days", "indicator_count"} and isinstance(value, (int, float)):
                    item[key] = value
            projected.append(item)
        return projected


__all__ = ["WebEvidenceService"]
