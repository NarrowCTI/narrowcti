import hashlib
import json
import os
from dataclasses import asdict, dataclass, field
from typing import Mapping, Sequence

from core.decision_audit import utc_now


PENDING = "pending"
RELEASED = "released"
PARTIALLY_RELEASED = "partially-released"
REJECTED = "rejected"
EXPIRED = "expired"

ACTIVE_STATUSES = {PENDING}
FINAL_STATUSES = {RELEASED, PARTIALLY_RELEASED, REJECTED, EXPIRED}
VALID_STATUSES = ACTIVE_STATUSES | FINAL_STATUSES


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


class QuarantineRepository:
    def __init__(self, repository_file, release_audit_file=""):
        self.repository_file = repository_file
        self.release_audit_file = release_audit_file

    def add(self, record):
        data = record.to_dict() if hasattr(record, "to_dict") else dict(record)
        data["status"] = normalize_status(data.get("status", PENDING))
        if data["status"] != PENDING:
            raise ValueError("new quarantine records must start as pending")
        data["quarantine_id"] = data.get("quarantine_id") or quarantine_id_for(data)
        data["created_at"] = data.get("created_at") or utc_now()
        data["updated_at"] = data.get("updated_at") or data["created_at"]
        data["indicator_count"] = int(
            data.get("indicator_count") or len(data.get("indicators") or [])
        )
        self._append(data)
        return data

    def records(self, status=None):
        current = {}
        for record in self.events():
            quarantine_id = record.get("quarantine_id")
            if quarantine_id:
                current[quarantine_id] = record
        records = list(current.values())
        if status:
            normalized_status = normalize_status(status)
            records = [
                record
                for record in records
                if normalize_status(record.get("status", PENDING)) == normalized_status
            ]
        return sorted(
            records,
            key=lambda record: (
                record.get("created_at", ""),
                record.get("quarantine_id", ""),
            ),
        )

    def events(self):
        if not self.repository_file or not os.path.exists(self.repository_file):
            return []
        records = []
        with open(self.repository_file, "r", encoding="utf-8") as file_obj:
            for line in file_obj:
                stripped = line.strip()
                if stripped:
                    records.append(json.loads(stripped))
        return records

    def get(self, quarantine_id):
        for record in reversed(self.records()):
            if record.get("quarantine_id") == quarantine_id:
                return record
        raise KeyError(f"Unknown quarantine id: {quarantine_id}")

    def reject(self, quarantine_id, reason, reviewer="operator", require_reason=True):
        return self._transition(
            quarantine_id,
            action="reject",
            status=REJECTED,
            reason=reason,
            reviewer=reviewer,
            require_reason=require_reason,
        )

    def release(self, quarantine_id, reason, reviewer="operator", require_reason=True):
        return self._transition(
            quarantine_id,
            action="release",
            status=RELEASED,
            reason=reason,
            reviewer=reviewer,
            require_reason=require_reason,
        )

    def release_indicators(
        self,
        quarantine_id,
        indicator_types,
        reason,
        reviewer="operator",
        require_reason=True,
    ):
        selected_types = normalize_indicator_types(indicator_types)
        if not selected_types:
            raise ValueError("at least one indicator type is required")
        return self._transition(
            quarantine_id,
            action="release-indicators",
            status=None,
            reason=reason,
            reviewer=reviewer,
            require_reason=require_reason,
            indicator_types=selected_types,
        )

    def _transition(
        self,
        quarantine_id,
        action,
        status,
        reason,
        reviewer,
        require_reason=True,
        indicator_types=(),
    ):
        if require_reason and not str(reason or "").strip():
            raise ValueError("review reason is required")
        current = self.get(quarantine_id)
        current_status = normalize_status(current.get("status", PENDING))
        if current_status != PENDING:
            raise ValueError(
                f"quarantine record is not pending: {quarantine_id} status={current_status}"
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

        now = utc_now()
        review = {
            "action": action,
            "reviewer": reviewer or "operator",
            "reason": str(reason or "").strip(),
            "recorded_at": now,
            "released_indicator_types": list(selected_types),
            "released_indicator_count": len(released),
            "held_indicator_count": len(held),
            "exported": False,
        }
        updated = dict(current)
        updated.update(
            {
                "status": next_status,
                "updated_at": now,
                "review": review,
            }
        )
        self._append(updated)
        self._append_release_audit(updated)
        return updated

    def _append(self, record):
        if not self.repository_file:
            raise ValueError("repository file is required")
        directory = os.path.dirname(self.repository_file)
        if directory:
            os.makedirs(directory, exist_ok=True)
        with open(self.repository_file, "a", encoding="utf-8") as file_obj:
            file_obj.write(json.dumps(record, sort_keys=True) + "\n")

    def _append_release_audit(self, record):
        if not self.release_audit_file:
            return
        review = dict(record.get("review") or {})
        event = {
            "recorded_at": review.get("recorded_at") or utc_now(),
            "quarantine_id": record.get("quarantine_id", ""),
            "status": record.get("status", ""),
            "action": review.get("action", ""),
            "reviewer": review.get("reviewer", ""),
            "reason": review.get("reason", ""),
            "source_key": record.get("source_key", ""),
            "external_id": record.get("external_id", ""),
            "title": record.get("title", ""),
            "released_indicator_types": review.get("released_indicator_types", []),
            "released_indicator_count": review.get("released_indicator_count", 0),
            "held_indicator_count": review.get("held_indicator_count", 0),
            "exported": review.get("exported", False),
        }
        directory = os.path.dirname(self.release_audit_file)
        if directory:
            os.makedirs(directory, exist_ok=True)
        with open(self.release_audit_file, "a", encoding="utf-8") as file_obj:
            file_obj.write(json.dumps(event, sort_keys=True) + "\n")


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
