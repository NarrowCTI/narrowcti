"""Local append-only JSONL quarantine repository."""

from __future__ import annotations

import json
import os

from narrowcti.domain.review.quarantine import (
    PENDING,
    normalize_indicator_types,
    normalize_status,
    quarantine_id_for,
    transition_mark_exported,
    transition_reject,
    transition_release,
    transition_release_indicators,
    utc_now,
    validate_review_reason,
)


class QuarantineRepository:
    """Concrete Community repository preserving the historical API."""

    def __init__(self, repository_file, release_audit_file=""):
        self.repository_file = repository_file
        self.release_audit_file = release_audit_file

    def add(self, record):
        data = record.to_dict() if hasattr(record, "to_dict") else dict(record)
        data["status"] = normalize_status(data.get("status", PENDING))
        if data["status"] != PENDING:
            raise ValueError("new quarantine records must start as pending")
        data["quarantine_id"] = data.get("quarantine_id") or quarantine_id_for(data)
        existing = self.find(data["quarantine_id"])
        if existing:
            return existing
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
        record = self.find(quarantine_id)
        if record:
            return record
        raise KeyError(f"Unknown quarantine id: {quarantine_id}")

    def find(self, quarantine_id):
        for record in reversed(self.records()):
            if record.get("quarantine_id") == quarantine_id:
                return record
        return None

    def reject(self, quarantine_id, reason, reviewer="operator", require_reason=True):
        validate_review_reason(reason, require_reason)
        current = self.get(quarantine_id)
        updated = transition_reject(
            current,
            reason,
            reviewer=reviewer,
            require_reason=require_reason,
            recorded_at=utc_now(),
        )
        self._append(updated)
        self._append_release_audit(updated)
        return updated

    def release(self, quarantine_id, reason, reviewer="operator", require_reason=True):
        validate_review_reason(reason, require_reason)
        current = self.get(quarantine_id)
        updated = transition_release(
            current,
            reason,
            reviewer=reviewer,
            require_reason=require_reason,
            recorded_at=utc_now(),
        )
        self._append(updated)
        self._append_release_audit(updated)
        return updated

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
        validate_review_reason(reason, require_reason)
        current = self.get(quarantine_id)
        updated = transition_release_indicators(
            current,
            selected_types,
            reason,
            reviewer=reviewer,
            require_reason=require_reason,
            recorded_at=utc_now(),
        )
        self._append(updated)
        self._append_release_audit(updated)
        return updated

    def mark_exported(
        self,
        quarantine_id,
        exported_indicator_count,
        dedup_duplicate_count=0,
        exported_by="gateway.quarantine",
    ):
        current = self.get(quarantine_id)
        updated = transition_mark_exported(
            current,
            exported_indicator_count,
            dedup_duplicate_count=dedup_duplicate_count,
            exported_by=exported_by,
            recorded_at=utc_now(),
        )
        self._append(updated)
        self._append_release_audit(updated, action="export")
        return updated

    def _append(self, record):
        if not self.repository_file:
            raise ValueError("repository file is required")
        directory = os.path.dirname(self.repository_file)
        if directory:
            os.makedirs(directory, exist_ok=True)
        with open(self.repository_file, "a", encoding="utf-8") as file_obj:
            file_obj.write(json.dumps(record, sort_keys=True) + "\n")

    def _append_release_audit(self, record, action=""):
        if not self.release_audit_file:
            return
        review = dict(record.get("review") or {})
        audit_action = action or review.get("action", "")
        recorded_at = review.get("recorded_at") or utc_now()
        if audit_action == "export":
            recorded_at = review.get("exported_at") or recorded_at
        event = {
            "recorded_at": recorded_at,
            "quarantine_id": record.get("quarantine_id", ""),
            "status": record.get("status", ""),
            "action": audit_action,
            "reviewer": review.get("reviewer", ""),
            "reason": review.get("reason", ""),
            "source_key": record.get("source_key", ""),
            "external_id": record.get("external_id", ""),
            "title": record.get("title", ""),
            "released_indicator_types": review.get("released_indicator_types", []),
            "released_indicator_count": review.get("released_indicator_count", 0),
            "held_indicator_count": review.get("held_indicator_count", 0),
            "exported": review.get("exported", False),
            "exported_at": review.get("exported_at", ""),
            "exported_by": review.get("exported_by", ""),
            "exported_indicator_count": review.get("exported_indicator_count", 0),
            "dedup_duplicate_count": review.get("dedup_duplicate_count", 0),
        }
        directory = os.path.dirname(self.release_audit_file)
        if directory:
            os.makedirs(directory, exist_ok=True)
        with open(self.release_audit_file, "a", encoding="utf-8") as file_obj:
            file_obj.write(json.dumps(event, sort_keys=True) + "\n")


__all__ = ["QuarantineRepository"]
