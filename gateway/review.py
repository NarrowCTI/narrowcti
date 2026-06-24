import json
import os
from dataclasses import dataclass

from core.quarantine import QuarantineRepository, normalize_status
from gateway.quarantine_export import QuarantineExporter


@dataclass(frozen=True)
class ReviewSummary:
    record_count: int
    status_counts: dict
    source_counts: dict
    pending_count: int
    exportable_count: int

    def to_dict(self):
        return {
            "record_count": self.record_count,
            "status_counts": dict(self.status_counts),
            "source_counts": dict(self.source_counts),
            "pending_count": self.pending_count,
            "exportable_count": self.exportable_count,
        }


class AnalystReviewService:
    def __init__(
        self,
        repository,
        release_audit_file="",
        reviewer="operator",
        require_reason=True,
    ):
        self.repository = repository
        self.release_audit_file = (
            release_audit_file
            or getattr(repository, "release_audit_file", "")
        )
        self.reviewer = reviewer or "operator"
        self.require_reason = bool(require_reason)

    @classmethod
    def from_paths(
        cls,
        repository_file,
        release_audit_file="",
        reviewer="operator",
        require_reason=True,
    ):
        repository = QuarantineRepository(repository_file, release_audit_file)
        return cls(
            repository,
            release_audit_file=release_audit_file,
            reviewer=reviewer,
            require_reason=require_reason,
        )

    def list_records(self, status="pending", source_key="", limit=0):
        records = self.repository.records(
            status=None if status == "all" else status
        )
        if source_key:
            records = [
                record
                for record in records
                if record.get("source_key", "") == source_key
            ]
        if limit and limit > 0:
            records = records[-limit:]
        return records

    def get_record(self, quarantine_id):
        return self.repository.get(quarantine_id)

    def summary(self):
        records = self.repository.records()
        status_counts = {}
        source_counts = {}
        exportable_count = 0
        for record in records:
            status = normalize_status(record.get("status"))
            source_key = record.get("source_key") or "(unknown)"
            status_counts[status] = status_counts.get(status, 0) + 1
            source_counts[source_key] = source_counts.get(source_key, 0) + 1
            if status in ("released", "partially-released"):
                exportable_count += 1
        return ReviewSummary(
            record_count=len(records),
            status_counts=status_counts,
            source_counts=source_counts,
            pending_count=status_counts.get("pending", 0),
            exportable_count=exportable_count,
        )

    def reject(self, quarantine_id, reason, reviewer=""):
        return self.repository.reject(
            quarantine_id,
            reason,
            reviewer=reviewer or self.reviewer,
            require_reason=self.require_reason,
        )

    def release(self, quarantine_id, reason, reviewer=""):
        return self.repository.release(
            quarantine_id,
            reason,
            reviewer=reviewer or self.reviewer,
            require_reason=self.require_reason,
        )

    def release_indicators(
        self,
        quarantine_id,
        indicator_types,
        reason,
        reviewer="",
    ):
        return self.repository.release_indicators(
            quarantine_id,
            indicator_types,
            reason,
            reviewer=reviewer or self.reviewer,
            require_reason=self.require_reason,
        )

    def export_released(
        self,
        quarantine_id="",
        limit=0,
        api_client=None,
        artifact_dedup=None,
        identity_name="NarrowCTI Gateway",
        logger=None,
        dry_run=True,
    ):
        exporter = QuarantineExporter(
            self.repository,
            api_client=api_client,
            artifact_dedup=artifact_dedup,
            identity_name=identity_name,
            logger=logger,
            dry_run=dry_run,
        )
        return exporter.export_pending(quarantine_id, limit=limit)

    def audit_events(self, quarantine_id="", action="", limit=0):
        events = read_audit_events(self.release_audit_file)
        if quarantine_id:
            events = [
                event
                for event in events
                if event.get("quarantine_id", "") == quarantine_id
            ]
        if action:
            events = [
                event
                for event in events
                if event.get("action", "") == action
            ]
        if limit and limit > 0:
            events = events[-limit:]
        return events


def read_audit_events(path):
    if not path or not os.path.exists(path):
        return []
    events = []
    with open(path, "r", encoding="utf-8") as file_obj:
        for line in file_obj:
            stripped = line.strip()
            if stripped:
                events.append(json.loads(stripped))
    return events
