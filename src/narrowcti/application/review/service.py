"""Filesystem- and provider-neutral analyst review service."""

from dataclasses import dataclass
from typing import Callable

from narrowcti.domain.review.quarantine import normalize_status

from .export import QuarantineExporter


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
    """Coordinate review decisions while receiving side effects explicitly."""

    def __init__(
        self,
        repository,
        *,
        audit_reader: Callable[[], list] | None = None,
        export_operation: Callable | None = None,
        reviewer="operator",
        require_reason=True,
    ):
        self.repository = repository
        self.audit_reader = audit_reader or (lambda: [])
        self.export_operation = export_operation
        self.reviewer = reviewer or "operator"
        self.require_reason = bool(require_reason)

    def list_records(self, status="pending", source_key="", limit=0):
        records = self.repository.records(status=None if status == "all" else status)
        if source_key:
            records = [record for record in records if record.get("source_key", "") == source_key]
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
            quarantine_id, reason, reviewer=reviewer or self.reviewer,
            require_reason=self.require_reason,
        )

    def release(self, quarantine_id, reason, reviewer=""):
        return self.repository.release(
            quarantine_id, reason, reviewer=reviewer or self.reviewer,
            require_reason=self.require_reason,
        )

    def release_indicators(self, quarantine_id, indicator_types, reason, reviewer=""):
        return self.repository.release_indicators(
            quarantine_id, indicator_types, reason,
            reviewer=reviewer or self.reviewer,
            require_reason=self.require_reason,
        )

    def export_released(
        self, quarantine_id="", limit=0, api_client=None, artifact_dedup=None,
        identity_name="NarrowCTI Gateway", logger=None, dry_run=True,
        exported_by="gateway.quarantine", exporter=None,
    ):
        operation = self.export_operation if exporter is None else exporter
        export_service = QuarantineExporter(
            self.repository,
            api_client=api_client,
            exporter=operation,
            artifact_dedup=artifact_dedup,
            identity_name=identity_name,
            logger=logger,
            dry_run=dry_run,
            exported_by=exported_by,
        )
        return export_service.export_pending(quarantine_id, limit=limit)

    def audit_events(self, quarantine_id="", action="", limit=0):
        events = list(self.audit_reader() or [])
        if quarantine_id:
            events = [event for event in events if event.get("quarantine_id", "") == quarantine_id]
        if action:
            events = [event for event in events if event.get("action", "") == action]
        if limit and limit > 0:
            events = events[-limit:]
        return events
