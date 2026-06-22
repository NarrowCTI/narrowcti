from dataclasses import dataclass, field

from core.quarantine import (
    EXPORTABLE_STATUSES,
    normalize_status,
    released_indicators,
)
from exporters.opencti import send_bundle


@dataclass(frozen=True)
class QuarantineExportResult:
    quarantine_id: str
    status: str
    action: str
    reason: str = ""
    indicator_count: int = 0
    exported_indicator_count: int = 0
    dedup_duplicate_count: int = 0
    title: str = ""
    source_key: str = ""
    external_id: str = ""
    dry_run: bool = False
    errors: tuple[str, ...] = field(default_factory=tuple)

    def to_dict(self):
        return {
            "quarantine_id": self.quarantine_id,
            "status": self.status,
            "action": self.action,
            "reason": self.reason,
            "indicator_count": self.indicator_count,
            "exported_indicator_count": self.exported_indicator_count,
            "dedup_duplicate_count": self.dedup_duplicate_count,
            "title": self.title,
            "source_key": self.source_key,
            "external_id": self.external_id,
            "dry_run": self.dry_run,
            "errors": list(self.errors),
        }


class QuarantineExporter:
    def __init__(
        self,
        repository,
        api_client=None,
        exporter=send_bundle,
        artifact_dedup=None,
        identity_name="NarrowCTI Gateway",
        logger=None,
        dry_run=True,
        exported_by="gateway.quarantine",
    ):
        self.repository = repository
        self.api_client = api_client
        self.exporter = exporter
        self.artifact_dedup = artifact_dedup
        self.identity_name = identity_name or "NarrowCTI Gateway"
        self.logger = logger or (lambda message: None)
        self.dry_run = dry_run
        self.exported_by = exported_by or "gateway.quarantine"

    def export_pending(self, quarantine_id="", limit=0):
        if quarantine_id:
            return [self.export_record(self.repository.get(quarantine_id))]
        records = exportable_records(self.repository.records(), quarantine_id)
        if limit and limit > 0:
            records = records[:limit]
        return [self.export_record(record) for record in records]

    def export_record(self, record):
        base = result_base(record, dry_run=self.dry_run)
        status = normalize_status(record.get("status"))
        if status not in EXPORTABLE_STATUSES:
            return QuarantineExportResult(
                **base,
                action="skip",
                reason=f"status is not exportable: {status}",
            )
        review = record.get("review") or {}
        if review.get("exported"):
            return QuarantineExportResult(
                **base,
                action="skip",
                reason="already exported",
            )

        indicators = released_indicators(record)
        if not indicators:
            return QuarantineExportResult(
                **base,
                action="skip",
                reason="no released indicators",
            )

        indicators, duplicate_count = self.filter_new_indicators(record, indicators)
        if not indicators:
            if not self.dry_run:
                self.repository.mark_exported(
                    record["quarantine_id"],
                    exported_indicator_count=0,
                    dedup_duplicate_count=duplicate_count,
                    exported_by=self.exported_by,
                )
            return QuarantineExportResult(
                **base,
                action="dry-run" if self.dry_run else "dedup-skip",
                reason="all released indicators already known",
                indicator_count=len(released_indicators(record)),
                exported_indicator_count=0,
                dedup_duplicate_count=duplicate_count,
            )

        if self.dry_run:
            return QuarantineExportResult(
                **base,
                action="dry-run",
                reason="would export released quarantine record",
                indicator_count=len(indicators),
                exported_indicator_count=len(indicators),
                dedup_duplicate_count=duplicate_count,
            )

        try:
            exported_count = self.exporter(
                self.api_client,
                record_title(record),
                record_description(record),
                record_score(record),
                indicators,
                identity_name=self.identity_name,
            )
        except Exception as exc:
            self.logger(
                f"Quarantine export failed: id={record.get('quarantine_id')} error={exc}"
            )
            return QuarantineExportResult(
                **base,
                action="error",
                reason="export failed",
                indicator_count=len(indicators),
                dedup_duplicate_count=duplicate_count,
                errors=(str(exc),),
            )

        self.mark_artifacts(record, indicators)
        self.repository.mark_exported(
            record["quarantine_id"],
            exported_indicator_count=exported_count,
            dedup_duplicate_count=duplicate_count,
            exported_by=self.exported_by,
        )
        self.logger(
            "Quarantine export complete: "
            f"id={record.get('quarantine_id')} indicators={exported_count}"
        )
        return QuarantineExportResult(
            **base,
            action="export",
            reason="exported released quarantine record",
            indicator_count=len(indicators),
            exported_indicator_count=exported_count,
            dedup_duplicate_count=duplicate_count,
        )

    def filter_new_indicators(self, record, indicators):
        if not self.artifact_dedup:
            return indicators, 0
        filtered, duplicate_count = self.artifact_dedup.filter_new_indicators(
            indicators
        )
        if duplicate_count:
            self.logger(
                "Quarantine export dedup: "
                f"id={record.get('quarantine_id')} duplicates={duplicate_count}"
            )
        return filtered, duplicate_count

    def mark_artifacts(self, record, indicators):
        if not self.artifact_dedup:
            return
        try:
            added = self.artifact_dedup.mark_indicators(
                indicators,
                source_key=record.get("source_key", ""),
                external_id=record.get("external_id", ""),
                title=record_title(record),
            )
        except Exception as exc:
            self.logger(
                "Quarantine export dedup mark failed: "
                f"id={record.get('quarantine_id')} error={exc}"
            )
            return
        if added:
            self.logger(
                f"Quarantine export dedup mark: "
                f"id={record.get('quarantine_id')} added={added}"
            )


def exportable_records(records, quarantine_id=""):
    selected = []
    for record in records:
        if quarantine_id and record.get("quarantine_id") != quarantine_id:
            continue
        status = normalize_status(record.get("status"))
        if status in EXPORTABLE_STATUSES:
            selected.append(record)
    return selected


def result_base(record, dry_run=False):
    return {
        "quarantine_id": record.get("quarantine_id", ""),
        "status": record.get("status", ""),
        "title": record_title(record),
        "source_key": record.get("source_key", ""),
        "external_id": record.get("external_id", ""),
        "dry_run": dry_run,
    }


def record_title(record):
    return record.get("title") or "NarrowCTI quarantined intelligence"


def record_description(record):
    review = record.get("review") or {}
    lines = [
        "Released from NarrowCTI quarantine.",
        f"Source: {record.get('source_key') or 'unknown'}",
        f"External ID: {record.get('external_id') or 'none'}",
        f"Original reason: {record.get('reason') or 'none'}",
        f"Review reason: {review.get('reason') or 'none'}",
    ]
    query = record.get("query")
    if query:
        lines.append(f"Query: {query}")
    return "\n".join(lines)


def record_score(record):
    try:
        return int(record.get("score"))
    except (TypeError, ValueError):
        return 0
