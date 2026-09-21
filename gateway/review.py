"""Historical compatibility wrapper for the canonical review service."""

from narrowcti.adapters.persistence.local.quarantine_repository import QuarantineRepository
from narrowcti.adapters.persistence.local.review_audit import read_audit_events
from narrowcti.adapters.opencti.exporter import send_bundle
from narrowcti.application.review.service import AnalystReviewService as _AnalystReviewService
from narrowcti.application.review.service import ReviewSummary


class AnalystReviewService(_AnalystReviewService):
    def __init__(self, repository, release_audit_file="", reviewer="operator", require_reason=True):
        audit_path = release_audit_file or getattr(repository, "release_audit_file", "")
        super().__init__(repository, audit_reader=lambda: read_audit_events(audit_path),
                         export_operation=send_bundle, reviewer=reviewer,
                         require_reason=require_reason)
        self.release_audit_file = audit_path

    @classmethod
    def from_paths(cls, repository_file, release_audit_file="", reviewer="operator", require_reason=True):
        return cls(QuarantineRepository(repository_file, release_audit_file),
                   release_audit_file=release_audit_file, reviewer=reviewer,
                   require_reason=require_reason)

    def export_released(
        self,
        quarantine_id="",
        limit=0,
        api_client=None,
        artifact_dedup=None,
        identity_name="NarrowCTI Gateway",
        logger=None,
        dry_run=True,
        exported_by="gateway.quarantine",
    ):
        return super().export_released(
            quarantine_id,
            limit=limit,
            api_client=api_client,
            artifact_dedup=artifact_dedup,
            identity_name=identity_name,
            logger=logger,
            dry_run=dry_run,
            exported_by=exported_by,
        )


__all__ = ["AnalystReviewService", "ReviewSummary", "read_audit_events"]
