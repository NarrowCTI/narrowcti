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


__all__ = ["AnalystReviewService", "ReviewSummary", "read_audit_events"]
