"""Historical exporter surface backed by the canonical application owner."""

from narrowcti.adapters.opencti.exporter import send_bundle
from narrowcti.application.review.export import (
    QuarantineExportResult,
    QuarantineExporter as _QuarantineExporter,
    exportable_records,
    record_description,
    record_score,
    record_title,
    result_base,
)


class QuarantineExporter(_QuarantineExporter):
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
        super().__init__(
            repository,
            api_client=api_client,
            exporter=exporter,
            artifact_dedup=artifact_dedup,
            identity_name=identity_name,
            logger=logger,
            dry_run=dry_run,
            exported_by=exported_by,
        )


__all__ = ["QuarantineExporter", "QuarantineExportResult", "exportable_records", "result_base", "record_title", "record_description", "record_score", "send_bundle"]
