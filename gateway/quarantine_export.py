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
    def __init__(self, repository, api_client=None, exporter=None, **kwargs):
        super().__init__(repository, api_client=api_client, exporter=exporter or send_bundle, **kwargs)


__all__ = ["QuarantineExporter", "QuarantineExportResult", "exportable_records", "result_base", "record_title", "record_description", "record_score", "send_bundle"]
