"""Provider-neutral artifact correlation reporting semantics."""

from __future__ import annotations

import json
from dataclasses import dataclass

_ARTIFACTS_KEY = "artifact_fingerprints"
_ARTIFACT_RECORDS_KEY = "artifact_records"


@dataclass(frozen=True)
class ArtifactCorrelationReport:
    artifact_count: int
    record_count: int
    correlated_count: int
    source_counts: dict
    correlated_artifacts: tuple[dict, ...]

    def to_dict(self):
        return {
            "artifact_count": self.artifact_count,
            "record_count": self.record_count,
            "correlated_count": self.correlated_count,
            "source_counts": self.source_counts,
            "correlated_artifacts": list(self.correlated_artifacts),
        }

def build_correlation_report(state, limit=20):
    artifacts = state.get(_ARTIFACTS_KEY, [])
    records = state.get(_ARTIFACT_RECORDS_KEY, {})
    source_counts = {}
    correlated = []

    for fingerprint in sorted(records):
        record = records.get(fingerprint)
        if not isinstance(record, dict):
            continue

        sources = sorted(str(source) for source in record.get("sources", []) if source)
        for source in sources:
            source_counts[source] = source_counts.get(source, 0) + 1

        sightings = [
            sighting
            for sighting in record.get("sightings", [])
            if isinstance(sighting, dict)
        ]
        if len(sources) > 1:
            correlated.append(
                {
                    "fingerprint": fingerprint,
                    "sources": sources,
                    "source_count": len(sources),
                    "sighting_count": len(sightings),
                    "first_seen": record.get("first_seen", ""),
                    "last_seen": record.get("last_seen", ""),
                }
            )

    correlated.sort(
        key=lambda item: (
            item["source_count"],
            item["sighting_count"],
            item["last_seen"],
            item["fingerprint"],
        ),
        reverse=True,
    )
    if limit and limit > 0:
        correlated = correlated[:limit]

    return ArtifactCorrelationReport(
        artifact_count=len(artifacts),
        record_count=len(records),
        correlated_count=sum(
            1
            for record in records.values()
            if isinstance(record, dict)
            and len([source for source in record.get("sources", []) if source]) > 1
        ),
        source_counts=dict(sorted(source_counts.items())),
        correlated_artifacts=tuple(correlated),
    )

def format_text_report(report):
    lines = [
        "NarrowCTI artifact correlation report",
        f"artifact_count={report.artifact_count}",
        f"record_count={report.record_count}",
        f"correlated_count={report.correlated_count}",
    ]
    if report.source_counts:
        lines.append("sources:")
        for source, count in report.source_counts.items():
            lines.append(f"- {source} artifacts={count}")
    if report.correlated_artifacts:
        lines.append("correlated_artifacts:")
        for artifact in report.correlated_artifacts:
            sources = ",".join(artifact["sources"])
            lines.append(
                f"- {artifact['fingerprint']} sources={sources} "
                f"sightings={artifact['sighting_count']}"
            )
    return "\n".join(lines)

def render_report(report, output_format="text"):
    output_format = normalize_output_format(output_format)
    if output_format == "json":
        return json.dumps(report.to_dict(), sort_keys=True)
    return format_text_report(report)

def normalize_output_format(value):
    output_format = str(value or "text").strip().lower()
    if output_format not in ("text", "json"):
        raise ValueError("output_format must be one of: text,json")
    return output_format


__all__ = [
    "ArtifactCorrelationReport", "build_correlation_report", "format_text_report",
    "render_report", "normalize_output_format",
]
