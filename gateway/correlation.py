import argparse
import json
import os
from dataclasses import dataclass

from core.deduplication import (
    ARTIFACT_RECORDS_KEY,
    ARTIFACTS_KEY,
    load_artifact_state,
)
from gateway.settings import load_settings


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
    artifacts = state.get(ARTIFACTS_KEY, [])
    records = state.get(ARTIFACT_RECORDS_KEY, {})
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


def write_report(report, output_file, output_format="text"):
    output_file = str(output_file or "").strip()
    if not output_file:
        raise ValueError("output_file is required")
    directory = os.path.dirname(output_file)
    if directory:
        os.makedirs(directory, exist_ok=True)
    with open(output_file, "w", encoding="utf-8") as handle:
        handle.write(render_report(report, output_format=output_format) + "\n")
    return output_file


def main():
    parser = argparse.ArgumentParser(
        description="Summarize NarrowCTI local artifact correlation state."
    )
    parser.add_argument(
        "--file",
        default="",
        help="Artifact dedup state file. Defaults to NARROWCTI_DEDUP_STATE_FILE.",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=20,
        help="Maximum correlated artifacts to print. Zero prints all.",
    )
    parser.add_argument(
        "--output-file",
        default="",
        help="Optional file path to write the rendered correlation report.",
    )
    parser.add_argument("--json", action="store_true", help="Print JSON output.")
    args = parser.parse_args()

    state_file = args.file or load_settings().dedup_state_file
    report = build_correlation_report(
        load_artifact_state(state_file),
        limit=args.limit,
    )
    output_format = "json" if args.json else "text"
    rendered = render_report(report, output_format=output_format)
    if args.output_file:
        write_report(report, args.output_file, output_format=output_format)
    print(rendered)


if __name__ == "__main__":
    main()
