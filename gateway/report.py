import argparse
import json
import os
from collections import Counter
from dataclasses import dataclass

from core.quarantine import (
    EXPIRED,
    PARTIALLY_RELEASED,
    PENDING,
    REJECTED,
    RELEASED,
    QuarantineRepository,
    normalize_status,
)
from gateway.runtime import SUMMARY_FIELDS
from gateway.settings import load_settings

QUARANTINE_STATUS_ORDER = (
    PENDING,
    RELEASED,
    PARTIALLY_RELEASED,
    REJECTED,
    EXPIRED,
)


@dataclass(frozen=True)
class GatewayOperationalReport:
    run_count: int
    first_recorded_at: str
    last_recorded_at: str
    totals: dict
    metrics: dict
    failures: list
    queries: list
    sources: dict
    quarantine_review: dict

    def to_dict(self):
        return {
            "run_count": self.run_count,
            "first_recorded_at": self.first_recorded_at,
            "last_recorded_at": self.last_recorded_at,
            "totals": self.totals,
            "metrics": self.metrics,
            "failures": self.failures,
            "queries": self.queries,
            "sources": self.sources,
            "quarantine_review": self.quarantine_review,
        }


def read_gateway_summary_file(summary_file, limit=None):
    records = []
    with open(summary_file, "r", encoding="utf-8") as file_obj:
        for line in file_obj:
            stripped = line.strip()
            if stripped:
                records.append(json.loads(stripped))
    if limit is not None and limit > 0:
        records = records[-limit:]
    return records


def read_quarantine_records(repository_file):
    if not repository_file:
        return []
    return QuarantineRepository(repository_file).records()


def build_operational_report(records, quarantine_records=None):
    if not records:
        return GatewayOperationalReport(
            run_count=0,
            first_recorded_at="",
            last_recorded_at="",
            totals=empty_totals(),
            metrics=build_value_metrics(empty_totals()),
            failures=[],
            queries=[],
            sources={},
            quarantine_review=build_quarantine_review(quarantine_records),
        )

    sources = {}
    totals = empty_totals()
    failures = []
    queries = {}
    for record in records:
        merge_totals(totals, record.get("totals", {}))
        for result in record.get("results", []):
            source_key = result.get("source_key", "unknown")
            source_report = sources.setdefault(
                source_key,
                {
                    "source_name": result.get("source_name", source_key),
                    "runs": 0,
                    "succeeded": 0,
                    "failed": 0,
                    "totals": empty_totals(),
                    "metrics": {},
                    "failures": [],
                },
            )
            source_report["runs"] += 1
            if result.get("success"):
                source_report["succeeded"] += 1
            else:
                source_report["failed"] += 1
                failure = failure_record(record, result)
                failures.append(failure)
                source_report["failures"].append(failure)
            merge_totals(source_report["totals"], result.get("totals", {}))
            merge_query_summaries(queries, source_key, result.get("summaries", []))

    for source_report in sources.values():
        source_report["metrics"] = build_value_metrics(source_report["totals"])

    return GatewayOperationalReport(
        run_count=len(records),
        first_recorded_at=records[0].get("recorded_at", ""),
        last_recorded_at=records[-1].get("recorded_at", ""),
        totals=totals,
        metrics=build_value_metrics(totals),
        failures=failures,
        queries=sorted_query_summaries(queries),
        sources=sources,
        quarantine_review=build_quarantine_review(quarantine_records),
    )


def build_quarantine_review(records):
    records = list(records or [])
    statuses = Counter()
    by_source = {}
    exported = 0
    released_indicator_count = 0
    held_indicator_count = 0
    exported_indicator_count = 0
    dedup_duplicate_count = 0

    for record in records:
        status = normalize_status(record.get("status", PENDING))
        statuses[status] += 1
        source_key = str(record.get("source_key") or "unknown")
        source_report = by_source.setdefault(
            source_key,
            {
                "records": 0,
                "statuses": empty_quarantine_statuses(),
                "released_indicator_count": 0,
                "held_indicator_count": 0,
                "exported_indicator_count": 0,
                "dedup_duplicate_count": 0,
            },
        )
        source_report["records"] += 1
        source_report["statuses"][status] += 1

        review = record.get("review") or {}
        if review.get("exported"):
            exported += 1
        released_count = int(review.get("released_indicator_count", 0) or 0)
        held_count = int(review.get("held_indicator_count", 0) or 0)
        exported_count = int(review.get("exported_indicator_count", 0) or 0)
        duplicate_count = int(review.get("dedup_duplicate_count", 0) or 0)
        released_indicator_count += released_count
        held_indicator_count += held_count
        exported_indicator_count += exported_count
        dedup_duplicate_count += duplicate_count
        source_report["released_indicator_count"] += released_count
        source_report["held_indicator_count"] += held_count
        source_report["exported_indicator_count"] += exported_count
        source_report["dedup_duplicate_count"] += duplicate_count

    status_counts = empty_quarantine_statuses()
    for status, count in statuses.items():
        status_counts[status] = count

    return {
        "record_count": len(records),
        "statuses": status_counts,
        "pending": status_counts[PENDING],
        "released": status_counts[RELEASED],
        "partially_released": status_counts[PARTIALLY_RELEASED],
        "rejected": status_counts[REJECTED],
        "expired": status_counts[EXPIRED],
        "exportable": status_counts[RELEASED] + status_counts[PARTIALLY_RELEASED],
        "exported": exported,
        "released_indicator_count": released_indicator_count,
        "held_indicator_count": held_indicator_count,
        "exported_indicator_count": exported_indicator_count,
        "dedup_duplicate_count": dedup_duplicate_count,
        "by_source": dict(sorted(by_source.items())),
    }


def empty_quarantine_statuses():
    return {status: 0 for status in QUARANTINE_STATUS_ORDER}


def empty_totals():
    return {field_name: 0 for field_name in SUMMARY_FIELDS}


def merge_totals(target, source):
    for field_name in SUMMARY_FIELDS:
        target[field_name] += int(source.get(field_name, 0) or 0)


def merge_query_summaries(target, source_key, summaries):
    for summary in summaries or ():
        query = str(summary.get("query", "") or "(none)")
        key = (source_key, query)
        query_report = target.setdefault(
            key,
            {
                "source_key": source_key,
                "query": query,
                "runs": 0,
                "available": 0,
                "handled": 0,
                "totals": empty_totals(),
                "metrics": {},
            },
        )
        query_report["runs"] += 1
        query_report["available"] += int(summary.get("available", 0) or 0)
        query_report["handled"] += int(summary.get("handled", 0) or 0)
        merge_totals(query_report["totals"], summary)


def sorted_query_summaries(query_reports):
    reports = []
    for report in query_reports.values():
        report["metrics"] = build_value_metrics(report["totals"])
        reports.append(report)
    return sorted(
        reports,
        key=lambda item: (
            -int(item.get("handled", 0) or 0),
            item.get("source_key", ""),
            item.get("query", ""),
        ),
    )


def build_value_metrics(totals):
    reviewed = int(totals.get("reviewed", 0) or 0)
    accepted = int(totals.get("ingested", 0) or 0) + int(
        totals.get("dry_run", 0) or 0
    )
    filtered = (
        int(totals.get("dropped", 0) or 0)
        + int(totals.get("quarantined", 0) or 0)
        + int(totals.get("skipped", 0) or 0)
    )
    errors = int(totals.get("errors", 0) or 0)
    handled = accepted + filtered + errors
    return {
        "handled": handled,
        "accepted": accepted,
        "filtered": filtered,
        "errors": errors,
        "acceptance_rate_pct": percentage(accepted, reviewed),
        "filter_rate_pct": percentage(filtered, reviewed),
        "error_rate_pct": percentage(errors, reviewed),
    }


def failure_record(record, result):
    return {
        "recorded_at": record.get("recorded_at", ""),
        "source_key": result.get("source_key", "unknown"),
        "source_name": result.get("source_name", result.get("source_key", "unknown")),
        "error": result.get("error", "") or "source failed without error detail",
    }


def percentage(value, total):
    if total <= 0:
        return 0.0
    return round((value / total) * 100, 2)


def format_text_report(report):
    lines = [
        "NarrowCTI gateway operational report",
        f"run_count={report.run_count}",
        f"first_recorded_at={report.first_recorded_at or '(none)'}",
        f"last_recorded_at={report.last_recorded_at or '(none)'}",
        "totals=" + format_totals(report.totals),
        "metrics=" + format_metrics(report.metrics),
    ]
    if report.failures:
        lines.append("failures:")
        for failure in report.failures:
            lines.append(
                f"- {failure['recorded_at'] or '(unknown-time)'} "
                f"{failure['source_key']} error={failure['error']}"
            )
    if report.queries:
        lines.append("queries:")
        for query in report.queries:
            lines.append(
                f"- {query['source_key']} query={query['query']} "
                f"runs={query['runs']} available={query['available']} "
                f"handled={query['handled']} {format_totals(query['totals'])} "
                f"metrics={format_metrics(query['metrics'])}"
            )
    if report.sources:
        lines.append("sources:")
        for source_key in sorted(report.sources):
            source = report.sources[source_key]
            lines.append(
                f"- {source_key} runs={source['runs']} "
                f"succeeded={source['succeeded']} failed={source['failed']} "
                f"{format_totals(source['totals'])} "
                f"metrics={format_metrics(source['metrics'])}"
            )
    if report.quarantine_review.get("record_count", 0):
        review = report.quarantine_review
        lines.append("quarantine_review:")
        lines.append(
            "- "
            f"records={review['record_count']} "
            f"pending={review['pending']} "
            f"released={review['released']} "
            f"partially_released={review['partially_released']} "
            f"rejected={review['rejected']} "
            f"exportable={review['exportable']} "
            f"exported={review['exported']} "
            f"released_indicators={review['released_indicator_count']} "
            f"held_indicators={review['held_indicator_count']} "
            f"exported_indicators={review['exported_indicator_count']} "
            f"dedup_duplicates={review['dedup_duplicate_count']}"
        )
        for source_key, source in review["by_source"].items():
            lines.append(
                f"- source={source_key} records={source['records']} "
                f"statuses={format_quarantine_statuses(source['statuses'])} "
                f"released_indicators={source['released_indicator_count']} "
                f"held_indicators={source['held_indicator_count']} "
                f"exported_indicators={source['exported_indicator_count']} "
                f"dedup_duplicates={source['dedup_duplicate_count']}"
            )
    return "\n".join(lines)


def render_report(report, output_format="text"):
    output_format = normalize_output_format(output_format)
    if output_format == "json":
        return json.dumps(report.to_dict(), sort_keys=True)
    return format_text_report(report)


def normalize_output_format(value):
    normalized = str(value or "text").strip().lower()
    if normalized not in {"text", "json"}:
        raise ValueError(f"unsupported report format: {value}")
    return normalized


def write_report(report, output_file, output_format="text"):
    if not output_file:
        return
    directory = os.path.dirname(output_file)
    if directory:
        os.makedirs(directory, exist_ok=True)
    rendered = render_report(report, output_format)
    with open(output_file, "w", encoding="utf-8") as file_obj:
        file_obj.write(rendered)
        file_obj.write("\n")


def format_totals(totals):
    return " ".join(
        f"{field_name}={totals.get(field_name, 0)}" for field_name in SUMMARY_FIELDS
    )


def format_metrics(metrics):
    fields = (
        "handled",
        "accepted",
        "filtered",
        "errors",
        "acceptance_rate_pct",
        "filter_rate_pct",
        "error_rate_pct",
    )
    return " ".join(
        f"{field_name}={metrics.get(field_name, 0)}" for field_name in fields
    )


def format_quarantine_statuses(statuses):
    return " ".join(
        f"{status}={statuses.get(status, 0)}" for status in QUARANTINE_STATUS_ORDER
    )


def main():
    parser = argparse.ArgumentParser(
        description="Summarize NarrowCTI gateway JSONL run summaries."
    )
    parser.add_argument(
        "--file",
        default="",
        help="Gateway JSONL summary file. Defaults to NARROWCTI_RUN_SUMMARY_FILE.",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=0,
        help="Only read the most recent N records. Zero reads all records.",
    )
    parser.add_argument("--json", action="store_true", help="Print JSON output.")
    parser.add_argument(
        "--output-file",
        default="",
        help="Optional path where the rendered report should be written.",
    )
    parser.add_argument(
        "--quarantine-file",
        default="",
        help="Optional quarantine repository JSONL file for review metrics.",
    )
    args = parser.parse_args()

    settings = load_settings()
    summary_file = args.file or settings.run_summary_file
    if not summary_file:
        raise SystemExit("summary file is required")

    records = read_gateway_summary_file(summary_file, limit=args.limit or None)
    quarantine_file = args.quarantine_file or settings.quarantine_repository_file
    quarantine_records = read_quarantine_records(quarantine_file)
    report = build_operational_report(records, quarantine_records=quarantine_records)
    output_format = "json" if args.json else "text"
    write_report(report, args.output_file, output_format)
    print(render_report(report, output_format))


if __name__ == "__main__":
    main()
