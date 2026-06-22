import argparse
import json
from dataclasses import dataclass

from gateway.runtime import SUMMARY_FIELDS
from gateway.settings import load_settings


@dataclass(frozen=True)
class GatewayOperationalReport:
    run_count: int
    first_recorded_at: str
    last_recorded_at: str
    totals: dict
    sources: dict

    def to_dict(self):
        return {
            "run_count": self.run_count,
            "first_recorded_at": self.first_recorded_at,
            "last_recorded_at": self.last_recorded_at,
            "totals": self.totals,
            "sources": self.sources,
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


def build_operational_report(records):
    if not records:
        return GatewayOperationalReport(
            run_count=0,
            first_recorded_at="",
            last_recorded_at="",
            totals=empty_totals(),
            sources={},
        )

    sources = {}
    totals = empty_totals()
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
                },
            )
            source_report["runs"] += 1
            if result.get("success"):
                source_report["succeeded"] += 1
            else:
                source_report["failed"] += 1
            merge_totals(source_report["totals"], result.get("totals", {}))

    return GatewayOperationalReport(
        run_count=len(records),
        first_recorded_at=records[0].get("recorded_at", ""),
        last_recorded_at=records[-1].get("recorded_at", ""),
        totals=totals,
        sources=sources,
    )


def empty_totals():
    return {field_name: 0 for field_name in SUMMARY_FIELDS}


def merge_totals(target, source):
    for field_name in SUMMARY_FIELDS:
        target[field_name] += int(source.get(field_name, 0) or 0)


def format_text_report(report):
    lines = [
        "NarrowCTI gateway operational report",
        f"run_count={report.run_count}",
        f"first_recorded_at={report.first_recorded_at or '(none)'}",
        f"last_recorded_at={report.last_recorded_at or '(none)'}",
        "totals=" + format_totals(report.totals),
    ]
    if report.sources:
        lines.append("sources:")
        for source_key in sorted(report.sources):
            source = report.sources[source_key]
            lines.append(
                f"- {source_key} runs={source['runs']} "
                f"succeeded={source['succeeded']} failed={source['failed']} "
                f"{format_totals(source['totals'])}"
            )
    return "\n".join(lines)


def format_totals(totals):
    return " ".join(
        f"{field_name}={totals.get(field_name, 0)}" for field_name in SUMMARY_FIELDS
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
    args = parser.parse_args()

    summary_file = args.file or load_settings().run_summary_file
    if not summary_file:
        raise SystemExit("summary file is required")

    records = read_gateway_summary_file(summary_file, limit=args.limit or None)
    report = build_operational_report(records)
    if args.json:
        print(json.dumps(report.to_dict(), sort_keys=True))
    else:
        print(format_text_report(report))


if __name__ == "__main__":
    main()
