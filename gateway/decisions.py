import argparse
import glob
import json
import os
from collections import Counter
from dataclasses import dataclass

from gateway.settings import load_settings


ACTION_ORDER = (
    "ingest",
    "drop",
    "quarantine",
    "skip",
    "dry-run",
    "error",
)


@dataclass(frozen=True)
class DecisionAuditReport:
    record_count: int
    first_recorded_at: str
    last_recorded_at: str
    actions: dict
    reasons: list
    score_summary: dict
    sources: dict

    def to_dict(self):
        return {
            "record_count": self.record_count,
            "first_recorded_at": self.first_recorded_at,
            "last_recorded_at": self.last_recorded_at,
            "actions": self.actions,
            "reasons": self.reasons,
            "score_summary": self.score_summary,
            "sources": self.sources,
        }


def read_decision_records(paths, limit=None):
    records = []
    for path in expand_paths(paths):
        with open(path, "r", encoding="utf-8") as file_obj:
            for line in file_obj:
                stripped = line.strip()
                if stripped:
                    records.append(json.loads(stripped))
    records.sort(key=lambda record: record.get("recorded_at", ""))
    if limit is not None and limit > 0:
        records = records[-limit:]
    return records


def expand_paths(paths):
    expanded = []
    for path in paths or ():
        if os.path.isdir(path):
            expanded.extend(sorted(glob.glob(os.path.join(path, "*.jsonl"))))
        elif not os.path.exists(path) and os.path.splitext(path)[1].lower() != ".jsonl":
            continue
        else:
            expanded.append(path)
    return expanded


def build_decision_audit_report(records, reason_limit=10):
    if not records:
        return DecisionAuditReport(
            record_count=0,
            first_recorded_at="",
            last_recorded_at="",
            actions=empty_actions(),
            reasons=[],
            score_summary={
                "overall": build_score_summary([]),
                "by_action": {},
            },
            sources={},
        )

    actions = empty_actions()
    reason_counts = Counter()
    sources = {}
    records_by_action = {}
    records_by_source = {}

    for record in records:
        action = normalize_value(record.get("action"), "unknown")
        reason = normalize_value(record.get("reason"), "unspecified")
        source_key = normalize_value(record.get("source_key"), "unknown")

        actions[action] = actions.get(action, 0) + 1
        reason_counts[(action, reason)] += 1
        records_by_action.setdefault(action, []).append(record)
        records_by_source.setdefault(source_key, []).append(record)

        source_report = sources.setdefault(
            source_key,
            {
                "records": 0,
                "actions": empty_actions(),
                "reasons": {},
                "score_summary": {},
            },
        )
        source_report["records"] += 1
        source_report["actions"][action] = source_report["actions"].get(action, 0) + 1
        source_report["reasons"][reason] = source_report["reasons"].get(reason, 0) + 1

    for source_key, source_records in records_by_source.items():
        sources[source_key]["score_summary"] = build_score_summary(source_records)

    return DecisionAuditReport(
        record_count=len(records),
        first_recorded_at=records[0].get("recorded_at", ""),
        last_recorded_at=records[-1].get("recorded_at", ""),
        actions=actions,
        reasons=top_reasons(reason_counts, reason_limit),
        score_summary={
            "overall": build_score_summary(records),
            "by_action": {
                action: build_score_summary(action_records)
                for action, action_records in sorted(records_by_action.items())
            },
        },
        sources=sources,
    )


def empty_actions():
    return {action: 0 for action in ACTION_ORDER}


def normalize_value(value, default):
    value = str(value or "").strip()
    return value or default


def top_reasons(reason_counts, limit):
    items = sorted(
        reason_counts.items(),
        key=lambda item: (-item[1], item[0][0], item[0][1]),
    )
    if limit and limit > 0:
        items = items[:limit]
    return [
        {"action": action, "reason": reason, "count": count}
        for (action, reason), count in items
    ]


def build_score_summary(records):
    scores = [
        score
        for score in (coerce_score(record.get("score")) for record in records or ())
        if score is not None
    ]
    return {
        "records_with_score": len(scores),
        "min_score": min(scores) if scores else None,
        "max_score": max(scores) if scores else None,
        "average_score": round(sum(scores) / len(scores), 2) if scores else None,
        "bands": score_bands(scores),
    }


def coerce_score(value):
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def score_bands(scores):
    bands = {
        "0-29": 0,
        "30-49": 0,
        "50-69": 0,
        "70-89": 0,
        "90-100": 0,
    }
    for score in scores:
        if score < 30:
            bands["0-29"] += 1
        elif score < 50:
            bands["30-49"] += 1
        elif score < 70:
            bands["50-69"] += 1
        elif score < 90:
            bands["70-89"] += 1
        else:
            bands["90-100"] += 1
    return bands


def format_text_report(report):
    lines = [
        "NarrowCTI decision audit report",
        f"record_count={report.record_count}",
        f"first_recorded_at={report.first_recorded_at or '(none)'}",
        f"last_recorded_at={report.last_recorded_at or '(none)'}",
        "actions=" + format_counts(report.actions),
        "scores=" + format_score_summary(report.score_summary["overall"]),
    ]
    if report.reasons:
        lines.append("top_reasons:")
        for item in report.reasons:
            lines.append(
                f"- action={item['action']} count={item['count']} "
                f"reason={item['reason']}"
            )
    if report.sources:
        lines.append("sources:")
        for source_key in sorted(report.sources):
            source = report.sources[source_key]
            lines.append(
                f"- {source_key} records={source['records']} "
                f"actions={format_counts(source['actions'])} "
                f"scores={format_score_summary(source['score_summary'])}"
            )
    return "\n".join(lines)


def format_counts(counts):
    ordered_keys = list(ACTION_ORDER) + sorted(
        key for key in counts if key not in ACTION_ORDER
    )
    return " ".join(f"{key}={counts.get(key, 0)}" for key in ordered_keys)


def format_score_summary(summary):
    bands = summary.get("bands", {})
    band_text = ",".join(f"{key}:{bands.get(key, 0)}" for key in sorted(bands))
    return (
        f"records_with_score={summary.get('records_with_score', 0)} "
        f"min_score={format_optional(summary.get('min_score'))} "
        f"max_score={format_optional(summary.get('max_score'))} "
        f"average_score={format_optional(summary.get('average_score'))} "
        f"bands={band_text}"
    )


def format_optional(value):
    return "(none)" if value is None else str(value)


def main():
    parser = argparse.ArgumentParser(
        description="Summarize NarrowCTI decision audit JSONL records."
    )
    parser.add_argument(
        "--file",
        action="append",
        default=[],
        help="Decision audit JSONL file. Can be passed more than once.",
    )
    parser.add_argument(
        "--dir",
        default="",
        help="Directory containing decision audit *.jsonl files.",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=0,
        help="Only read the most recent N records. Zero reads all records.",
    )
    parser.add_argument(
        "--reason-limit",
        type=int,
        default=10,
        help="Maximum top reasons to include. Zero includes all reasons.",
    )
    parser.add_argument("--json", action="store_true", help="Print JSON output.")
    args = parser.parse_args()

    paths = list(args.file)
    if args.dir:
        paths.append(args.dir)
    if not paths:
        paths.append(load_settings().decision_audit_dir)

    records = read_decision_records(paths, limit=args.limit or None)
    report = build_decision_audit_report(records, reason_limit=args.reason_limit)
    if args.json:
        print(json.dumps(report.to_dict(), sort_keys=True))
    else:
        print(format_text_report(report))


if __name__ == "__main__":
    main()
