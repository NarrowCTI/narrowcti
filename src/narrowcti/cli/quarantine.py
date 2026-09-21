"""Canonical command-line composition for quarantine review."""

import argparse
import json
import os

from narrowcti.adapters.opencti.client import build_opencti_client
from narrowcti.adapters.opencti.deduplication import CompositeArtifactDeduplication, OpenCTIArtifactLookup
from narrowcti.adapters.opencti.exporter import send_bundle
from narrowcti.adapters.persistence.local.artifact_index import ArtifactDeduplicationIndex
from narrowcti.adapters.persistence.local.quarantine_repository import QuarantineRepository
from narrowcti.adapters.persistence.local.review_audit import read_audit_events
from narrowcti.application.review.service import AnalystReviewService

DEFAULT_REPOSITORY = "/app/state/quarantine.jsonl"
DEFAULT_RELEASE_AUDIT = "/app/state/audit/releases.jsonl"


def reason_required():
    return os.getenv("NARROWCTI_RELEASE_QUARANTINE_REQUIRES_REASON", "true").lower() in ("true", "1", "yes")


def reviewer(args):
    return getattr(args, "reviewer", "") or os.getenv("NARROWCTI_REVIEWER", "operator")


def repository_from_args(args):
    return QuarantineRepository(
        args.repository or os.getenv("NARROWCTI_QUARANTINE_REPOSITORY", DEFAULT_REPOSITORY),
        args.release_audit_file or os.getenv("NARROWCTI_RELEASE_AUDIT_FILE", DEFAULT_RELEASE_AUDIT),
    )


def review_service_from_args(args):
    repository = repository_from_args(args)
    audit_path = repository.release_audit_file
    return AnalystReviewService(
        repository,
        audit_reader=lambda: read_audit_events(audit_path),
        export_operation=send_bundle,
        reviewer=reviewer(args),
        require_reason=reason_required(),
    )


def format_optional(value):
    return "(none)" if value is None or value == "" else str(value)


def format_record_summary(record):
    return (f"- {record['quarantine_id']} status={record['status']} "
            f"source={record.get('source_key') or '(unknown)'} "
            f"external_id={record.get('external_id') or '(none)'} "
            f"score={format_optional(record.get('score'))} "
            f"indicators={record.get('indicator_count', 0)} "
            f"title={record.get('title') or '(untitled)'}")


def format_record_detail(record):
    lines = [
        "NarrowCTI quarantine record", f"id={record.get('quarantine_id')}",
        f"status={record.get('status')}", f"source_key={record.get('source_key') or '(unknown)'}",
        f"external_id={record.get('external_id') or '(none)'}", f"query={record.get('query') or '(none)'}",
        f"title={record.get('title') or '(untitled)'}", f"reason={record.get('reason') or '(none)'}",
        f"score={format_optional(record.get('score'))}", f"age_days={format_optional(record.get('age_days'))}",
        f"indicator_count={record.get('indicator_count', 0)}", f"created_at={record.get('created_at') or '(unknown)'}",
        f"updated_at={record.get('updated_at') or '(unknown)'}",
    ]
    review = record.get("review") or {}
    if review:
        lines.extend([
            "review:", f"- action={review.get('action') or '(unknown)'}",
            f"- reviewer={review.get('reviewer') or '(unknown)'}",
            f"- reason={review.get('reason') or '(none)'}",
            f"- released_indicator_count={review.get('released_indicator_count', 0)}",
            f"- held_indicator_count={review.get('held_indicator_count', 0)}",
            f"- exported={str(review.get('exported', False)).lower()}",
        ])
    indicators = record.get("indicators") or []
    if indicators:
        lines.append("indicators:")
        lines.extend(f"- {item.get('type') or '(unknown)'}={item.get('indicator') or item.get('value') or '(empty)'}" for item in indicators)
    return "\n".join(lines)


def format_review_summary(summary):
    lines = ["NarrowCTI quarantine review summary", f"records={summary.get('record_count', 0)}", f"pending={summary.get('pending_count', 0)}", f"exportable={summary.get('exportable_count', 0)}"]
    for status, count in sorted((summary.get("status_counts") or {}).items()):
        lines.append(f"- {status}={count}")
    for source, count in sorted((summary.get("source_counts") or {}).items()):
        lines.append(f"- {source}={count}")
    return "\n".join(lines)


def format_release_audit_events(events):
    lines = ["NarrowCTI quarantine release audit", f"count={len(events)}"]
    for event in events:
        lines.append(
            f"- {event.get('recorded_at') or '(unknown-time)'} id={event.get('quarantine_id') or '(none)'} "
            f"action={event.get('action') or '(unknown)'} status={event.get('status') or '(unknown)'} "
            f"reviewer={event.get('reviewer') or '(unknown)'} released={event.get('released_indicator_count', 0)} "
            f"held={event.get('held_indicator_count', 0)} exported={str(event.get('exported', False)).lower()} "
            f"title={event.get('title') or '(untitled)'}"
        )
        if event.get("reason"):
            lines.append(f"  reason={event['reason']}")
    return "\n".join(lines)


def build_opencti_client_from_env():
    url, token = os.getenv("OPENCTI_URL"), os.getenv("OPENCTI_TOKEN")
    if not url or not token:
        raise ValueError("OPENCTI_URL and OPENCTI_TOKEN are required for export")
    return build_opencti_client(url, token)


def build_artifact_dedup(args, api_client=None):
    state_file = args.dedup_state_file or os.getenv("NARROWCTI_DEDUP_STATE_FILE", "")
    local_index = ArtifactDeduplicationIndex(state_file) if state_file else None
    lookup = None
    if args.opencti_dedup_lookup:
        if not api_client:
            raise ValueError("OpenCTI client is required for OpenCTI dedup lookup")
        lookup = OpenCTIArtifactLookup(api_client)
    if not local_index and not lookup:
        return None
    return CompositeArtifactDeduplication(local_index=local_index, opencti_lookup=lookup)


def format_export_results(results):
    lines = ["NarrowCTI quarantine export", f"count={len(results)}"]
    for result in results:
        lines.append(
            f"- {result['quarantine_id']} action={result['action']} status={result['status']} "
            f"dry_run={str(result['dry_run']).lower()} exported_indicators={result['exported_indicator_count']} "
            f"duplicates={result['dedup_duplicate_count']} title={result['title'] or '(untitled)'}"
        )
        if result.get("reason"):
            lines.append(f"  reason={result['reason']}")
        lines.extend(f"  error={error}" for error in result.get("errors") or [])
    return "\n".join(lines)


def build_parser():
    parser = argparse.ArgumentParser(description="Review NarrowCTI quarantine records.")
    parser.add_argument("--repository", default="", help="Quarantine JSONL repository path.")
    parser.add_argument("--release-audit-file", default="", help="Release audit JSONL path.")
    parser.add_argument("--json", action="store_true", help="Print JSON output.")
    subparsers = parser.add_subparsers(dest="command", required=True)
    item = subparsers.add_parser("list", help="List quarantine records.")
    item.add_argument("--status", default="pending")
    item.set_defaults(func=command_list)
    item = subparsers.add_parser("show", help="Show one quarantine record.")
    item.add_argument("--id", required=True)
    item.set_defaults(func=command_show)
    item = subparsers.add_parser("summary", help="Summarize quarantine review queue state.")
    item.set_defaults(func=command_summary)
    for name, callback in (("reject", command_reject), ("release", command_release)):
        item = subparsers.add_parser(name)
        item.add_argument("--id", required=True)
        item.add_argument("--reason", default="")
        item.add_argument("--reviewer", default="")
        item.set_defaults(func=callback)
    item = subparsers.add_parser("release-indicators")
    item.add_argument("--id", required=True)
    item.add_argument("--type", required=True)
    item.add_argument("--reason", default="")
    item.add_argument("--reviewer", default="")
    item.set_defaults(func=command_release_indicators)
    item = subparsers.add_parser("export-released")
    item.add_argument("--id", default="")
    item.add_argument("--limit", type=int, default=0)
    item.add_argument("--execute", action="store_true")
    item.add_argument("--dedup-state-file", default="")
    item.add_argument("--opencti-dedup-lookup", action="store_true")
    item.add_argument("--identity-name", default=os.getenv("CONNECTOR_NAME", "NarrowCTI Gateway"))
    item.set_defaults(func=command_export_released)
    item = subparsers.add_parser("audit")
    item.add_argument("--id", default="")
    item.add_argument("--action", default="")
    item.add_argument("--limit", type=int, default=0)
    item.set_defaults(func=command_audit)
    return parser


def print_data(data, as_json, formatter):
    print(json.dumps(data, sort_keys=True) if as_json else formatter(data))


def command_list(args):
    records = review_service_from_args(args).list_records(status=None if args.status == "all" else args.status)
    if args.json:
        print(json.dumps(records, sort_keys=True))
    else:
        print("\n".join(["NarrowCTI quarantine list", f"count={len(records)}", *(format_record_summary(record) for record in records)]))
    return 0


def command_show(args):
    print_data(review_service_from_args(args).get_record(args.id), args.json, format_record_detail)
    return 0


def command_summary(args):
    summary = review_service_from_args(args).summary().to_dict()
    print(json.dumps(summary, sort_keys=True) if args.json else format_review_summary(summary))
    return 0


def command_reject(args):
    print_data(review_service_from_args(args).reject(args.id, args.reason, reviewer=reviewer(args)), args.json, format_record_detail)
    return 0


def command_release(args):
    print_data(review_service_from_args(args).release(args.id, args.reason, reviewer=reviewer(args)), args.json, format_record_detail)
    return 0


def command_release_indicators(args):
    print_data(review_service_from_args(args).release_indicators(args.id, args.type, args.reason, reviewer=reviewer(args)), args.json, format_record_detail)
    return 0


def command_export_released(args):
    dry_run = not args.execute
    api_client = build_opencti_client_from_env() if args.opencti_dedup_lookup or not dry_run else None
    dedup = build_artifact_dedup(args, api_client)
    service = review_service_from_args(args)
    results = service.export_released(args.id, limit=args.limit, api_client=api_client, artifact_dedup=dedup, identity_name=args.identity_name, dry_run=dry_run, exporter=send_bundle)
    data = [result.to_dict() for result in results]
    print(json.dumps(data, sort_keys=True) if args.json else format_export_results(data))
    return 0


def command_audit(args):
    events = review_service_from_args(args).audit_events(quarantine_id=args.id, action=args.action, limit=args.limit)
    print(json.dumps(events, sort_keys=True) if args.json else format_release_audit_events(events))
    return 0


def read_release_audit_events(path):
    return read_audit_events(path)


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except (KeyError, ValueError) as exc:
        parser.error(str(exc))
    return 1


__all__ = ["main", "build_parser", "read_release_audit_events", "AnalystReviewService"]


if __name__ == "__main__":
    raise SystemExit(main())
