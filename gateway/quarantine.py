import argparse
import json
import os

from core.deduplication import ArtifactDeduplicationIndex
from core.opencti_deduplication import (
    CompositeArtifactDeduplication,
    OpenCTIArtifactLookup,
)
from core.quarantine import QuarantineRepository
from gateway.quarantine_export import QuarantineExporter


DEFAULT_REPOSITORY = "/app/state/quarantine.jsonl"
DEFAULT_RELEASE_AUDIT = "/app/state/audit/releases.jsonl"


def repository_from_args(args):
    return QuarantineRepository(
        args.repository
        or os.getenv("NARROWCTI_QUARANTINE_REPOSITORY", DEFAULT_REPOSITORY),
        args.release_audit_file
        or os.getenv("NARROWCTI_RELEASE_AUDIT_FILE", DEFAULT_RELEASE_AUDIT),
    )


def reason_required():
    value = os.getenv("NARROWCTI_RELEASE_QUARANTINE_REQUIRES_REASON", "true")
    return value.lower() in ("true", "1", "yes")


def reviewer(args):
    return args.reviewer or os.getenv("NARROWCTI_REVIEWER", "operator")


def format_record_summary(record):
    return (
        f"- {record['quarantine_id']} status={record['status']} "
        f"source={record.get('source_key') or '(unknown)'} "
        f"external_id={record.get('external_id') or '(none)'} "
        f"score={format_optional(record.get('score'))} "
        f"indicators={record.get('indicator_count', 0)} "
        f"title={record.get('title') or '(untitled)'}"
    )


def format_record_detail(record):
    lines = [
        "NarrowCTI quarantine record",
        f"id={record.get('quarantine_id')}",
        f"status={record.get('status')}",
        f"source_key={record.get('source_key') or '(unknown)'}",
        f"external_id={record.get('external_id') or '(none)'}",
        f"query={record.get('query') or '(none)'}",
        f"title={record.get('title') or '(untitled)'}",
        f"reason={record.get('reason') or '(none)'}",
        f"score={format_optional(record.get('score'))}",
        f"age_days={format_optional(record.get('age_days'))}",
        f"indicator_count={record.get('indicator_count', 0)}",
        f"created_at={record.get('created_at') or '(unknown)'}",
        f"updated_at={record.get('updated_at') or '(unknown)'}",
    ]
    review = record.get("review") or {}
    if review:
        lines.extend(
            [
                "review:",
                f"- action={review.get('action') or '(unknown)'}",
                f"- reviewer={review.get('reviewer') or '(unknown)'}",
                f"- reason={review.get('reason') or '(none)'}",
                f"- released_indicator_count={review.get('released_indicator_count', 0)}",
                f"- held_indicator_count={review.get('held_indicator_count', 0)}",
                f"- exported={str(review.get('exported', False)).lower()}",
            ]
        )
    indicators = record.get("indicators") or []
    if indicators:
        lines.append("indicators:")
        for indicator in indicators:
            lines.append(
                f"- {indicator.get('type') or '(unknown)'}="
                f"{indicator.get('indicator') or indicator.get('value') or '(empty)'}"
            )
    return "\n".join(lines)


def format_optional(value):
    return "(none)" if value is None or value == "" else str(value)


def print_output(data, as_json, formatter):
    if as_json:
        print(json.dumps(data, sort_keys=True))
    else:
        print(formatter(data))


def command_list(args):
    status = None if args.status == "all" else args.status
    records = repository_from_args(args).records(status=status)
    if args.json:
        print(json.dumps(records, sort_keys=True))
        return 0
    lines = [
        "NarrowCTI quarantine list",
        f"count={len(records)}",
    ]
    lines.extend(format_record_summary(record) for record in records)
    print("\n".join(lines))
    return 0


def command_show(args):
    record = repository_from_args(args).get(args.id)
    print_output(record, args.json, format_record_detail)
    return 0


def command_reject(args):
    record = repository_from_args(args).reject(
        args.id,
        args.reason,
        reviewer=reviewer(args),
        require_reason=reason_required(),
    )
    print_output(record, args.json, format_record_detail)
    return 0


def command_release(args):
    record = repository_from_args(args).release(
        args.id,
        args.reason,
        reviewer=reviewer(args),
        require_reason=reason_required(),
    )
    print_output(record, args.json, format_record_detail)
    return 0


def command_release_indicators(args):
    record = repository_from_args(args).release_indicators(
        args.id,
        args.type,
        args.reason,
        reviewer=reviewer(args),
        require_reason=reason_required(),
    )
    print_output(record, args.json, format_record_detail)
    return 0


def command_export_released(args):
    dry_run = not args.execute
    api_client = None
    if args.opencti_dedup_lookup or not dry_run:
        api_client = build_opencti_client()

    dedup = build_artifact_dedup(args, api_client)
    service = QuarantineExporter(
        repository_from_args(args),
        api_client=api_client,
        artifact_dedup=dedup,
        identity_name=args.identity_name,
        logger=lambda message: None,
        dry_run=dry_run,
    )
    results = service.export_pending(args.id, limit=args.limit)
    data = [result.to_dict() for result in results]
    if args.json:
        print(json.dumps(data, sort_keys=True))
    else:
        print(format_export_results(data))
    return 0


def build_opencti_client():
    from pycti import OpenCTIApiClient

    opencti_url = os.getenv("OPENCTI_URL")
    opencti_token = os.getenv("OPENCTI_TOKEN")
    if not opencti_url or not opencti_token:
        raise ValueError("OPENCTI_URL and OPENCTI_TOKEN are required for export")
    return OpenCTIApiClient(opencti_url, opencti_token)


def build_artifact_dedup(args, api_client=None):
    state_file = args.dedup_state_file or os.getenv("NARROWCTI_DEDUP_STATE_FILE", "")
    local_index = ArtifactDeduplicationIndex(state_file) if state_file else None
    opencti_lookup = None
    if args.opencti_dedup_lookup:
        if not api_client:
            raise ValueError("OpenCTI client is required for OpenCTI dedup lookup")
        opencti_lookup = OpenCTIArtifactLookup(api_client)
    if not local_index and not opencti_lookup:
        return None
    return CompositeArtifactDeduplication(
        local_index=local_index,
        opencti_lookup=opencti_lookup,
    )


def format_export_results(results):
    lines = [
        "NarrowCTI quarantine export",
        f"count={len(results)}",
    ]
    for result in results:
        lines.append(
            f"- {result['quarantine_id']} action={result['action']} "
            f"status={result['status']} dry_run={str(result['dry_run']).lower()} "
            f"exported_indicators={result['exported_indicator_count']} "
            f"duplicates={result['dedup_duplicate_count']} "
            f"title={result['title'] or '(untitled)'}"
        )
        if result.get("reason"):
            lines.append(f"  reason={result['reason']}")
        for error in result.get("errors") or []:
            lines.append(f"  error={error}")
    return "\n".join(lines)


def build_parser():
    parser = argparse.ArgumentParser(
        description="Review NarrowCTI quarantine records."
    )
    parser.add_argument(
        "--repository",
        default="",
        help="Quarantine JSONL repository path.",
    )
    parser.add_argument(
        "--release-audit-file",
        default="",
        help="Release audit JSONL path.",
    )
    parser.add_argument("--json", action="store_true", help="Print JSON output.")

    subparsers = parser.add_subparsers(dest="command", required=True)

    list_parser = subparsers.add_parser("list", help="List quarantine records.")
    list_parser.add_argument("--status", default="pending", help="Status filter.")
    list_parser.set_defaults(func=command_list)

    show_parser = subparsers.add_parser("show", help="Show one quarantine record.")
    show_parser.add_argument("--id", required=True, help="Quarantine id.")
    show_parser.set_defaults(func=command_show)

    reject_parser = subparsers.add_parser("reject", help="Reject a pending record.")
    reject_parser.add_argument("--id", required=True, help="Quarantine id.")
    reject_parser.add_argument("--reason", required=True, help="Review reason.")
    reject_parser.add_argument("--reviewer", default="", help="Reviewer identity.")
    reject_parser.set_defaults(func=command_reject)

    release_parser = subparsers.add_parser("release", help="Release a pending record.")
    release_parser.add_argument("--id", required=True, help="Quarantine id.")
    release_parser.add_argument("--reason", required=True, help="Review reason.")
    release_parser.add_argument("--reviewer", default="", help="Reviewer identity.")
    release_parser.set_defaults(func=command_release)

    partial_parser = subparsers.add_parser(
        "release-indicators",
        help="Release only selected indicator types from a pending record.",
    )
    partial_parser.add_argument("--id", required=True, help="Quarantine id.")
    partial_parser.add_argument(
        "--type",
        required=True,
        help="Comma-separated indicator types to release.",
    )
    partial_parser.add_argument("--reason", required=True, help="Review reason.")
    partial_parser.add_argument("--reviewer", default="", help="Reviewer identity.")
    partial_parser.set_defaults(func=command_release_indicators)

    export_parser = subparsers.add_parser(
        "export-released",
        help="Replay released quarantine records through the OpenCTI export path.",
    )
    export_parser.add_argument("--id", default="", help="Optional quarantine id.")
    export_parser.add_argument("--limit", type=int, default=0, help="Maximum records.")
    export_parser.add_argument(
        "--execute",
        action="store_true",
        help="Export to OpenCTI. Without this flag the command runs as dry-run.",
    )
    export_parser.add_argument(
        "--dedup-state-file",
        default="",
        help="Artifact dedup state file. Defaults to NARROWCTI_DEDUP_STATE_FILE.",
    )
    export_parser.add_argument(
        "--opencti-dedup-lookup",
        action="store_true",
        help="Check OpenCTI for existing indicator patterns before export.",
    )
    export_parser.add_argument(
        "--identity-name",
        default=os.getenv("CONNECTOR_NAME", "NarrowCTI Gateway"),
        help="STIX identity name used for exported objects.",
    )
    export_parser.set_defaults(func=command_export_released)

    return parser


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except (KeyError, ValueError) as exc:
        parser.error(str(exc))
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
