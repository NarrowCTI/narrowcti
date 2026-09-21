"""Historical quarantine CLI entrypoint backed by the canonical CLI."""

from narrowcti.cli.quarantine import (
    DEFAULT_RELEASE_AUDIT,
    DEFAULT_REPOSITORY,
    build_artifact_dedup,
    build_opencti_client_from_env as build_opencti_client,
    build_parser,
    command_audit,
    command_export_released,
    command_list,
    command_reject,
    command_release,
    command_release_indicators,
    command_show,
    command_summary,
    format_export_results,
    format_record_detail,
    format_record_summary,
    format_release_audit_events,
    format_review_summary,
    format_optional,
    main,
    print_data as print_output,
    reason_required,
    read_release_audit_events,
    repository_from_args,
    review_service_from_args,
    reviewer,
)

__all__ = [
    "DEFAULT_REPOSITORY", "DEFAULT_RELEASE_AUDIT", "build_artifact_dedup",
    "build_opencti_client", "build_parser", "command_audit", "command_export_released",
    "command_list", "command_reject", "command_release", "command_release_indicators",
    "command_show", "command_summary", "format_export_results", "format_record_detail",
    "format_record_summary", "format_release_audit_events", "format_review_summary",
    "format_optional", "main", "print_output", "reason_required",
    "read_release_audit_events", "repository_from_args", "review_service_from_args",
    "reviewer",
]


if __name__ == "__main__":
    raise SystemExit(main())
