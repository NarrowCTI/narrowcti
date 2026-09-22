"""Compatibility/composition surface for curation reports."""

from __future__ import annotations
# ruff: noqa: F403, F405

import argparse
import json
import os

from narrowcti.application.reporting.curation import *  # noqa: F403
from narrowcti.application.reporting.curation import build_curation_report
from narrowcti.application.reporting.operational import build_operational_report
from narrowcti.application.reporting.decisions import build_decision_audit_report
from narrowcti.adapters.persistence.local.decision_audit_reader import read_decision_records
from narrowcti.adapters.persistence.local.review_audit import read_audit_events
from narrowcti.infrastructure.runtime.summary_store import read_gateway_summary_file
from gateway.report import read_quarantine_records
from gateway.review import AnalystReviewService, ReviewSummary
from gateway.settings import load_settings

def build_curation_report_from_files(
    summary_file="",
    decision_paths=None,
    quarantine_file="",
    release_audit_file="",
    relationship_audit_file="",
    limit=0,
):
    summary_records = safe_read_gateway_summary_file(summary_file, limit=limit)
    quarantine_records = read_quarantine_records(quarantine_file) if quarantine_file else []
    operational = build_operational_report(
        summary_records,
        quarantine_records=quarantine_records,
    )
    decision_records = read_decision_records(decision_paths or (), limit=limit or None)
    decisions = build_decision_audit_report(decision_records)
    review_summary = build_review_summary(quarantine_file, release_audit_file)
    review_actions = build_review_action_summary(
        safe_read_audit_events(release_audit_file, limit=limit),
    )
    graph_validation = build_graph_validation_summary(
        load_relationship_audit_evidence(relationship_audit_file)
    )
    return build_curation_report(
        operational,
        decisions,
        review_summary,
        analyst_review_actions=review_actions,
        graph_validation=graph_validation,
    )


def safe_read_gateway_summary_file(summary_file, limit=0):
    if not summary_file or not os.path.exists(summary_file):
        return []
    return read_gateway_summary_file(summary_file, limit=limit or None)


def build_review_summary(quarantine_file="", release_audit_file=""):
    if not quarantine_file or not os.path.exists(quarantine_file):
        return ReviewSummary(
            record_count=0,
            status_counts={},
            source_counts={},
            pending_count=0,
            exportable_count=0,
        )
    return AnalystReviewService.from_paths(
        quarantine_file,
        release_audit_file=release_audit_file,
    ).summary()


def safe_read_audit_events(release_audit_file="", limit=0):
    if not release_audit_file or not os.path.exists(release_audit_file):
        return []
    events = read_audit_events(release_audit_file)
    if limit and limit > 0:
        return events[-limit:]
    return events


def load_relationship_audit_evidence(evidence_file):
    evidence_file = str(evidence_file or "").strip()
    if not evidence_file or not os.path.exists(evidence_file):
        return {}
    with open(evidence_file, "r", encoding="utf-8") as handle:
        data = json.load(handle)
    if not isinstance(data, dict):
        raise ValueError("relationship audit evidence file must contain a JSON object")
    return data


def write_html_report(report, html_file, redaction_profile="none"):
    html_file = str(html_file or "").strip()
    if not html_file:
        raise ValueError("html_file is required")
    directory = os.path.dirname(html_file)
    if directory:
        os.makedirs(directory, exist_ok=True)
    with open(html_file, "w", encoding="utf-8") as handle:
        handle.write(
            format_html_report(report, redaction_profile=redaction_profile) + "\n"
        )
    return html_file


def write_report(report, output_file, output_format="text", redaction_profile="none"):
    output_file = str(output_file or "").strip()
    if not output_file:
        raise ValueError("output_file is required")
    directory = os.path.dirname(output_file)
    if directory:
        os.makedirs(directory, exist_ok=True)
    with open(output_file, "w", encoding="utf-8") as handle:
        handle.write(
            render_report(
                report,
                output_format=output_format,
                redaction_profile=redaction_profile,
            )
            + "\n"
        )
    return output_file


def main():
    parser = argparse.ArgumentParser(
        description="Build an analyst-facing NarrowCTI curation report."
    )
    parser.add_argument(
        "--summary-file",
        default="",
        help="Gateway run summary JSONL. Defaults to NARROWCTI_RUN_SUMMARY_FILE.",
    )
    parser.add_argument(
        "--decision-path",
        action="append",
        default=[],
        help="Decision audit JSONL file or directory. Can be passed more than once.",
    )
    parser.add_argument(
        "--quarantine-file",
        default="",
        help="Quarantine repository JSONL. Defaults to NARROWCTI_QUARANTINE_REPOSITORY.",
    )
    parser.add_argument(
        "--release-audit-file",
        default="",
        help="Release audit JSONL. Defaults to NARROWCTI_RELEASE_AUDIT_FILE.",
    )
    parser.add_argument(
        "--relationship-audit-file",
        default=os.getenv("NARROWCTI_OPENCTI_RELATIONSHIP_AUDIT_FILE", ""),
        help="Optional JSON file produced by gateway.opencti_relationship_audit.",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=0,
        help="Read only the most recent N records where supported.",
    )
    parser.add_argument(
        "--html-file",
        default="",
        help="Optional HTML report output file.",
    )
    parser.add_argument(
        "--output-file",
        default="",
        help="Optional text report output file.",
    )
    parser.add_argument(
        "--json-file",
        default="",
        help="Optional JSON report output file.",
    )
    parser.add_argument(
        "--redaction-profile",
        choices=REDACTION_PROFILES,
        default="none",
        help="Redact detailed local evidence for support sharing.",
    )
    parser.add_argument("--json", action="store_true", help="Print JSON output.")
    args = parser.parse_args()

    settings = load_settings()
    report = build_curation_report_from_files(
        summary_file=args.summary_file or settings.run_summary_file,
        decision_paths=args.decision_path or [settings.decision_audit_dir],
        quarantine_file=args.quarantine_file or settings.quarantine_repository_file,
        release_audit_file=args.release_audit_file or settings.release_audit_file,
        relationship_audit_file=args.relationship_audit_file,
        limit=args.limit,
    )
    if args.html_file:
        write_html_report(
            report,
            args.html_file,
            redaction_profile=args.redaction_profile,
        )
    if args.output_file:
        write_report(
            report,
            args.output_file,
            output_format="text",
            redaction_profile=args.redaction_profile,
        )
    if args.json_file:
        write_report(
            report,
            args.json_file,
            output_format="json",
            redaction_profile=args.redaction_profile,
        )
    if args.json:
        print(render_report(report, "json", redaction_profile=args.redaction_profile))
    else:
        print(render_report(report, "text", redaction_profile=args.redaction_profile))




if __name__ == "__main__":
    main()
