"""Compatibility/composition surface for support diagnostics."""

from __future__ import annotations
# ruff: noqa: F403, F405

import argparse
import json
import os
from datetime import datetime, timezone

from narrowcti.application.support.diagnostics import *  # noqa: F403
from narrowcti.application.support.diagnostics import (
    build_support_diagnostics as _build_support_diagnostics,
)
from narrowcti.adapters.persistence.local.support_bundle import (
    write_html_snapshot,
    write_support_bundle,
)
from gateway.curation_report import build_curation_report_from_files
from gateway.decisions import build_decision_audit_report, read_decision_records
from gateway.operational_validation import (
    build_operational_validation_report,
    evidence_bool,
    load_relationship_audit_evidence,
    load_manual_evidence,
)
from gateway.preflight import build_preflight_report
from gateway.settings import load_settings

def build_support_diagnostics(
    settings,
    summary_file="",
    decision_paths=None,
    quarantine_file="",
    release_audit_file="",
    limit=0,
    env=None,
    generated_at="",
    redaction_profile="none",
    operational_validation_evidence_file="",
    opencti_relationship_audit_file="",
):
    preflight = build_preflight_report(settings, env=env)
    evidence = collect_evidence_inventory(preflight)
    if operational_validation_evidence_file:
        evidence.append(evidence_item("operational_validation_evidence_file", operational_validation_evidence_file))
    if opencti_relationship_audit_file:
        evidence.append(evidence_item("opencti_relationship_audit_file", opencti_relationship_audit_file))
    resolved_decision_paths = decision_paths or [settings.decision_audit_dir]
    curation = build_curation_report_from_files(
        summary_file=summary_file or settings.run_summary_file,
        decision_paths=resolved_decision_paths,
        quarantine_file=quarantine_file or settings.quarantine_repository_file,
        release_audit_file=release_audit_file or settings.release_audit_file,
        relationship_audit_file=opencti_relationship_audit_file,
        limit=limit,
    )
    decision_records = read_decision_records(resolved_decision_paths, limit=limit or None)
    decisions = build_decision_audit_report(decision_records)
    manual_evidence = load_manual_evidence(operational_validation_evidence_file)
    relationship_audit_evidence = load_relationship_audit_evidence(opencti_relationship_audit_file)
    operational_validation = build_operational_validation_report(
        preflight,
        decisions,
        full_validation_passed=evidence_bool(manual_evidence, "full_validation_passed"),
        opencti_ui_no_duplicate=evidence_bool(manual_evidence, "opencti_ui_no_duplicate"),
        opencti_ui_duplicate_found=evidence_bool(manual_evidence, "opencti_ui_duplicate_found"),
        resource_posture_ok=evidence_bool(manual_evidence, "resource_posture_ok"),
        resource_posture_unhealthy=evidence_bool(manual_evidence, "resource_posture_unhealthy"),
        relationship_audit_evidence=relationship_audit_evidence,
        required_sources=preflight.enabled_sources,
    )
    return _build_support_diagnostics(
        preflight,
        evidence,
        curation,
        operational_validation,
        generated_at=generated_at,
        redaction_profile=redaction_profile,
    )

def collect_evidence_inventory(preflight_report):
    paths = preflight_report.evidence_paths or {}
    items = [
        evidence_item("state_dir", paths.get("state_dir"), expected_kind="directory"),
        evidence_item(
            "decision_audit_dir",
            paths.get("decision_audit_dir"),
            expected_kind="directory",
        ),
        evidence_item("run_summary_file", paths.get("run_summary_file")),
        evidence_item(
            "quarantine_repository_file",
            paths.get("quarantine_repository_file"),
        ),
        evidence_item("release_audit_file", paths.get("release_audit_file")),
        evidence_item("dedup_state_file", paths.get("dedup_state_file")),
        evidence_item(
            "graph_dedup_state_file",
            paths.get("graph_dedup_state_file"),
        ),
        evidence_item("mitre_cache_file", paths.get("mitre_cache_file")),
    ]
    for source_key, source_paths in sorted((paths.get("sources") or {}).items()):
        items.append(
            evidence_item(
                f"{source_key}.state_file",
                source_paths.get("state_file"),
            )
        )
        items.append(
            evidence_item(
                f"{source_key}.decision_audit_file",
                source_paths.get("decision_audit_file"),
            )
        )
    return [item for item in items if item.get("configured")]


def evidence_item(name, path, expected_kind="file"):
    path = str(path or "").strip()
    item = {
        "name": name,
        "path": path,
        "configured": bool(path),
        "expected_kind": expected_kind,
        "exists": False,
        "kind": "",
        "size_bytes": 0,
        "modified_at": "",
        "readable": False,
    }
    if not path:
        return item
    try:
        item["exists"] = os.path.exists(path)
        if not item["exists"]:
            return item
        item["kind"] = "directory" if os.path.isdir(path) else "file"
        item["readable"] = os.access(path, os.R_OK)
        if os.path.isfile(path):
            stat = os.stat(path)
            item["size_bytes"] = stat.st_size
            item["modified_at"] = datetime.fromtimestamp(
                stat.st_mtime,
                timezone.utc,
            ).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    except OSError as exc:
        item["error"] = str(exc)
    return item


def main():
    parser = argparse.ArgumentParser(
        description="Build a read-only NarrowCTI support diagnostic snapshot."
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
        "--limit",
        type=int,
        default=0,
        help="Read only the most recent N records where supported.",
    )
    parser.add_argument(
        "--redaction-profile",
        choices=REDACTION_PROFILES,
        default="none",
        help="Redact sensitive local details for support sharing.",
    )
    parser.add_argument(
        "--bundle-file",
        default="",
        help="Write a support-safe zip bundle. Requires --redaction-profile support.",
    )
    parser.add_argument(
        "--html-file",
        default="",
        help="Write an HTML diagnostic snapshot.",
    )
    parser.add_argument(
        "--operational-validation-evidence-file",
        default=os.environ.get("NARROWCTI_OPERATIONAL_VALIDATION_EVIDENCE_FILE", ""),
        help="Optional JSON file with manual current operational validation evidence.",
    )
    parser.add_argument(
        "--opencti-relationship-audit-file",
        default=os.environ.get("NARROWCTI_OPENCTI_RELATIONSHIP_AUDIT_FILE", ""),
        help="Optional JSON file produced by gateway.opencti_relationship_audit.",
    )
    parser.add_argument("--json", action="store_true", help="Print JSON output.")
    args = parser.parse_args()

    settings = load_settings()
    snapshot = build_support_diagnostics(
        settings,
        summary_file=args.summary_file,
        decision_paths=args.decision_path,
        quarantine_file=args.quarantine_file,
        release_audit_file=args.release_audit_file,
        limit=args.limit,
        redaction_profile=args.redaction_profile,
        operational_validation_evidence_file=args.operational_validation_evidence_file,
        opencti_relationship_audit_file=args.opencti_relationship_audit_file,
    )
    bundle_result = None
    if args.bundle_file:
        try:
            bundle_result = write_support_bundle(snapshot, args.bundle_file)
        except ValueError as exc:
            raise SystemExit(str(exc)) from None
    html_result = None
    if args.html_file:
        try:
            html_result = write_html_snapshot(snapshot, args.html_file)
        except ValueError as exc:
            raise SystemExit(str(exc)) from None
    if args.json:
        output = snapshot.to_dict()
        if bundle_result:
            output["support_bundle"] = bundle_result
        if html_result:
            output["html_file"] = html_result
        print(json.dumps(output, sort_keys=True))
    else:
        print(format_text_snapshot(snapshot))
        if bundle_result:
            print(f"support_bundle={bundle_result['bundle_file']}")
        if html_result:
            print(f"html_file={html_result}")




if __name__ == "__main__":
    main()
