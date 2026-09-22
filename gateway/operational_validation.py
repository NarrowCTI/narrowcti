"""Compatibility/composition surface for operational validation."""

from __future__ import annotations
# ruff: noqa: F403, F405

import argparse
import json
import os

from narrowcti.application.assurance.operational_validation import *  # noqa: F403
from narrowcti.application.assurance.operational_validation import build_operational_validation_report
from narrowcti.application.reporting.decisions import build_decision_audit_report
from narrowcti.adapters.persistence.local.decision_audit_reader import read_decision_records
from narrowcti.application.preflight import build_preflight_report
from gateway.settings import load_settings

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


def load_manual_evidence(evidence_file):
    evidence_file = str(evidence_file or "").strip()
    if not evidence_file or not os.path.exists(evidence_file):
        return {}
    with open(evidence_file, "r", encoding="utf-8-sig") as handle:
        data = json.load(handle)
    if not isinstance(data, dict):
        raise ValueError("operational validation evidence file must contain a JSON object")
    return data


def load_relationship_audit_evidence(evidence_file):
    evidence_file = str(evidence_file or "").strip()
    if not evidence_file or not os.path.exists(evidence_file):
        return {}
    with open(evidence_file, "r", encoding="utf-8-sig") as handle:
        data = json.load(handle)
    if not isinstance(data, dict):
        raise ValueError("relationship audit evidence file must contain a JSON object")
    return data


def main():
    parser = argparse.ArgumentParser(
        description="Build the current v1.0 operational validation checklist from local evidence."
    )
    parser.add_argument(
        "--decision-path",
        action="append",
        default=[],
        help="Decision audit JSONL file or directory. Defaults to NARROWCTI_DECISION_AUDIT_DIR.",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=0,
        help="Read only the most recent N decision records.",
    )
    parser.add_argument(
        "--required-sources",
        default="otx,misp",
        help="Comma-separated source keys expected in bounded dry-run evidence.",
    )
    parser.add_argument(
        "--evidence-file",
        default="",
        help=(
            "Optional JSON file with manual validation evidence such as "
            "full_validation_passed, opencti_ui_no_duplicate and resource_posture_ok."
        ),
    )
    parser.add_argument(
        "--relationship-audit-file",
        default=os.getenv("NARROWCTI_OPENCTI_RELATIONSHIP_AUDIT_FILE", ""),
        help="Optional JSON file produced by gateway.opencti_relationship_audit.",
    )
    parser.add_argument(
        "--full-validation-passed",
        action="store_true",
        help="Mark repository validation as passed after .\\scripts\\validate-release.ps1 succeeds.",
    )
    parser.add_argument(
        "--opencti-ui-no-duplicate",
        action="store_true",
        help="Mark the OpenCTI UI duplicate ATT&CK object check as passed.",
    )
    parser.add_argument(
        "--opencti-ui-duplicate-found",
        action="store_true",
        help="Mark the OpenCTI UI duplicate ATT&CK object check as failed.",
    )
    parser.add_argument(
        "--resource-posture-ok",
        action="store_true",
        help="Mark local lab resource posture as healthy after bounded validation.",
    )
    parser.add_argument(
        "--resource-posture-unhealthy",
        action="store_true",
        help="Mark local lab resource posture as unhealthy after bounded validation.",
    )
    parser.add_argument(
        "--format",
        choices=("text", "json", "html"),
        default="text",
        help="Output format for stdout or --output-file.",
    )
    parser.add_argument(
        "--output-file",
        default="",
        help="Optional file path to write the rendered validation report.",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Print JSON output. Deprecated alias for --format json.",
    )
    args = parser.parse_args()

    settings = load_settings()
    preflight = build_preflight_report(settings)
    records = read_decision_records(
        args.decision_path or [settings.decision_audit_dir],
        limit=args.limit or None,
    )
    decisions = build_decision_audit_report(records)
    manual_evidence = load_manual_evidence(args.evidence_file)
    relationship_audit_evidence = load_relationship_audit_evidence(
        args.relationship_audit_file
    )
    report = build_operational_validation_report(
        preflight,
        decisions,
        full_validation_passed=args.full_validation_passed
        or evidence_bool(manual_evidence, "full_validation_passed"),
        opencti_ui_no_duplicate=args.opencti_ui_no_duplicate
        or evidence_bool(manual_evidence, "opencti_ui_no_duplicate"),
        opencti_ui_duplicate_found=args.opencti_ui_duplicate_found
        or evidence_bool(manual_evidence, "opencti_ui_duplicate_found"),
        resource_posture_ok=args.resource_posture_ok
        or evidence_bool(manual_evidence, "resource_posture_ok"),
        resource_posture_unhealthy=args.resource_posture_unhealthy
        or evidence_bool(manual_evidence, "resource_posture_unhealthy"),
        resource_posture_evidence=manual_evidence.get("resource_posture"),
        relationship_audit_evidence=relationship_audit_evidence,
        required_sources=parse_sources(args.required_sources),
    )
    output_format = "json" if args.json else args.format
    rendered = render_report(report, output_format=output_format)
    if args.output_file:
        write_report(report, args.output_file, output_format=output_format)
    print(rendered)




if __name__ == "__main__":
    main()
