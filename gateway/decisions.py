"""Compatibility/composition surface for decision audit reporting."""

from __future__ import annotations
# ruff: noqa: F401, F403, F405

import argparse
import os

from narrowcti.application.reporting.decisions import *  # noqa: F403
from narrowcti.application.reporting.decisions import build_decision_audit_report, render_report
from narrowcti.adapters.persistence.local.decision_audit_reader import (
    expand_paths,
    read_decision_records,
)
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
    parser.add_argument(
        "--quarantine-limit",
        type=int,
        default=10,
        help="Maximum quarantined candidates to include. Zero includes all candidates.",
    )
    parser.add_argument(
        "--output-file",
        default="",
        help="Optional file path to write the rendered decision audit report.",
    )
    parser.add_argument("--json", action="store_true", help="Print JSON output.")
    args = parser.parse_args()

    paths = list(args.file)
    if args.dir:
        paths.append(args.dir)
    if not paths:
        paths.append(load_settings().decision_audit_dir)

    records = read_decision_records(paths, limit=args.limit or None)
    report = build_decision_audit_report(
        records,
        reason_limit=args.reason_limit,
        quarantine_limit=args.quarantine_limit,
    )
    output_format = "json" if args.json else "text"
    rendered = render_report(report, output_format=output_format)
    if args.output_file:
        write_report(report, args.output_file, output_format=output_format)
    print(rendered)


if __name__ == "__main__":
    main()
