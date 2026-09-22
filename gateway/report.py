"""Compatibility/composition surface for operational gateway reports."""

from __future__ import annotations
# ruff: noqa: F401, F403, F405

import argparse
import os

from narrowcti.application.reporting.operational import *  # noqa: F403
from narrowcti.application.reporting.operational import build_operational_report, render_report
from narrowcti.application.runtime import SUMMARY_FIELDS
from narrowcti.adapters.persistence.local.quarantine_repository import QuarantineRepository
from narrowcti.infrastructure.runtime.summary_store import read_gateway_summary_file
from gateway.settings import load_settings


def read_quarantine_records(repository_file):
    if not repository_file:
        return []
    return QuarantineRepository(repository_file).records()


def write_report(report, output_file, output_format="text"):
    output_file = str(output_file or "").strip()
    if not output_file:
        return None
    directory = os.path.dirname(output_file)
    if directory:
        os.makedirs(directory, exist_ok=True)
    with open(output_file, "w", encoding="utf-8") as handle:
        handle.write(render_report(report, output_format=output_format) + "\n")
    return None


def main():
    parser = argparse.ArgumentParser(
        description="Summarize NarrowCTI gateway JSONL run summaries."
    )
    parser.add_argument("--file", default="", help="Gateway JSONL summary file. Defaults to NARROWCTI_RUN_SUMMARY_FILE.")
    parser.add_argument("--limit", type=int, default=0, help="Only read the most recent N records. Zero reads all records.")
    parser.add_argument("--json", action="store_true", help="Print JSON output.")
    parser.add_argument("--output-file", default="", help="Optional path where the rendered report should be written.")
    parser.add_argument("--quarantine-file", default="", help="Optional quarantine repository JSONL file for review metrics.")
    args = parser.parse_args()

    settings = load_settings()
    summary_file = args.file or settings.run_summary_file
    if not summary_file:
        raise SystemExit("summary file is required")
    records = read_gateway_summary_file(summary_file, limit=args.limit or None)
    quarantine_records = read_quarantine_records(
        args.quarantine_file or settings.quarantine_repository_file
    )
    report = build_operational_report(records, quarantine_records=quarantine_records)
    output_format = "json" if args.json else "text"
    write_report(report, args.output_file, output_format)
    print(render_report(report, output_format))


if __name__ == "__main__":
    main()
