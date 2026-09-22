"""Compatibility/composition surface for artifact correlation reports."""

from __future__ import annotations
# ruff: noqa: F403, F405

import argparse
import os

from narrowcti.application.reporting.correlation import *  # noqa: F403
from narrowcti.application.reporting.correlation import (
    build_correlation_report,
    render_report,
)
from narrowcti.adapters.persistence.local.artifact_index import load_artifact_state
from gateway.settings import load_settings

ARTIFACTS_KEY = "artifact_fingerprints"
ARTIFACT_RECORDS_KEY = "artifact_records"


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
        description="Summarize NarrowCTI local artifact correlation state."
    )
    parser.add_argument("--file", default="", help="Artifact dedup state file. Defaults to NARROWCTI_DEDUP_STATE_FILE.")
    parser.add_argument("--limit", type=int, default=20, help="Maximum correlated artifacts to print. Zero prints all.")
    parser.add_argument("--output-file", default="", help="Optional file path to write the rendered correlation report.")
    parser.add_argument("--json", action="store_true", help="Print JSON output.")
    args = parser.parse_args()

    state_file = args.file or load_settings().dedup_state_file
    report = build_correlation_report(load_artifact_state(state_file), limit=args.limit)
    output_format = "json" if args.json else "text"
    rendered = render_report(report, output_format=output_format)
    if args.output_file:
        write_report(report, args.output_file, output_format=output_format)
    print(rendered)


if __name__ == "__main__":
    main()
