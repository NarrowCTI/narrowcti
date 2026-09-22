"""Local filesystem writer for support-safe diagnostic artifacts."""

from __future__ import annotations

import json
import os
import zipfile

from narrowcti.application.support.diagnostics import (
    format_html_snapshot,
    format_text_snapshot,
)


def write_support_bundle(snapshot, bundle_file):
    if snapshot.redaction_profile != "support":
        raise ValueError("support bundle requires redaction_profile=support")
    bundle_file = str(bundle_file or "").strip()
    if not bundle_file:
        raise ValueError("bundle_file is required")

    directory = os.path.dirname(bundle_file)
    if directory:
        os.makedirs(directory, exist_ok=True)

    snapshot_json = json.dumps(snapshot.to_dict(), sort_keys=True, indent=2)
    snapshot_text = format_text_snapshot(snapshot)
    snapshot_html = format_html_snapshot(snapshot)
    manifest = {
        "schema_version": "support-bundle/v0.8",
        "generated_at": snapshot.generated_at,
        "snapshot_schema_version": snapshot.schema_version,
        "redaction_profile": snapshot.redaction_profile,
        "files": [
            "support-diagnostics.json",
            "support-diagnostics.txt",
            "support-diagnostics.html",
            "manifest.json",
        ],
        "raw_evidence_included": False,
        "notes": [
            "This bundle contains only the redacted support diagnostic snapshot.",
            "Raw logs, state files, decision audit JSONL and quarantine records are not included.",
        ],
    }
    with zipfile.ZipFile(bundle_file, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("support-diagnostics.json", snapshot_json + "\n")
        archive.writestr("support-diagnostics.txt", snapshot_text + "\n")
        archive.writestr("support-diagnostics.html", snapshot_html + "\n")
        archive.writestr(
            "manifest.json",
            json.dumps(manifest, sort_keys=True, indent=2) + "\n",
        )
    return {
        "bundle_file": bundle_file,
        "files": manifest["files"],
        "raw_evidence_included": False,
    }


def write_html_snapshot(snapshot, html_file):
    html_file = str(html_file or "").strip()
    if not html_file:
        raise ValueError("html_file is required")
    directory = os.path.dirname(html_file)
    if directory:
        os.makedirs(directory, exist_ok=True)
    with open(html_file, "w", encoding="utf-8") as handle:
        handle.write(format_html_snapshot(snapshot) + "\n")
    return html_file


__all__ = ["write_support_bundle", "write_html_snapshot"]
