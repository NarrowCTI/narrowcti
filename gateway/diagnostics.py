import argparse
import copy
import html
import json
import os
import zipfile
from dataclasses import dataclass
from datetime import datetime, timezone

from core.decision_audit import utc_now
from gateway.curation_report import (
    build_curation_report_from_files,
    format_context_narrative_summary,
    format_context_quality_summary,
    format_graph_evidence_summary,
    format_policy_score_summary,
    format_reason_entries,
    format_redaction_policy,
    report_to_dict,
)
from gateway.decisions import build_decision_audit_report, read_decision_records
from gateway.operational_validation import (
    build_operational_validation_report,
    evidence_bool,
    load_manual_evidence,
)
from gateway.preflight import build_preflight_report
from gateway.settings import load_settings


SCHEMA_VERSION = "support-diagnostics/v0.8"
REDACTION_PROFILES = ("none", "support", "external")


@dataclass(frozen=True)
class SupportDiagnosticSnapshot:
    schema_version: str
    generated_at: str
    redaction_profile: str
    preflight: dict
    evidence_inventory: list
    curation_report: dict
    operational_validation: dict
    support_warnings: list

    def to_dict(self):
        return {
            "schema_version": self.schema_version,
            "generated_at": self.generated_at,
            "redaction_profile": self.redaction_profile,
            "preflight": self.preflight,
            "evidence_inventory": list(self.evidence_inventory),
            "curation_report": self.curation_report,
            "operational_validation": self.operational_validation,
            "support_warnings": list(self.support_warnings),
        }


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
):
    profile = normalize_redaction_profile(redaction_profile)
    preflight = build_preflight_report(settings, env=env)
    evidence = collect_evidence_inventory(preflight)
    if operational_validation_evidence_file:
        evidence.append(
            evidence_item(
                "operational_validation_evidence_file",
                operational_validation_evidence_file,
            )
        )
    resolved_decision_paths = decision_paths or [settings.decision_audit_dir]
    curation = build_curation_report_from_files(
        summary_file=summary_file or settings.run_summary_file,
        decision_paths=resolved_decision_paths,
        quarantine_file=quarantine_file or settings.quarantine_repository_file,
        release_audit_file=release_audit_file or settings.release_audit_file,
        limit=limit,
    )
    decision_records = read_decision_records(
        resolved_decision_paths,
        limit=limit or None,
    )
    decisions = build_decision_audit_report(decision_records)
    manual_evidence = load_manual_evidence(operational_validation_evidence_file)
    operational_validation = build_operational_validation_report(
        preflight,
        decisions,
        full_validation_passed=evidence_bool(
            manual_evidence,
            "full_validation_passed",
        ),
        opencti_ui_no_duplicate=evidence_bool(
            manual_evidence,
            "opencti_ui_no_duplicate",
        ),
        opencti_ui_duplicate_found=evidence_bool(
            manual_evidence,
            "opencti_ui_duplicate_found",
        ),
        resource_posture_ok=evidence_bool(manual_evidence, "resource_posture_ok"),
        resource_posture_unhealthy=evidence_bool(
            manual_evidence,
            "resource_posture_unhealthy",
        ),
        required_sources=preflight.enabled_sources,
    )
    snapshot = SupportDiagnosticSnapshot(
        schema_version=SCHEMA_VERSION,
        generated_at=generated_at or utc_now(),
        redaction_profile=profile,
        preflight=preflight.to_dict(),
        evidence_inventory=evidence,
        curation_report=report_to_dict(curation, redaction_profile=profile),
        operational_validation=operational_validation.to_dict(),
        support_warnings=build_support_warnings(
            preflight,
            evidence,
            curation,
            operational_validation,
        ),
    )
    if snapshot.redaction_profile == "none":
        return snapshot
    return snapshot_from_dict(redact_snapshot_dict(snapshot.to_dict()))


def normalize_redaction_profile(value):
    profile = str(value or "none").strip().lower()
    if profile not in REDACTION_PROFILES:
        raise ValueError(
            "redaction_profile must be one of: " + ",".join(REDACTION_PROFILES)
        )
    return profile


def snapshot_from_dict(data):
    return SupportDiagnosticSnapshot(
        schema_version=data["schema_version"],
        generated_at=data["generated_at"],
        redaction_profile=data.get("redaction_profile", "none"),
        preflight=data.get("preflight") or {},
        evidence_inventory=data.get("evidence_inventory") or [],
        curation_report=data.get("curation_report") or {},
        operational_validation=data.get("operational_validation") or {},
        support_warnings=data.get("support_warnings") or [],
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


def build_support_warnings(
    preflight_report,
    evidence_inventory,
    curation_report,
    operational_validation_report=None,
):
    warnings = []
    if not preflight_report.ok:
        warnings.append(
            support_warning(
                "preflight-errors",
                "Preflight has blocking errors; fix configuration before runtime validation.",
            )
        )
    preflight_warning_count = sum(
        1 for issue in preflight_report.issues if issue.severity == "warning"
    )
    if preflight_warning_count:
        warnings.append(
            support_warning(
                "preflight-warnings",
                f"Preflight has {preflight_warning_count} warning issue(s).",
            )
        )

    missing = [
        item["name"]
        for item in evidence_inventory
        if item.get("configured") and not item.get("exists")
    ]
    if missing:
        warnings.append(
            support_warning(
                "missing-configured-evidence",
                "Configured evidence paths are missing: " + ",".join(missing),
            )
        )

    recommendations = curation_report.to_dict().get("recommendations") or []
    if any(item.get("code") == "collect-evidence" for item in recommendations):
        warnings.append(
            support_warning(
                "curation-evidence-missing",
                "No run or decision evidence was found for the curation report.",
            )
        )
    if operational_validation_report:
        validation = operational_validation_report.to_dict()
        status = validation.get("overall_status", "")
        counts = validation.get("counts") or {}
        if status == "fail":
            warnings.append(
                support_warning(
                    "operational-validation-failed",
                    "v0.8 operational validation has failing checks; graph promotion must remain blocked.",
                )
            )
        elif status == "needs-evidence":
            warnings.append(
                support_warning(
                    "operational-validation-needs-evidence",
                    "v0.8 operational validation still needs evidence: "
                    f"needs-evidence={counts.get('needs-evidence', 0)} "
                    f"warn={counts.get('warn', 0)}.",
                )
            )
    return warnings


def support_warning(code, message):
    return {
        "code": code,
        "message": message,
    }


def redact_snapshot_dict(snapshot):
    redacted = copy.deepcopy(snapshot)
    known_paths = collect_sensitive_paths(redacted)
    redact_preflight(redacted.get("preflight") or {}, known_paths)
    redact_evidence_inventory(redacted.get("evidence_inventory") or [], known_paths)
    redact_curation_report(redacted.get("curation_report") or {}, known_paths)
    redact_text_fields(redacted.get("operational_validation") or {}, known_paths)
    redact_warning_messages(redacted.get("support_warnings") or [], known_paths)
    return redacted


def collect_sensitive_paths(value):
    paths = []
    collect_paths(value, paths)
    return sorted(set(paths), key=len, reverse=True)


def collect_paths(value, paths):
    if isinstance(value, dict):
        for key, item in value.items():
            if should_redact_path_key(key) and isinstance(item, str) and item.strip():
                paths.append(item)
            collect_paths(item, paths)
    elif isinstance(value, list):
        for item in value:
            collect_paths(item, paths)


def redact_preflight(preflight, known_paths):
    settings = preflight.get("settings") or {}
    if settings.get("license_customer_id"):
        settings["license_customer_id"] = "[redacted]"
    redact_paths(settings, known_paths)
    redact_text_fields(settings, known_paths)
    redact_paths(preflight.get("evidence_paths") or {}, known_paths)
    redact_issue_messages(preflight.get("issues") or [], known_paths)


def redact_evidence_inventory(inventory, known_paths):
    for item in inventory:
        if item.get("path"):
            item["path"] = redact_path(item["path"])
        if item.get("error"):
            item["error"] = redact_text(item["error"], known_paths)


def redact_curation_report(report, known_paths):
    operational = report.get("operational") or {}
    operational["failures"] = []
    operational["queries"] = []
    for source in (operational.get("sources") or {}).values():
        if isinstance(source, dict):
            source["failures"] = []

    decisions = report.get("decisions") or {}
    decisions["quarantined"] = []
    decisions["queries"] = []

    redact_text_fields(report, known_paths)


def redact_warning_messages(warnings, known_paths):
    for item in warnings:
        if isinstance(item, dict) and item.get("message"):
            item["message"] = redact_text(item["message"], known_paths)


def redact_issue_messages(issues, known_paths):
    for item in issues:
        if isinstance(item, dict) and item.get("message"):
            item["message"] = redact_text(item["message"], known_paths)


def redact_paths(value, known_paths):
    if isinstance(value, dict):
        for key, item in list(value.items()):
            if should_redact_path_key(key) and isinstance(item, str):
                value[key] = redact_path(item)
            else:
                redact_paths(item, known_paths)
    elif isinstance(value, list):
        for item in value:
            redact_paths(item, known_paths)


def redact_text_fields(value, known_paths):
    if isinstance(value, dict):
        for key, item in list(value.items()):
            redacted_key = redact_text(key, known_paths) if isinstance(key, str) else key
            if isinstance(item, str):
                redacted_item = redact_text(item, known_paths)
            else:
                redact_text_fields(item, known_paths)
                redacted_item = item
            if redacted_key != key:
                value.pop(key, None)
                value[redacted_key] = redacted_item
            else:
                value[key] = redacted_item
    elif isinstance(value, list):
        for item in value:
            redact_text_fields(item, known_paths)


def should_redact_path_key(key):
    key = str(key or "").lower()
    return key == "path" or key.endswith("_file") or key.endswith("_dir")


def redact_text(value, known_paths):
    text = str(value)
    for path in known_paths:
        text = text.replace(path, redact_path(path))
    return text


def redact_path(path):
    path = str(path or "").strip()
    if not path:
        return path
    normalized = path.replace("\\", "/").rstrip("/")
    leaf = normalized.rsplit("/", 1)[-1]
    if not leaf:
        return "[redacted-path]"
    return f"[redacted-path]/{leaf}"


def format_text_snapshot(snapshot):
    data = snapshot.to_dict()
    preflight = data["preflight"]
    curation = data["curation_report"]
    validation = data.get("operational_validation") or {}
    summary = curation["executive_summary"]
    lines = [
        "NarrowCTI support diagnostics",
        f"schema_version={data['schema_version']}",
        f"generated_at={data['generated_at']}",
        f"redaction_profile={data.get('redaction_profile', 'none')}",
        f"curation_report_profile={curation.get('redaction_profile', 'none')}",
        "curation_report_policy:",
        f"- {format_redaction_policy(curation.get('redaction_policy'))}",
        f"preflight_ok={str(preflight.get('ok', False)).lower()}",
        f"ingestion_mode={preflight.get('ingestion_mode', '')}",
        "enabled_sources=" + ",".join(preflight.get("enabled_sources") or []),
        "license_edition="
        f"{preflight.get('settings', {}).get('license_edition', 'evaluation')}",
        "feature_gates_enforced="
        f"{str(preflight.get('settings', {}).get('feature_gates_enforced', False)).lower()}",
        "curation_summary:",
        "- "
        f"runs={summary.get('run_count', 0)} "
        f"decision_records={summary.get('decision_record_count', 0)} "
        f"reviewed={summary.get('reviewed_count', 0)} "
        f"accepted={summary.get('accepted_count', 0)} "
        f"filtered={summary.get('filtered_count', 0)} "
        f"errors={summary.get('error_count', 0)} "
        f"pending_review={summary.get('pending_review_count', 0)}",
        "graph_readiness:",
        "- "
        f"candidates={summary.get('graph_candidate_count', 0)} "
        f"accepted={summary.get('graph_accepted_count', 0)} "
        f"held={summary.get('graph_held_count', 0)} "
        f"lookup_matches={summary.get('graph_lookup_match_count', 0)} "
        f"would_create_objects={summary.get('graph_would_create_object_count', 0)} "
        f"would_create_relationships="
        f"{summary.get('graph_would_create_relationship_count', 0)}",
        "evidence_inventory:",
    ]
    if curation.get("source_summaries"):
        lines.append("source_posture:")
        for source in curation["source_summaries"]:
            lines.append(
                "- "
                f"{source.get('source_key')} posture={source.get('posture')} "
                f"runs={source.get('runs', 0)} failed={source.get('failed', 0)} "
                f"decision_records={source.get('decision_records', 0)} "
                f"pending_review={source.get('pending_review', 0)} "
                f"narrative="
                f"{format_context_narrative_summary(source.get('context_narrative'))}"
            )
    if curation.get("policy_insights"):
        lines.append("policy_insights:")
        for insight in curation["policy_insights"]:
            lines.append(
                "- "
                f"{insight.get('source_key')} severity={insight.get('severity')} "
                f"signal={insight.get('signal')} "
                f"review_decisions={insight.get('review_decision_count', 0)} "
                f"release_rate_pct={insight.get('release_rate_pct', 0)} "
                f"reject_rate_pct={insight.get('reject_rate_pct', 0)} "
                f"scores={format_policy_score_summary(insight.get('score_summary'))} "
                f"graph={format_graph_evidence_summary(insight.get('graph_evidence'))} "
                f"context={format_context_quality_summary(insight.get('context_quality'))} "
                f"narrative="
                f"{format_context_narrative_summary(insight.get('context_narrative'))} "
                f"quarantine_reasons="
                f"{format_reason_entries(insight.get('top_quarantine_reasons'))} "
                f"top_reasons={format_reason_entries(insight.get('top_reasons'))}"
            )
    if validation:
        lines.append("operational_validation:")
        lines.append(
            "- "
            f"overall_status={validation.get('overall_status', '')} "
            + "counts="
            + ",".join(
                f"{status}:{count}"
                for status, count in (validation.get("counts") or {}).items()
            )
        )
        for item in validation.get("checks") or []:
            lines.append(
                "- "
                f"{item.get('code')} status={item.get('status')}: "
                f"{item.get('message')}"
            )
    for item in data["evidence_inventory"]:
        lines.append(
            "- "
            f"{item['name']} exists={str(item.get('exists', False)).lower()} "
            f"kind={item.get('kind') or item.get('expected_kind')} "
            f"size_bytes={item.get('size_bytes', 0)} "
            f"path={item.get('path')}"
        )
    if data["support_warnings"]:
        lines.append("support_warnings:")
        for item in data["support_warnings"]:
            lines.append(f"- {item['code']}: {item['message']}")
    return "\n".join(lines)


def format_html_snapshot(snapshot):
    data = snapshot.to_dict()
    preflight = data.get("preflight") or {}
    settings = preflight.get("settings") or {}
    curation = data.get("curation_report") or {}
    validation = data.get("operational_validation") or {}
    summary = curation.get("executive_summary") or {}
    source_rows = "\n".join(
        html_table_row(
            source.get("source_key"),
            source.get("posture"),
            source.get("runs"),
            source.get("failed"),
            source.get("decision_records"),
            source.get("pending_review"),
            format_context_narrative_summary(source.get("context_narrative")),
        )
        for source in curation.get("source_summaries") or []
    )
    if not source_rows:
        source_rows = html_table_row("none", "", 0, 0, 0, 0, "")
    policy_rows = "\n".join(
        html_table_row(
            insight.get("source_key"),
            insight.get("severity"),
            insight.get("signal"),
            insight.get("review_decision_count"),
            insight.get("release_rate_pct"),
            insight.get("reject_rate_pct"),
            format_policy_score_summary(insight.get("score_summary")),
            format_graph_evidence_summary(insight.get("graph_evidence")),
            format_context_quality_summary(insight.get("context_quality")),
            format_context_narrative_summary(insight.get("context_narrative")),
            format_reason_entries(insight.get("top_quarantine_reasons")),
            format_reason_entries(insight.get("top_reasons")),
        )
        for insight in curation.get("policy_insights") or []
    )
    if not policy_rows:
        policy_rows = html_table_row("none", "", "", 0, 0, 0, "", "", "", "", "", "")
    validation_rows = "\n".join(
        html_table_row(
            item.get("code"),
            item.get("status"),
            item.get("message"),
        )
        for item in validation.get("checks") or []
    )
    if not validation_rows:
        validation_rows = html_table_row("none", "", "")
    evidence_rows = "\n".join(
        html_table_row(
            item.get("name"),
            str(item.get("exists", False)).lower(),
            item.get("kind") or item.get("expected_kind"),
            item.get("size_bytes", 0),
            item.get("path"),
        )
        for item in data.get("evidence_inventory") or []
    )
    warning_items = "\n".join(
        "<li><strong>{}</strong>: {}</li>".format(
            escape(item.get("code")),
            escape(item.get("message")),
        )
        for item in data.get("support_warnings") or []
    )
    if not warning_items:
        warning_items = "<li>none</li>"

    return """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>NarrowCTI support diagnostics</title>
  <style>
    body {{ font-family: Arial, sans-serif; margin: 24px; color: #202124; }}
    h1, h2 {{ margin: 0 0 12px; }}
    section {{ margin-top: 24px; }}
    table {{ border-collapse: collapse; width: 100%; }}
    th, td {{ border: 1px solid #d8dee4; padding: 6px 8px; text-align: left; }}
    th {{ background: #f6f8fa; }}
    code {{ background: #f6f8fa; padding: 1px 4px; }}
  </style>
</head>
<body>
  <h1>NarrowCTI support diagnostics</h1>
  <section>
    <h2>Snapshot</h2>
    <p><strong>schema:</strong> <code>{schema}</code></p>
    <p><strong>generated_at:</strong> <code>{generated_at}</code></p>
    <p><strong>redaction_profile:</strong> <code>{redaction_profile}</code></p>
    <p><strong>curation_report_profile:</strong> <code>{curation_report_profile}</code></p>
    <p><strong>curation_report_policy:</strong> <code>{curation_report_policy}</code></p>
    <p><strong>preflight_ok:</strong> <code>{preflight_ok}</code></p>
    <p><strong>ingestion_mode:</strong> <code>{ingestion_mode}</code></p>
    <p><strong>enabled_sources:</strong> <code>{enabled_sources}</code></p>
    <p><strong>license_edition:</strong> <code>{license_edition}</code></p>
  </section>
  <section>
    <h2>Curation Summary</h2>
    <table>
      <tr><th>runs</th><th>decision records</th><th>reviewed</th><th>accepted</th><th>filtered</th><th>errors</th><th>pending review</th></tr>
      <tr><td>{runs}</td><td>{decision_records}</td><td>{reviewed}</td><td>{accepted}</td><td>{filtered}</td><td>{errors}</td><td>{pending_review}</td></tr>
    </table>
  </section>
  <section>
    <h2>Graph Readiness</h2>
    <table>
      <tr><th>candidates</th><th>accepted</th><th>held</th><th>lookup matches</th><th>would-create objects</th><th>would-create relationships</th></tr>
      <tr><td>{graph_candidates}</td><td>{graph_accepted}</td><td>{graph_held}</td><td>{lookup_matches}</td><td>{would_create_objects}</td><td>{would_create_relationships}</td></tr>
    </table>
  </section>
  <section>
    <h2>Source Posture</h2>
    <table>
      <tr><th>source</th><th>posture</th><th>runs</th><th>failed</th><th>decision records</th><th>pending review</th><th>context narrative</th></tr>
      {source_rows}
    </table>
  </section>
  <section>
    <h2>Policy Insights</h2>
    <table>
      <tr><th>source</th><th>severity</th><th>signal</th><th>review decisions</th><th>release rate</th><th>reject rate</th><th>scores</th><th>graph evidence</th><th>context quality</th><th>context narrative</th><th>quarantine reasons</th><th>top reasons</th></tr>
      {policy_rows}
    </table>
  </section>
  <section>
    <h2>Operational Validation</h2>
    <p><strong>overall_status:</strong> <code>{validation_status}</code></p>
    <table>
      <tr><th>check</th><th>status</th><th>message</th></tr>
      {validation_rows}
    </table>
  </section>
  <section>
    <h2>Evidence Inventory</h2>
    <table>
      <tr><th>name</th><th>exists</th><th>kind</th><th>size bytes</th><th>path</th></tr>
      {evidence_rows}
    </table>
  </section>
  <section>
    <h2>Support Warnings</h2>
    <ul>
      {warning_items}
    </ul>
  </section>
</body>
</html>""".format(
        schema=escape(data.get("schema_version")),
        generated_at=escape(data.get("generated_at")),
        redaction_profile=escape(data.get("redaction_profile")),
        curation_report_profile=escape(curation.get("redaction_profile")),
        curation_report_policy=escape(
            format_redaction_policy(curation.get("redaction_policy"))
        ),
        preflight_ok=escape(str(preflight.get("ok", False)).lower()),
        ingestion_mode=escape(preflight.get("ingestion_mode")),
        enabled_sources=escape(",".join(preflight.get("enabled_sources") or [])),
        license_edition=escape(settings.get("license_edition", "evaluation")),
        runs=escape(summary.get("run_count", 0)),
        decision_records=escape(summary.get("decision_record_count", 0)),
        reviewed=escape(summary.get("reviewed_count", 0)),
        accepted=escape(summary.get("accepted_count", 0)),
        filtered=escape(summary.get("filtered_count", 0)),
        errors=escape(summary.get("error_count", 0)),
        pending_review=escape(summary.get("pending_review_count", 0)),
        graph_candidates=escape(summary.get("graph_candidate_count", 0)),
        graph_accepted=escape(summary.get("graph_accepted_count", 0)),
        graph_held=escape(summary.get("graph_held_count", 0)),
        lookup_matches=escape(summary.get("graph_lookup_match_count", 0)),
        would_create_objects=escape(summary.get("graph_would_create_object_count", 0)),
        would_create_relationships=escape(
            summary.get("graph_would_create_relationship_count", 0)
        ),
        source_rows=source_rows,
        policy_rows=policy_rows,
        validation_status=escape(validation.get("overall_status", "")),
        validation_rows=validation_rows,
        evidence_rows=evidence_rows,
        warning_items=warning_items,
    )


def html_table_row(*values):
    return "<tr>{}</tr>".format(
        "".join(f"<td>{escape(value)}</td>" for value in values)
    )


def escape(value):
    return html.escape("" if value is None else str(value), quote=True)


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
        help="Optional JSON file with manual v0.8 operational validation evidence.",
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
    )
    bundle_result = None
    if args.bundle_file:
        try:
            bundle_result = write_support_bundle(snapshot, args.bundle_file)
        except ValueError as exc:
            raise SystemExit(str(exc))
    html_result = None
    if args.html_file:
        try:
            html_result = write_html_snapshot(snapshot, args.html_file)
        except ValueError as exc:
            raise SystemExit(str(exc))
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
