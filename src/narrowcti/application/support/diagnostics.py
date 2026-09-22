"""Provider-neutral support diagnostics interpretation and redaction."""

from __future__ import annotations

import copy
import html
from dataclasses import dataclass
from datetime import datetime, timezone

from narrowcti.application.reporting.curation import (
    format_audit_target_summary, format_context_narrative_summary,
    format_context_quality_summary, format_graph_evidence_summary,
    format_mapping_counts, format_policy_score_summary, format_reason_entries,
    format_redaction_policy, format_text_values, report_to_dict,
)

SCHEMA_VERSION = "support-diagnostics/v0.8"
REDACTION_PROFILES = ("none", "support", "external")

def _utc_now():
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


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
    if any(
        item.get("code") == "complete-opencti-relationship-coverage"
        for item in recommendations
    ):
        warnings.append(
            support_warning(
                "curation-graph-validation-incomplete",
                "Curation report shows incomplete OpenCTI Diamond or Kill Chain relationship coverage.",
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
                    "Current operational validation has failing checks; graph promotion must remain blocked.",
                )
            )
        elif status == "needs-evidence":
            warnings.append(
                support_warning(
                    "operational-validation-needs-evidence",
                    "Current operational validation still needs evidence: "
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
    relationship_audit = (
        (curation.get("graph_validation") or {}).get("relationship_audit") or {}
    )
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
        "distribution_model="
        f"{preflight.get('settings', {}).get('distribution_model', 'open_source')}",
        "open_source="
        f"{str(preflight.get('settings', {}).get('open_source', True)).lower()}",
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
    ]
    if relationship_audit.get("available"):
        lines.append("graph_validation:")
        lines.append(
            "- "
            f"opencti_relationship_audit found="
            f"{str(relationship_audit.get('found', False)).lower()} "
            f"target={format_audit_target_summary(relationship_audit.get('target'))} "
            f"relationships={relationship_audit.get('relationship_count', 0)} "
            f"coverage={relationship_audit.get('coverage_status', '')} "
            f"present={format_text_values(relationship_audit.get('present_quadrants'))} "
            f"missing={format_text_values(relationship_audit.get('missing_quadrants'))} "
            f"quadrants="
            f"{format_mapping_counts(relationship_audit.get('diamond_quadrant_counts'))} "
            f"kill_chain_present="
            f"{str(relationship_audit.get('kill_chain_present', False)).lower()}"
        )
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
    lines.append("evidence_inventory:")
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
    relationship_audit = (
        (curation.get("graph_validation") or {}).get("relationship_audit") or {}
    )
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
    graph_validation_rows = html_table_row(
        "not-collected",
        "",
        0,
        "none",
        "none",
        "none",
        "false",
    )
    if relationship_audit.get("available"):
        graph_validation_rows = html_table_row(
            "found" if relationship_audit.get("found") else "missing",
            format_audit_target_summary(relationship_audit.get("target")),
            relationship_audit.get("relationship_count", 0),
            relationship_audit.get("coverage_status", ""),
            format_text_values(relationship_audit.get("present_quadrants")),
            format_text_values(relationship_audit.get("missing_quadrants")),
            str(relationship_audit.get("kill_chain_present", False)).lower(),
        )
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
    <p><strong>distribution_model:</strong> <code>{distribution_model}</code></p>
    <p><strong>open_source:</strong> <code>{open_source}</code></p>
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
    <h2>Graph Validation</h2>
    <table>
      <tr><th>status</th><th>target</th><th>relationships</th><th>coverage</th><th>present quadrants</th><th>missing quadrants</th><th>kill chain present</th></tr>
      {graph_validation_rows}
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
        distribution_model=escape(settings.get("distribution_model", "open_source")),
        open_source=escape(str(settings.get("open_source", True)).lower()),
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
        graph_validation_rows=graph_validation_rows,
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

def build_support_diagnostics(
    preflight_report, evidence_inventory, curation_report,
    operational_validation_report=None, generated_at="", redaction_profile="none",
):
    profile = normalize_redaction_profile(redaction_profile)
    preflight_data = preflight_report.to_dict() if hasattr(preflight_report, "to_dict") else dict(preflight_report or {})
    curation_data = report_to_dict(curation_report, redaction_profile=profile) if hasattr(curation_report, "to_dict") else dict(curation_report or {})
    validation_data = (
        operational_validation_report.to_dict()
        if hasattr(operational_validation_report, "to_dict")
        else dict(operational_validation_report or {})
    )
    snapshot = SupportDiagnosticSnapshot(
        schema_version=SCHEMA_VERSION,
        generated_at=generated_at or _utc_now(),
        redaction_profile=profile,
        preflight=preflight_data,
        evidence_inventory=list(evidence_inventory or []),
        curation_report=curation_data,
        operational_validation=validation_data,
        support_warnings=build_support_warnings(
            preflight_report, evidence_inventory or [], curation_report, operational_validation_report,
        ),
    )
    if profile == "none":
        return snapshot
    return snapshot_from_dict(redact_snapshot_dict(snapshot.to_dict()))


__all__ = [

    "SupportDiagnosticSnapshot",
    "normalize_redaction_profile",
    "snapshot_from_dict",
    "build_support_warnings",
    "support_warning",
    "redact_snapshot_dict",
    "collect_sensitive_paths",
    "collect_paths",
    "redact_preflight",
    "redact_evidence_inventory",
    "redact_curation_report",
    "redact_warning_messages",
    "redact_issue_messages",
    "redact_paths",
    "redact_text_fields",
    "should_redact_path_key",
    "redact_text",
    "redact_path",
    "format_text_snapshot",
    "format_html_snapshot",
    "html_table_row",
    "escape",
    "SCHEMA_VERSION", "REDACTION_PROFILES",
]
