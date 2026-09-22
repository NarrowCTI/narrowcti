"""Provider-neutral operational assurance checks and rendering."""

from __future__ import annotations

import html
import json
from dataclasses import dataclass

STATUS_ORDER = {"fail": 0, "needs-evidence": 1, "warn": 2, "pass": 3}
DECISION_SOURCE_ALIASES = {
    "otx": ("otx", "alienvault:otx"),
    "misp": ("misp", "misp:misp"),
}


@dataclass(frozen=True)
class ValidationCheck:
    code: str
    status: str
    message: str
    evidence: dict

    def to_dict(self):
        return {
            "code": self.code,
            "status": self.status,
            "message": self.message,
            "evidence": dict(self.evidence),
        }

@dataclass(frozen=True)
class OperationalValidationReport:
    schema_version: str
    release: str
    overall_status: str
    checks: tuple[ValidationCheck, ...]

    def to_dict(self):
        return {
            "schema_version": self.schema_version,
            "release": self.release,
            "overall_status": self.overall_status,
            "checks": [check.to_dict() for check in self.checks],
            "counts": status_counts(self.checks),
        }

def build_operational_validation_report(
    preflight_report,
    decision_report,
    full_validation_passed=False,
    opencti_ui_no_duplicate=False,
    opencti_ui_duplicate_found=False,
    resource_posture_ok=False,
    resource_posture_unhealthy=False,
    resource_posture_evidence=None,
    relationship_audit_evidence=None,
    required_sources=("otx", "misp"),
):
    preflight = preflight_report.to_dict()
    decisions = decision_report.to_dict()
    graph = decisions.get("graph_export") or {}
    checks = [
        full_validation_check(full_validation_passed),
        preflight_graph_controls_check(preflight),
        source_dry_run_check(preflight, decisions, required_sources),
        canonical_attack_match_check(graph),
        lookup_metadata_check(graph),
        lookup_aggregation_check(graph),
        held_relationship_validation_check(graph),
        duplicate_attack_pattern_check(
            opencti_ui_no_duplicate,
            opencti_ui_duplicate_found,
        ),
        relationship_audit_check(relationship_audit_evidence),
        resource_posture_check(
            resource_posture_ok,
            resource_posture_unhealthy,
            resource_posture_evidence=resource_posture_evidence,
        ),
    ]
    return OperationalValidationReport(
        schema_version="operational-validation/v1.0",
        release="v1.0.0",
        overall_status=overall_status(checks),
        checks=tuple(checks),
    )

def full_validation_check(full_validation_passed):
    if full_validation_passed:
        return check(
            "full-validation",
            "pass",
            "Full repository validation was reported as passed.",
            {"command": ".\\scripts\\validate-release.ps1"},
        )
    return check(
        "full-validation",
        "needs-evidence",
        "Run .\\scripts\\validate-release.ps1 and record this check as passed after it succeeds.",
        {"command": ".\\scripts\\validate-release.ps1"},
    )

def preflight_graph_controls_check(preflight):
    settings = preflight.get("settings") or {}
    issues = preflight.get("issues") or []
    error_codes = sorted(
        issue.get("code")
        for issue in issues
        if issue.get("severity") == "error"
    )
    graph_export_mode = settings.get("graph_export_mode")
    graph_state = settings.get("graph_dedup_state_file", "")
    opencti_graph_lookup = bool(settings.get("opencti_graph_lookup", False))
    safe_mode = graph_export_mode in ("audit", "dry-run")
    evidence = {
        "preflight_ok": bool(preflight.get("ok", False)),
        "graph_export_mode": graph_export_mode,
        "graph_dedup_state_file": graph_state,
        "opencti_graph_lookup": opencti_graph_lookup,
        "error_codes": error_codes,
    }
    if not preflight.get("ok", False):
        return check(
            "preflight-graph-controls",
            "fail",
            "Preflight has blocking errors; graph validation should not proceed.",
            evidence,
        )
    if safe_mode and graph_state and opencti_graph_lookup:
        return check(
            "preflight-graph-controls",
            "pass",
            "Preflight reports safe graph controls and read-only OpenCTI graph lookup.",
            evidence,
        )
    return check(
        "preflight-graph-controls",
        "warn",
        "Preflight is not blocking, but graph validation controls are incomplete.",
        evidence,
    )

def source_dry_run_check(preflight, decisions, required_sources):
    source_controls = preflight.get("source_controls") or {}
    decision_sources = decisions.get("sources") or {}
    per_source = {}
    missing = []
    unsafe = []
    for source in required_sources or ():
        controls = source_controls.get(source) or {}
        decision_source_keys = decision_keys_for_source(source)
        dry_run = bool(controls.get("dry_run", False))
        records = sum(
            int((decision_sources.get(key) or {}).get("records", 0) or 0)
            for key in decision_source_keys
        )
        per_source[source] = {
            "dry_run": dry_run,
            "decision_records": records,
            "decision_source_keys": list(decision_source_keys),
        }
        if not dry_run:
            unsafe.append(source)
        if records <= 0:
            missing.append(source)
    evidence = {
        "required_sources": list(required_sources or ()),
        "sources": per_source,
    }
    if unsafe:
        return check(
            "bounded-source-dry-runs",
            "fail",
            "One or more required sources are not configured for dry-run validation.",
            {**evidence, "unsafe_sources": unsafe},
        )
    if missing:
        return check(
            "bounded-source-dry-runs",
            "needs-evidence",
            "Bounded dry-run decision evidence is still missing for one or more required sources.",
            {**evidence, "missing_sources": missing},
        )
    return check(
        "bounded-source-dry-runs",
        "pass",
        "Required sources have dry-run controls and decision audit evidence.",
        evidence,
    )

def decision_keys_for_source(source):
    source = str(source or "").strip()
    return DECISION_SOURCE_ALIASES.get(source, (source,))

def canonical_attack_match_check(graph):
    object_counts = graph.get("lookup_match_object_counts") or {}
    match_types = graph.get("lookup_match_type_counts") or {}
    attack_matches = int(object_counts.get("attack-pattern", 0) or 0)
    mitre_matches = int(match_types.get("mitre_attack_id", 0) or 0)
    evidence = {
        "lookup_match_count": graph.get("lookup_match_count", 0),
        "attack_pattern_matches": attack_matches,
        "mitre_attack_id_matches": mitre_matches,
    }
    if attack_matches > 0 and mitre_matches > 0:
        return check(
            "canonical-attack-match",
            "pass",
            "Decision evidence includes a canonical ATT&CK attack-pattern lookup match.",
            evidence,
        )
    return check(
        "canonical-attack-match",
        "needs-evidence",
        "Capture an OTX or MISP dry-run with an ATT&CK candidate matched to a canonical OpenCTI attack-pattern.",
        evidence,
    )

def lookup_metadata_check(graph):
    lookup_matches = int(graph.get("lookup_match_count", 0) or 0)
    evidence = {
        "graph_record_count": graph.get("record_count", 0),
        "lookup_match_count": lookup_matches,
    }
    if lookup_matches > 0:
        return check(
            "lookup-metadata",
            "pass",
            "Decision metadata contains bounded OpenCTI graph lookup match evidence.",
            evidence,
        )
    return check(
        "lookup-metadata",
        "needs-evidence",
        "Decision metadata does not yet show OpenCTI graph lookup matches.",
        evidence,
    )

def lookup_aggregation_check(graph):
    object_counts = graph.get("lookup_match_object_counts") or {}
    match_types = graph.get("lookup_match_type_counts") or {}
    evidence = {
        "lookup_match_object_counts": object_counts,
        "lookup_match_type_counts": match_types,
    }
    if object_counts and match_types:
        return check(
            "lookup-aggregation",
            "pass",
            "Decision report aggregates lookup evidence by object type and match type.",
            evidence,
        )
    return check(
        "lookup-aggregation",
        "needs-evidence",
        "Decision report lookup counters are empty; capture lookup evidence before closing v0.8 validation.",
        evidence,
    )

def held_relationship_validation_check(graph):
    held_reasons = graph.get("held_reasons") or {}
    validation_count = int(
        held_reasons.get("relationship_requires_opencti_validation", 0) or 0
    )
    evidence = {
        "held_reasons": dict(held_reasons),
        "relationship_requires_opencti_validation": validation_count,
    }
    if validation_count > 0:
        return check(
            "held-opencti-relationship-validation",
            "needs-evidence",
            "Decision evidence contains OpenCTI relationship candidates held until source semantics and OpenCTI rendering are validated.",
            evidence,
        )
    return check(
        "held-opencti-relationship-validation",
        "pass",
        "Decision evidence has no OpenCTI relationship candidates held for validation.",
        evidence,
    )

def duplicate_attack_pattern_check(no_duplicate, duplicate_found):
    evidence = {
        "opencti_ui_no_duplicate": bool(no_duplicate),
        "opencti_ui_duplicate_found": bool(duplicate_found),
    }
    if duplicate_found:
        return check(
            "opencti-no-duplicate-attack-pattern",
            "fail",
            "OpenCTI UI validation indicates a duplicate ATT&CK attack-pattern was created.",
            evidence,
        )
    if no_duplicate:
        return check(
            "opencti-no-duplicate-attack-pattern",
            "pass",
            "OpenCTI UI validation confirms no duplicate ATT&CK attack-pattern was created.",
            evidence,
        )
    return check(
        "opencti-no-duplicate-attack-pattern",
        "needs-evidence",
        "OpenCTI UI duplicate check has not been recorded yet.",
        evidence,
    )

def relationship_audit_check(audit_evidence):
    audit_evidence = audit_evidence if isinstance(audit_evidence, dict) else {}
    quadrant_counts = audit_evidence.get("diamond_quadrant_counts") or {}
    relationship_count = int(audit_evidence.get("relationship_count", 0) or 0)
    kill_chain_count = len(audit_evidence.get("kill_chain_attack_patterns") or [])
    coverage = audit_evidence.get("coverage") or {}
    diamond_context_count = sum(
        int(quadrant_counts.get(quadrant, 0) or 0)
        for quadrant in (
            "adversary",
            "capability",
            "infrastructure",
            "victimology",
        )
    )
    evidence = {
        "found": bool(audit_evidence.get("found", False)),
        "target": audit_evidence.get("target") or {},
        "relationship_count": relationship_count,
        "outbound_count": int(audit_evidence.get("outbound_count", 0) or 0),
        "inbound_count": int(audit_evidence.get("inbound_count", 0) or 0),
        "diamond_quadrant_counts": dict(quadrant_counts),
        "kill_chain_attack_pattern_count": kill_chain_count,
        "coverage": dict(coverage),
    }
    if not audit_evidence:
        return check(
            "opencti-relationship-audit",
            "needs-evidence",
            "Run the OpenCTI relationship audit for at least one promoted graph object.",
            evidence,
        )
    if not audit_evidence.get("found", False):
        return check(
            "opencti-relationship-audit",
            "fail",
            "OpenCTI relationship audit did not find the requested graph object.",
            evidence,
        )
    if relationship_count <= 0:
        return check(
            "opencti-relationship-audit",
            "fail",
            "OpenCTI relationship audit found the object but no direct relationships.",
            evidence,
        )
    if coverage.get("status") == "needs-evidence":
        return check(
            "opencti-relationship-audit",
            "needs-evidence",
            "OpenCTI relationship audit found the object, but expected Diamond or Kill Chain coverage is still incomplete.",
            evidence,
        )
    if coverage.get("status") == "pass":
        return check(
            "opencti-relationship-audit",
            "pass",
            "OpenCTI relationship audit satisfies the configured Diamond and Kill Chain coverage requirements.",
            evidence,
        )
    if diamond_context_count > 0 or kill_chain_count > 0:
        return check(
            "opencti-relationship-audit",
            "pass",
            "OpenCTI relationship audit confirms direct Diamond or Kill Chain graph context.",
            evidence,
        )
    return check(
        "opencti-relationship-audit",
        "needs-evidence",
        "Relationship audit has direct edges, but not enough Diamond or Kill Chain context yet.",
        evidence,
    )

def resource_posture_check(resource_ok, resource_unhealthy, resource_posture_evidence=None):
    resource_posture_evidence = (
        resource_posture_evidence if isinstance(resource_posture_evidence, dict) else {}
    )
    evidence = {
        "resource_posture_ok": bool(resource_ok),
        "resource_posture_unhealthy": bool(resource_unhealthy),
        "resource_posture": dict(resource_posture_evidence),
    }
    if resource_unhealthy or structured_resource_posture_unhealthy(resource_posture_evidence):
        return check(
            "resource-posture",
            "fail",
            "Local lab resource posture was marked unhealthy after bounded validation.",
            evidence,
        )
    if resource_ok or structured_resource_posture_ok(resource_posture_evidence):
        return check(
            "resource-posture",
            "pass",
            "Local lab resource posture evidence was captured and marked healthy after bounded validation.",
            evidence,
        )
    return check(
        "resource-posture",
        "needs-evidence",
        "Record local lab resource posture after bounded OTX and MISP validation.",
        evidence,
    )

def structured_resource_posture_ok(evidence):
    evidence = evidence if isinstance(evidence, dict) else {}
    status = normalized_status(evidence.get("status"))
    if status in {"ok", "pass", "healthy"}:
        return True
    return all(
        evidence_bool(evidence, key)
        for key in (
            "docker_stats_captured",
            "docker_system_df_captured",
            "containers_healthy",
            "disk_posture_ok",
        )
    )

def structured_resource_posture_unhealthy(evidence):
    evidence = evidence if isinstance(evidence, dict) else {}
    status = normalized_status(evidence.get("status"))
    if status in {"fail", "failed", "unhealthy", "error"}:
        return True
    for key in ("containers_healthy", "disk_posture_ok"):
        if key in evidence and not evidence_bool(evidence, key):
            return True
    return False

def normalized_status(value):
    return str(value or "").strip().lower()

def check(code, status, message, evidence=None):
    return ValidationCheck(
        code=code,
        status=status,
        message=message,
        evidence=evidence or {},
    )

def status_counts(checks):
    counts = {status: 0 for status in STATUS_ORDER}
    for item in checks:
        counts[item.status] = counts.get(item.status, 0) + 1
    return dict(sorted(counts.items()))

def overall_status(checks):
    statuses = [item.status for item in checks]
    if "fail" in statuses:
        return "fail"
    if "needs-evidence" in statuses:
        return "needs-evidence"
    if "warn" in statuses:
        return "warn"
    return "pass"

def format_text_report(report):
    data = report.to_dict()
    lines = [
        "NarrowCTI v1.0 operational validation",
        f"schema_version={data['schema_version']}",
        f"release={data['release']}",
        f"overall_status={data['overall_status']}",
        "counts="
        + ",".join(
            f"{status}:{count}" for status, count in data["counts"].items()
        ),
        "checks:",
    ]
    for item in data["checks"]:
        lines.append(
            "- "
            f"{item['code']} status={item['status']}: "
            f"{item['message']}"
        )
    return "\n".join(lines)

def format_html_report(report):
    data = report.to_dict()
    counts = data["counts"]
    rows = "\n".join(format_html_check_row(item) for item in data["checks"])
    count_items = "\n".join(
        f"<li><strong>{escape_html(status)}</strong>: {count}</li>"
        for status, count in counts.items()
    )
    return "\n".join(
        [
            "<!doctype html>",
            '<html lang="en">',
            "<head>",
            '  <meta charset="utf-8">',
            "  <title>NarrowCTI v1.0 operational validation</title>",
            "  <style>",
            "    body { font-family: Arial, sans-serif; margin: 24px; color: #1f2933; }",
            "    h1 { font-size: 24px; margin-bottom: 8px; }",
            "    table { border-collapse: collapse; width: 100%; margin-top: 16px; }",
            "    th, td { border: 1px solid #d9e2ec; padding: 8px; text-align: left; vertical-align: top; }",
            "    th { background: #f0f4f8; }",
            "    code { white-space: pre-wrap; word-break: break-word; }",
            "  </style>",
            "</head>",
            "<body>",
            "  <h1>NarrowCTI v1.0 operational validation</h1>",
            f"  <p><strong>Schema:</strong> {escape_html(data['schema_version'])}</p>",
            f"  <p><strong>Release:</strong> {escape_html(data['release'])}</p>",
            f"  <p><strong>Overall status:</strong> {escape_html(data['overall_status'])}</p>",
            "  <h2>Status counts</h2>",
            f"  <ul>{count_items}</ul>",
            "  <h2>Checks</h2>",
            "  <table>",
            "    <thead>",
            "      <tr><th>Code</th><th>Status</th><th>Message</th><th>Evidence</th></tr>",
            "    </thead>",
            "    <tbody>",
            rows,
            "    </tbody>",
            "  </table>",
            "</body>",
            "</html>",
        ]
    )

def format_html_check_row(item):
    evidence = json.dumps(item["evidence"], sort_keys=True)
    return (
        "      <tr>"
        f"<td>{escape_html(item['code'])}</td>"
        f"<td>{escape_html(item['status'])}</td>"
        f"<td>{escape_html(item['message'])}</td>"
        f"<td><code>{escape_html(evidence)}</code></td>"
        "</tr>"
    )

def escape_html(value):
    return html.escape(str(value), quote=True)

def render_report(report, output_format="text"):
    output_format = normalize_output_format(output_format)
    if output_format == "json":
        return json.dumps(report.to_dict(), sort_keys=True)
    if output_format == "html":
        return format_html_report(report)
    return format_text_report(report)

def normalize_output_format(value):
    output_format = str(value or "text").strip().lower()
    if output_format not in ("text", "json", "html"):
        raise ValueError("output_format must be one of: text,json,html")
    return output_format

def evidence_bool(evidence, name):
    value = evidence.get(name, False)
    if isinstance(value, bool):
        return value
    return str(value or "").strip().lower() in ("true", "1", "yes")

def parse_sources(value):
    sources = []
    for item in str(value or "").split(","):
        source = item.strip().lower()
        if source:
            sources.append(source)
    return tuple(sources)


__all__ = [
    "STATUS_ORDER",
    "DECISION_SOURCE_ALIASES",
    "ValidationCheck",
    "OperationalValidationReport",
    "build_operational_validation_report",
    "full_validation_check",
    "preflight_graph_controls_check",
    "source_dry_run_check",
    "decision_keys_for_source",
    "canonical_attack_match_check",
    "lookup_metadata_check",
    "lookup_aggregation_check",
    "held_relationship_validation_check",
    "duplicate_attack_pattern_check",
    "relationship_audit_check",
    "resource_posture_check",
    "structured_resource_posture_ok",
    "structured_resource_posture_unhealthy",
    "normalized_status",
    "check",
    "status_counts",
    "overall_status",
    "format_text_report",
    "format_html_report",
    "format_html_check_row",
    "escape_html",
    "render_report",
    "normalize_output_format",
    "evidence_bool",
    "parse_sources",
]
