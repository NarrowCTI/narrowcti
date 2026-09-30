"""Allowlisted projections of operational reports for the Community Web."""

from __future__ import annotations

from collections.abc import Mapping


_VALID_SEVERITIES = frozenset({"error", "warning", "info"})
_VALID_VALIDATION_STATUSES = frozenset({"fail", "needs-evidence", "warn", "pass"})
_VALID_PREFLIGHT_MODES = frozenset({"direct", "misp-collector", "hybrid"})
_VALID_DEDUP_MODES = frozenset({"off", "source", "artifact", "hybrid"})
_VALID_GRAPH_MODES = frozenset({"audit", "dry-run", "export"})


def project_web_preflight(report) -> dict:
    """Project safe current-state fields; never expose settings, paths, or messages."""

    if report is None:
        return {"status": "unavailable", "issues": [], "sources": []}
    data = report.to_dict()
    settings = data.get("settings") if isinstance(data.get("settings"), Mapping) else {}
    issues = []
    raw_issues = data.get("issues")
    raw_issues = raw_issues if isinstance(raw_issues, (list, tuple)) else ()
    for issue in raw_issues[:50]:
        if not isinstance(issue, Mapping):
            continue
        severity = issue.get("severity")
        code = issue.get("code")
        if severity not in _VALID_SEVERITIES or not isinstance(code, str):
            continue
        issues.append({"severity": severity, "code": code[:80]})
    source_controls = data.get("source_controls")
    source_controls = source_controls if isinstance(source_controls, Mapping) else {}
    sources = []
    raw_sources = data.get("enabled_sources")
    raw_sources = raw_sources if isinstance(raw_sources, (list, tuple)) else ()
    for source in raw_sources[:20]:
        if not isinstance(source, str):
            continue
        controls = source_controls.get(source)
        controls = controls if isinstance(controls, Mapping) else {}
        sources.append({
            "name": source[:32],
            "dry_run": controls.get("dry_run") if isinstance(controls.get("dry_run"), bool) else None,
        })
    tls_value = settings.get("misp_verify_tls")
    return {
        "status": "ready" if data.get("ok") is True else "attention" if data.get("ok") is False else "unavailable",
        "ingestion_mode": data.get("ingestion_mode") if data.get("ingestion_mode") in _VALID_PREFLIGHT_MODES else "unknown",
        "sources": sources,
        "dedup_mode": settings.get("dedup_mode") if settings.get("dedup_mode") in _VALID_DEDUP_MODES else "unknown",
        "graph_export_mode": settings.get("graph_export_mode") if settings.get("graph_export_mode") in _VALID_GRAPH_MODES else "unknown",
        "misp_tls": tls_value if isinstance(tls_value, bool) else None,
        "issues": issues,
    }


def project_web_operational_validation(report) -> dict:
    """Keep the contract's status while stripping free-text and evidence payloads."""

    if report is None:
        return {"status": "unavailable", "checks": [], "counts": {}}
    data = report.to_dict()
    checks = []
    raw_checks = data.get("checks")
    raw_checks = raw_checks if isinstance(raw_checks, (list, tuple)) else ()
    for check in raw_checks[:50]:
        if not isinstance(check, Mapping):
            continue
        code = check.get("code")
        status = check.get("status")
        if isinstance(code, str) and status in _VALID_VALIDATION_STATUSES:
            checks.append({"code": code[:80], "status": status})
    raw_counts = data.get("counts")
    counts = {
        status: raw_counts.get(status, 0)
        for status in _VALID_VALIDATION_STATUSES
        if isinstance(raw_counts, Mapping)
        and isinstance(raw_counts.get(status), int)
        and 0 <= raw_counts[status] <= 2_147_483_647
    }
    return {
        "status": data.get("overall_status") if data.get("overall_status") in _VALID_VALIDATION_STATUSES else "unavailable",
        "schema_version": data.get("schema_version", "")[:64] if isinstance(data.get("schema_version"), str) else "",
        "release": data.get("release", "")[:32] if isinstance(data.get("release"), str) else "",
        "checks": checks,
        "counts": counts,
    }


__all__ = ["project_web_preflight", "project_web_operational_validation"]
