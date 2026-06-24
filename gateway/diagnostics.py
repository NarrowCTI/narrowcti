import argparse
import copy
import json
import os
from dataclasses import dataclass
from datetime import datetime, timezone

from core.decision_audit import utc_now
from gateway.curation_report import build_curation_report_from_files
from gateway.preflight import build_preflight_report
from gateway.settings import load_settings


SCHEMA_VERSION = "support-diagnostics/v0.8"
REDACTION_PROFILES = ("none", "support")


@dataclass(frozen=True)
class SupportDiagnosticSnapshot:
    schema_version: str
    generated_at: str
    redaction_profile: str
    preflight: dict
    evidence_inventory: list
    curation_report: dict
    support_warnings: list

    def to_dict(self):
        return {
            "schema_version": self.schema_version,
            "generated_at": self.generated_at,
            "redaction_profile": self.redaction_profile,
            "preflight": self.preflight,
            "evidence_inventory": list(self.evidence_inventory),
            "curation_report": self.curation_report,
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
):
    preflight = build_preflight_report(settings, env=env)
    evidence = collect_evidence_inventory(preflight)
    curation = build_curation_report_from_files(
        summary_file=summary_file or settings.run_summary_file,
        decision_paths=decision_paths or [settings.decision_audit_dir],
        quarantine_file=quarantine_file or settings.quarantine_repository_file,
        release_audit_file=release_audit_file or settings.release_audit_file,
        limit=limit,
    )
    snapshot = SupportDiagnosticSnapshot(
        schema_version=SCHEMA_VERSION,
        generated_at=generated_at or utc_now(),
        redaction_profile=normalize_redaction_profile(redaction_profile),
        preflight=preflight.to_dict(),
        evidence_inventory=evidence,
        curation_report=curation.to_dict(),
        support_warnings=build_support_warnings(preflight, evidence, curation),
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
        support_warnings=data.get("support_warnings") or [],
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


def build_support_warnings(preflight_report, evidence_inventory, curation_report):
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
    summary = data["curation_report"]["executive_summary"]
    lines = [
        "NarrowCTI support diagnostics",
        f"schema_version={data['schema_version']}",
        f"generated_at={data['generated_at']}",
        f"redaction_profile={data.get('redaction_profile', 'none')}",
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
    )
    if args.json:
        print(json.dumps(snapshot.to_dict(), sort_keys=True))
    else:
        print(format_text_snapshot(snapshot))


if __name__ == "__main__":
    main()
