"""Canonical, bounded current-state snapshot contract for Community Web."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import re

from narrowcti.application.assurance.operational_validation import (
    build_operational_validation_report,
)
from narrowcti.application.reporting.decisions import build_decision_audit_report
from narrowcti.application.reporting.web_assurance import (
    project_web_operational_validation,
    project_web_preflight,
)


SNAPSHOT_SCHEMA = "narrowcti.operational-state/v1"
MAX_SNAPSHOT_AGE = timedelta(minutes=15)
MAX_FUTURE_SKEW = timedelta(minutes=5)
_VALID_SEVERITIES = frozenset({"error", "warning", "info"})
_VALID_VALIDATION_STATUSES = frozenset({"fail", "needs-evidence", "warn", "pass"})
_SAFE_MODE_VALUES = {
    "ingestion_mode": frozenset({"direct", "misp-collector", "hybrid"}),
    "dedup_mode": frozenset({"off", "source", "artifact", "hybrid"}),
    "graph_export_mode": frozenset({"audit", "dry-run", "export"}),
}
_SAFE_SOURCE = re.compile(r"^[a-z0-9][a-z0-9:_-]{0,31}$")


@dataclass(frozen=True)
class OperationalStateSnapshot:
    """Safe Web read model captured by the authoritative Gateway/Ops process."""

    captured_at: str
    preflight: Mapping
    validation: Mapping
    required_sources: tuple[str, ...]

    def to_dict(self):
        return {
            "schema": SNAPSHOT_SCHEMA,
            "captured_at": self.captured_at,
            "preflight": dict(self.preflight),
            "validation": dict(self.validation),
            "required_sources": list(self.required_sources),
        }


def build_operational_state_snapshot(
    preflight_report,
    decision_records,
    *,
    required_sources,
    captured_at: str | None = None,
) -> OperationalStateSnapshot:
    """Build reports from raw bounded DecisionRecords, then apply Web projections."""

    required_sources = tuple(required_sources)
    audit_report = build_decision_audit_report(decision_records)
    validation_report = build_operational_validation_report(
        preflight_report,
        audit_report,
        required_sources=tuple(required_sources),
    )
    timestamp = captured_at or datetime.now(timezone.utc).isoformat(timespec="seconds")
    safe_required_sources = tuple(
        str(source).strip().lower()[:32]
        for source in required_sources
        if isinstance(source, str) and _SAFE_SOURCE.fullmatch(source.strip().lower())
    )[:20]
    return OperationalStateSnapshot(
        captured_at=timestamp,
        preflight=project_web_preflight(preflight_report),
        validation=project_web_operational_validation(validation_report),
        required_sources=safe_required_sources,
    )


def load_operational_state_snapshot(value: object) -> OperationalStateSnapshot | None:
    """Validate the bounded JSON snapshot shape; invalid data is unavailable."""

    if not isinstance(value, Mapping) or value.get("schema") != SNAPSHOT_SCHEMA:
        return None
    captured_at = value.get("captured_at")
    preflight = value.get("preflight")
    validation = value.get("validation")
    if not isinstance(captured_at, str) or len(captured_at) > 64:
        return None
    try:
        timestamp = datetime.fromisoformat(captured_at.replace("Z", "+00:00"))
    except ValueError:
        return None
    if timestamp.tzinfo is None:
        return None
    now = datetime.now(timezone.utc)
    captured_utc = timestamp.astimezone(timezone.utc)
    if captured_utc > now + MAX_FUTURE_SKEW or now - captured_utc > MAX_SNAPSHOT_AGE:
        return None
    if not isinstance(preflight, Mapping) or not isinstance(validation, Mapping):
        return None
    preflight_status = preflight.get("status")
    if preflight_status not in {"ready", "attention", "unavailable"}:
        return None
    source_rows = preflight.get("sources")
    issue_rows = preflight.get("issues")
    if not isinstance(source_rows, (list, tuple)) or not isinstance(issue_rows, (list, tuple)):
        return None
    safe_preflight = {
        "status": preflight_status,
        "ingestion_mode": preflight.get("ingestion_mode") if preflight.get("ingestion_mode") in _SAFE_MODE_VALUES["ingestion_mode"] else "unknown",
        "dedup_mode": preflight.get("dedup_mode") if preflight.get("dedup_mode") in _SAFE_MODE_VALUES["dedup_mode"] else "unknown",
        "graph_export_mode": preflight.get("graph_export_mode") if preflight.get("graph_export_mode") in _SAFE_MODE_VALUES["graph_export_mode"] else "unknown",
        "misp_tls": preflight.get("misp_tls") if isinstance(preflight.get("misp_tls"), bool) else None,
        "sources": [
            {
                "name": str(row.get("name", ""))[:32],
                "dry_run": row.get("dry_run") if isinstance(row.get("dry_run"), bool) else None,
            }
            for row in source_rows[:20]
            if isinstance(row, Mapping)
        ],
        "issues": [
            {"severity": row.get("severity"), "code": str(row.get("code", ""))[:80]}
            for row in issue_rows[:50]
            if isinstance(row, Mapping)
            and row.get("severity") in _VALID_SEVERITIES
            and isinstance(row.get("code"), str)
        ],
    }
    validation_status = validation.get("status")
    validation_checks = validation.get("checks")
    validation_counts = validation.get("counts")
    if (
        validation_status not in _VALID_VALIDATION_STATUSES
        or not isinstance(validation_checks, (list, tuple))
        or not isinstance(validation_counts, Mapping)
    ):
        return None
    safe_validation = {
        "status": validation_status,
        "schema_version": str(validation.get("schema_version", ""))[:64],
        "release": str(validation.get("release", ""))[:32],
        "checks": [
            {"code": str(item.get("code", ""))[:80], "status": item.get("status")}
            for item in validation_checks[:50]
            if isinstance(item, Mapping)
            and isinstance(item.get("code"), str)
            and item.get("status") in _VALID_VALIDATION_STATUSES
        ],
        "counts": {
            key: count
            for key, count in validation_counts.items()
            if key in _VALID_VALIDATION_STATUSES
            and isinstance(count, int)
            and 0 <= count <= 2_147_483_647
        },
    }
    required_sources = value.get("required_sources")
    if not isinstance(required_sources, (list, tuple)) or len(required_sources) > 20:
        return None
    safe_sources = tuple(
        source.strip().lower()[:32]
        for source in required_sources
        if isinstance(source, str) and _SAFE_SOURCE.fullmatch(source.strip().lower())
    )
    if len(safe_sources) != len(required_sources):
        return None
    return OperationalStateSnapshot(
        captured_at=captured_at,
        preflight=safe_preflight,
        validation=safe_validation,
        required_sources=safe_sources,
    )


__all__ = [
    "MAX_FUTURE_SKEW",
    "MAX_SNAPSHOT_AGE",
    "OperationalStateSnapshot",
    "SNAPSHOT_SCHEMA",
    "build_operational_state_snapshot",
    "load_operational_state_snapshot",
]
