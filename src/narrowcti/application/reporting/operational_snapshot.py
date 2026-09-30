"""Separate bounded Ops-owned snapshot contracts for read-only Community Web."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import re

from narrowcti.application.reporting.web_assurance import (
    project_web_operational_validation,
    project_web_preflight,
)


PREFLIGHT_SNAPSHOT_SCHEMA = "narrowcti.web-preflight/v1"
VALIDATION_SNAPSHOT_SCHEMA = "narrowcti.web-operational-validation/v1"
MAX_SNAPSHOT_AGE = timedelta(minutes=15)
MAX_FUTURE_SKEW = timedelta(minutes=5)
_VALID_SEVERITIES = frozenset({"error", "warning", "info"})
_VALID_VALIDATION_STATUSES = frozenset({"fail", "needs-evidence", "warn", "pass", "unavailable"})
_SAFE_SOURCE = re.compile(r"^[a-z0-9][a-z0-9:_-]{0,31}$")
_SAFE_MODES = {
    "ingestion_mode": frozenset({"direct", "misp-collector", "hybrid"}),
    "dedup_mode": frozenset({"off", "source", "artifact", "hybrid"}),
    "graph_export_mode": frozenset({"audit", "dry-run", "export"}),
}


def _snapshot_freshness(captured_at: str) -> str | None:
    try:
        timestamp = datetime.fromisoformat(captured_at.replace("Z", "+00:00"))
    except ValueError:
        return None
    if timestamp.tzinfo is None:
        return None
    age = datetime.now(timezone.utc) - timestamp.astimezone(timezone.utc)
    if age < -MAX_FUTURE_SKEW:
        return None
    return "stale" if age > MAX_SNAPSHOT_AGE else "current"


@dataclass(frozen=True)
class WebPreflightSnapshot:
    captured_at: str
    report: Mapping
    freshness: str = "current"

    def to_dict(self):
        return {
            "schema": PREFLIGHT_SNAPSHOT_SCHEMA,
            "captured_at": self.captured_at,
            "report": dict(self.report),
        }

    def to_web_dict(self):
        return {
            **dict(self.report),
            "captured_at": self.captured_at,
            "freshness": self.freshness,
        }


@dataclass(frozen=True)
class WebOperationalValidationSnapshot:
    captured_at: str
    report: Mapping
    required_sources: tuple[str, ...]
    freshness: str = "current"

    def to_dict(self):
        return {
            "schema": VALIDATION_SNAPSHOT_SCHEMA,
            "captured_at": self.captured_at,
            "report": dict(self.report),
            "required_sources": list(self.required_sources),
        }

    def to_web_dict(self):
        return {
            **dict(self.report),
            "captured_at": self.captured_at,
            "freshness": self.freshness,
            "required_sources": self.required_sources,
        }


def build_preflight_snapshot(preflight_report, *, captured_at: str | None = None):
    return WebPreflightSnapshot(
        captured_at=captured_at or datetime.now(timezone.utc).isoformat(timespec="seconds"),
        report=project_web_preflight(preflight_report),
    )


def build_operational_validation_snapshot(
    validation_report,
    *,
    required_sources,
    captured_at: str | None = None,
):
    safe_sources = _safe_sources(required_sources)
    if safe_sources is None:
        raise ValueError("required_sources contains an invalid source key")
    return WebOperationalValidationSnapshot(
        captured_at=captured_at or datetime.now(timezone.utc).isoformat(timespec="seconds"),
        report=project_web_operational_validation(validation_report),
        required_sources=safe_sources,
    )


def _safe_sources(values):
    if not isinstance(values, (tuple, list)) or len(values) > 20:
        return None
    result = []
    for value in values:
        if not isinstance(value, str):
            return None
        source = value.strip().lower()
        if not _SAFE_SOURCE.fullmatch(source):
            return None
        result.append(source)
    return tuple(result)


def _safe_preflight_report(value):
    if not isinstance(value, Mapping) or value.get("status") not in {"ready", "attention", "unavailable"}:
        return None
    if not isinstance(value.get("sources"), (list, tuple)) or not isinstance(value.get("issues"), (list, tuple)):
        return None
    sources = []
    for row in value["sources"][:20]:
        if not isinstance(row, Mapping) or not isinstance(row.get("name"), str):
            return None
        name = row["name"].strip().lower()
        if not _SAFE_SOURCE.fullmatch(name):
            return None
        dry_run = row.get("dry_run")
        sources.append({"name": name, "dry_run": dry_run if isinstance(dry_run, bool) else None})
    issues = []
    for row in value["issues"][:50]:
        if (
            not isinstance(row, Mapping)
            or row.get("severity") not in _VALID_SEVERITIES
            or not isinstance(row.get("code"), str)
        ):
            return None
        issues.append({"severity": row["severity"], "code": row["code"][:80]})
    return {
        "status": value["status"],
        "ingestion_mode": value.get("ingestion_mode") if value.get("ingestion_mode") in _SAFE_MODES["ingestion_mode"] else "unknown",
        "dedup_mode": value.get("dedup_mode") if value.get("dedup_mode") in _SAFE_MODES["dedup_mode"] else "unknown",
        "graph_export_mode": value.get("graph_export_mode") if value.get("graph_export_mode") in _SAFE_MODES["graph_export_mode"] else "unknown",
        "misp_tls": value.get("misp_tls") if isinstance(value.get("misp_tls"), bool) else None,
        "sources": sources,
        "issues": issues,
    }


def _safe_validation_report(value):
    if not isinstance(value, Mapping):
        return None
    status = value.get("status")
    checks = value.get("checks")
    counts = value.get("counts")
    if status not in _VALID_VALIDATION_STATUSES or not isinstance(checks, (list, tuple)) or not isinstance(counts, Mapping):
        return None
    safe_checks = []
    for item in checks[:50]:
        if (
            not isinstance(item, Mapping)
            or not isinstance(item.get("code"), str)
            or item.get("status") not in _VALID_VALIDATION_STATUSES
        ):
            return None
        safe_checks.append({"code": item["code"][:80], "status": item["status"]})
    safe_counts = {
        key: count
        for key, count in counts.items()
        if key in _VALID_VALIDATION_STATUSES and isinstance(count, int) and 0 <= count <= 2_147_483_647
    }
    return {
        "status": status,
        "schema_version": str(value.get("schema_version", ""))[:64],
        "release": str(value.get("release", ""))[:32],
        "checks": safe_checks,
        "counts": safe_counts,
    }


def load_preflight_snapshot(value: object) -> WebPreflightSnapshot | None:
    if not isinstance(value, Mapping) or value.get("schema") != PREFLIGHT_SNAPSHOT_SCHEMA:
        return None
    captured_at = value.get("captured_at")
    if not isinstance(captured_at, str) or len(captured_at) > 64:
        return None
    freshness = _snapshot_freshness(captured_at)
    report = _safe_preflight_report(value.get("report"))
    if freshness is None or report is None:
        return None
    return WebPreflightSnapshot(captured_at, report, freshness)


def load_operational_validation_snapshot(value: object) -> WebOperationalValidationSnapshot | None:
    if not isinstance(value, Mapping) or value.get("schema") != VALIDATION_SNAPSHOT_SCHEMA:
        return None
    captured_at = value.get("captured_at")
    if not isinstance(captured_at, str) or len(captured_at) > 64:
        return None
    freshness = _snapshot_freshness(captured_at)
    report = _safe_validation_report(value.get("report"))
    required_sources = _safe_sources(value.get("required_sources"))
    if freshness is None or report is None or required_sources is None:
        return None
    return WebOperationalValidationSnapshot(captured_at, report, required_sources, freshness)


__all__ = [
    "MAX_FUTURE_SKEW",
    "MAX_SNAPSHOT_AGE",
    "PREFLIGHT_SNAPSHOT_SCHEMA",
    "VALIDATION_SNAPSHOT_SCHEMA",
    "WebOperationalValidationSnapshot",
    "WebPreflightSnapshot",
    "build_operational_validation_snapshot",
    "build_preflight_snapshot",
    "load_operational_validation_snapshot",
    "load_preflight_snapshot",
]
