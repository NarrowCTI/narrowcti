"""Ops-owned publication of safe, independent Web operational snapshots."""

from __future__ import annotations

from narrowcti.adapters.persistence.local.operational_snapshot_store import (
    LocalOperationalSnapshotStore,
)
from narrowcti.application.reporting.operational_snapshot import (
    build_operational_validation_snapshot,
    build_preflight_snapshot,
)


def publish_gateway_preflight_snapshot(settings, preflight_report):
    """Publish the Gateway preflight result without deriving validation state."""

    snapshot = build_preflight_snapshot(preflight_report)
    LocalOperationalSnapshotStore(settings.runtime_db_file).write_preflight(snapshot)
    return snapshot


def publish_operational_validation_snapshot(settings, validation_report, required_sources):
    """Publish the report produced by the authoritative Operational Validation workflow."""

    snapshot = build_operational_validation_snapshot(
        validation_report,
        required_sources=tuple(required_sources),
    )
    LocalOperationalSnapshotStore(settings.runtime_db_file).write_validation(snapshot)
    return snapshot


__all__ = [
    "publish_gateway_preflight_snapshot",
    "publish_operational_validation_snapshot",
]
