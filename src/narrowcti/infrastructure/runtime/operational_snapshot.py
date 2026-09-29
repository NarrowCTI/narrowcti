"""Gateway-side publication of bounded operational state for read-only Web use."""

from __future__ import annotations

from narrowcti.adapters.persistence.local.operational_snapshot_store import (
    LocalOperationalSnapshotStore,
)
from narrowcti.adapters.persistence.local.web_evidence_reader import read_recent_records
from narrowcti.application.reporting.operational_snapshot import (
    build_operational_state_snapshot,
)


def publish_gateway_operational_snapshot(settings, preflight_report):
    """Build from Gateway settings and raw bounded evidence, then atomically publish."""

    records = read_recent_records(settings.decision_audit_dir, limit=100)
    snapshot = build_operational_state_snapshot(
        preflight_report,
        records,
        required_sources=tuple(settings.enabled_sources),
    )
    LocalOperationalSnapshotStore(settings.runtime_db_file).write(snapshot)
    return snapshot


__all__ = ["publish_gateway_operational_snapshot"]
