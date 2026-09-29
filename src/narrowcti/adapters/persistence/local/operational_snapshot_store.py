"""Bounded atomic storage for safe Gateway operational-state snapshots."""

from __future__ import annotations

import json
import os
from pathlib import Path

from narrowcti.adapters.persistence.local.atomic_io import write_json_atomic
from narrowcti.application.reporting.operational_snapshot import (
    OperationalStateSnapshot,
    load_operational_state_snapshot,
)


MAX_SNAPSHOT_BYTES = 256 * 1024
SNAPSHOT_FILENAME = "operational-snapshot.json"


class LocalOperationalSnapshotStore:
    """Read the fixed snapshot adjacent to runtime.db; never follows a custom path."""

    def __init__(self, runtime_db_file: str):
        if not runtime_db_file:
            raise ValueError("runtime database location is required")
        self.path = Path(os.path.abspath(os.fspath(runtime_db_file))).parent / SNAPSHOT_FILENAME

    def read(self) -> dict | None:
        try:
            resolved = self.path.resolve(strict=True)
            if resolved.parent != self.path.parent.resolve() or not resolved.is_file():
                return None
            if resolved.stat().st_size > MAX_SNAPSHOT_BYTES:
                return None
            with resolved.open("rb") as file_obj:
                value = json.load(file_obj)
        except (OSError, UnicodeError, json.JSONDecodeError):
            return None
        snapshot = load_operational_state_snapshot(value)
        return snapshot.to_dict() if snapshot is not None else None

    def write(self, snapshot: OperationalStateSnapshot) -> None:
        payload = json.dumps(snapshot.to_dict(), sort_keys=True, separators=(",", ":"))
        if len(payload.encode("utf-8")) > MAX_SNAPSHOT_BYTES:
            raise ValueError("operational snapshot exceeds its size limit")
        write_json_atomic(str(self.path), snapshot.to_dict())


__all__ = ["MAX_SNAPSHOT_BYTES", "SNAPSHOT_FILENAME", "LocalOperationalSnapshotStore"]
