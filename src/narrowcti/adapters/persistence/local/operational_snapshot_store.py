"""Bounded atomic stores for separate Ops-owned Web read snapshots."""

from __future__ import annotations

import json
import os
from pathlib import Path

from narrowcti.adapters.persistence.local.atomic_io import write_json_atomic
from narrowcti.application.reporting.operational_snapshot import (
    WebOperationalValidationSnapshot,
    WebPreflightSnapshot,
)


MAX_SNAPSHOT_BYTES = 256 * 1024
PREFLIGHT_SNAPSHOT_FILENAME = "preflight-snapshot.json"
VALIDATION_SNAPSHOT_FILENAME = "operational-validation-snapshot.json"


class LocalOperationalSnapshotStore:
    """Read/write only fixed snapshot files alongside the shared runtime DB."""

    def __init__(self, runtime_db_file: str):
        if not runtime_db_file:
            raise ValueError("runtime database location is required")
        self.directory = Path(os.path.abspath(os.fspath(runtime_db_file))).parent

    def _path(self, filename):
        return self.directory / filename

    def _read(self, filename):
        path = self._path(filename)
        try:
            resolved = path.resolve(strict=True)
            if resolved.parent != self.directory.resolve() or not resolved.is_file():
                return None
            if resolved.stat().st_size > MAX_SNAPSHOT_BYTES:
                return None
            with resolved.open("rb") as file_obj:
                value = json.load(file_obj)
        except (OSError, UnicodeError, json.JSONDecodeError):
            return None
        return value if isinstance(value, dict) else None

    def _write(self, filename, snapshot):
        payload = snapshot.to_dict()
        encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        if len(encoded) > MAX_SNAPSHOT_BYTES:
            raise ValueError("operational snapshot exceeds its size limit")
        write_json_atomic(str(self._path(filename)), payload)

    def read_preflight(self):
        return self._read(PREFLIGHT_SNAPSHOT_FILENAME)

    def write_preflight(self, snapshot: WebPreflightSnapshot) -> None:
        self._write(PREFLIGHT_SNAPSHOT_FILENAME, snapshot)

    def read_validation(self):
        return self._read(VALIDATION_SNAPSHOT_FILENAME)

    def write_validation(self, snapshot: WebOperationalValidationSnapshot) -> None:
        self._write(VALIDATION_SNAPSHOT_FILENAME, snapshot)


__all__ = [
    "MAX_SNAPSHOT_BYTES",
    "PREFLIGHT_SNAPSHOT_FILENAME",
    "VALIDATION_SNAPSHOT_FILENAME",
    "LocalOperationalSnapshotStore",
]
