"""Local JSONL/glob reader for decision audit evidence.

The producer and writer remain owned by ``core.decision_audit``.  This module
only preserves the historical file acquisition semantics used by reporting.
"""

from __future__ import annotations

import glob
import json
import os


def expand_paths(paths):
    expanded = []
    for path in paths or ():
        path = str(path or "")
        if os.path.isdir(path):
            expanded.extend(sorted(glob.glob(os.path.join(path, "*.jsonl"))))
        elif not os.path.exists(path) and os.path.splitext(path)[1].lower() != ".jsonl":
            continue
        else:
            expanded.append(path)
    return expanded


def read_decision_records(paths, limit=None):
    records = []
    for path in expand_paths(paths):
        with open(path, "r", encoding="utf-8") as file_obj:
            for line in file_obj:
                stripped = line.strip()
                if stripped:
                    records.append(json.loads(stripped))
    records.sort(key=lambda record: record.get("recorded_at", ""))
    if limit is not None and limit > 0:
        records = records[-limit:]
    return records


__all__ = ["expand_paths", "read_decision_records"]
