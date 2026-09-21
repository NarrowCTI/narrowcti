"""JSONL review audit reader for the Community local adapter."""

import json
import os


def read_audit_events(path):
    if not path or not os.path.exists(path):
        return []
    events = []
    with open(path, "r", encoding="utf-8-sig") as file_obj:
        for line in file_obj:
            stripped = line.strip()
            if stripped:
                events.append(json.loads(stripped))
    return events


__all__ = ["read_audit_events"]
