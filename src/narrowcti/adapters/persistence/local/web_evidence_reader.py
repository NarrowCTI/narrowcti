"""Bounded reader for the configured local DecisionRecord JSONL files."""

from __future__ import annotations

import json
from collections import deque
from pathlib import Path


MAX_FILES = 8
MAX_BYTES_PER_FILE = 256 * 1024
MAX_RECORD_BYTES = 16 * 1024


def read_recent_records(directory: str, limit: int = 100) -> list[dict]:
    if not 1 <= limit <= 100:
        raise ValueError("evidence limit must be between 1 and 100")
    root = Path(directory).resolve()
    if not root.is_dir():
        return []
    candidates = []
    for path in root.glob("*.jsonl"):
        try:
            resolved = path.resolve(strict=True)
            if resolved.parent != root or not resolved.is_file():
                continue
            candidates.append((resolved.stat().st_mtime_ns, resolved))
        except OSError:
            continue
    records = deque(maxlen=limit)
    for _mtime, path in sorted(candidates)[-MAX_FILES:]:
        try:
            size = path.stat().st_size
            with path.open("rb") as stream:
                stream.seek(max(0, size - MAX_BYTES_PER_FILE))
                if size > MAX_BYTES_PER_FILE:
                    stream.readline(MAX_RECORD_BYTES + 1)
                bytes_read = 0
                while bytes_read < MAX_BYTES_PER_FILE:
                    line = stream.readline(min(MAX_RECORD_BYTES + 1, MAX_BYTES_PER_FILE - bytes_read))
                    if not line:
                        break
                    bytes_read += len(line)
                    if len(line) > MAX_RECORD_BYTES or not line.strip():
                        continue
                    try:
                        value = json.loads(line)
                    except (UnicodeDecodeError, json.JSONDecodeError):
                        continue
                    if isinstance(value, dict):
                        records.append(value)
        except OSError:
            continue
    return list(records)


__all__ = ["MAX_FILES", "MAX_BYTES_PER_FILE", "MAX_RECORD_BYTES", "read_recent_records"]
