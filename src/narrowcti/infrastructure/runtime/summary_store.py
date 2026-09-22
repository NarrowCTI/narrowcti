"""Local JSONL persistence for gateway cycle summaries."""

from __future__ import annotations

import json
import os


def write_gateway_summary(summary, summary_file, logger):
    if not summary_file:
        return
    try:
        directory = os.path.dirname(summary_file)
        if directory:
            os.makedirs(directory, exist_ok=True)
        with open(summary_file, "a", encoding="utf-8") as file_obj:
            file_obj.write(json.dumps(summary.to_dict(), sort_keys=True) + "\n")
    except Exception as exc:
        logger(f"Gateway summary write failed: {summary_file} error={exc}")


def read_gateway_summary_file(summary_file, limit=None):
    """Read gateway cycle summaries using the historical strict semantics."""

    records = []
    with open(summary_file, "r", encoding="utf-8") as file_obj:
        for line in file_obj:
            stripped = line.strip()
            if stripped:
                records.append(json.loads(stripped))
    if limit is not None and limit > 0:
        records = records[-limit:]
    return records


__all__ = ["write_gateway_summary", "read_gateway_summary_file"]
