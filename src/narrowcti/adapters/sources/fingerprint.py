"""Canonical value fingerprints for bounded source-object identity checks."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping


def source_document_fingerprint(value: Mapping[str, object]) -> str:
    encoded = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


__all__ = ["source_document_fingerprint"]
