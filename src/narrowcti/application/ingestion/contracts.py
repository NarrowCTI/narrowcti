"""Small explicit contract used by the candidate-level ingestion seam."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from .outcomes import IngestionOutcome


@dataclass(frozen=True)
class IngestionOperations:
    """Source-provided operations consumed in a fixed application order.

    The bundle deliberately describes operations rather than implementing any
    source, policy, persistence or exporter behavior.  It is an immutable seam
    for the later MISP and OTX cutovers.
    """

    precheck: Callable[[Any], IngestionOutcome | None]
    enrich: Callable[[Any], Any | None]
    tlp: Callable[[Any], IngestionOutcome]
    score: Callable[[Any], Any]
    policy: Callable[[Any], IngestionOutcome]
    indicator_filter: Callable[[Any], tuple[Any | None, str]]
    artifact_dedup: Callable[[Any], tuple[Any | None, str]]
    export: Callable[[Any, Any, str], Any]
    mark_artifacts: Callable[[Any], None]
    checkpoint: Callable[[Any], None]
    record_decision: Callable[[Any, Any | None, IngestionOutcome], None]
    mark_graph: Callable[[Any, Any, dict[str, object]], None] | None = None
    dry_run: bool = False


__all__ = ["IngestionOperations"]
