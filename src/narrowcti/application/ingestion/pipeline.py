"""Linear candidate-level ingestion orchestration.

This module owns ordering only.  Source normalization, enrichment, scoring,
policy, persistence and export implementations remain supplied by callers.
"""

from typing import Any

from .contracts import IngestionOperations
from .outcomes import IngestionOutcome


def run_candidate(candidate_ref: Any, operations: IngestionOperations) -> IngestionOutcome:
    """Run one candidate through the characterized decision and export order."""

    candidate = None

    precheck = operations.precheck(candidate_ref)
    if precheck is not None:
        operations.record_decision(candidate_ref, candidate, precheck)
        return precheck

    candidate = operations.enrich(candidate_ref)
    if candidate is None:
        return _record(
            operations,
            candidate_ref,
            candidate,
            IngestionOutcome("skip", "enrichment failed"),
        )

    tlp = operations.tlp(candidate)
    if tlp.action != "ingest":
        return _record(operations, candidate_ref, candidate, tlp)

    candidate = operations.score(candidate)

    policy = operations.policy(candidate)
    if policy.action != "ingest":
        return _record(operations, candidate_ref, candidate, policy)
    current_reason = policy.reason

    candidate, filter_reason = operations.indicator_filter(candidate)
    if candidate is None:
        return _record(
            operations,
            candidate_ref,
            candidate,
            IngestionOutcome("skip", filter_reason),
        )

    candidate, dedup_reason = operations.artifact_dedup(candidate)
    if candidate is None:
        return _record(
            operations,
            candidate_ref,
            candidate,
            IngestionOutcome("skip", dedup_reason),
        )
    if dedup_reason:
        current_reason = dedup_reason

    if operations.dry_run:
        return _record(
            operations,
            candidate_ref,
            candidate,
            IngestionOutcome("dry_run", current_reason),
        )

    export_result = operations.export(candidate_ref, candidate, current_reason)
    if not export_result:
        return _record(
            operations,
            candidate_ref,
            candidate,
            IngestionOutcome("error", "export failed"),
        )

    operations.mark_artifacts(candidate)
    operations.checkpoint(candidate)
    success = IngestionOutcome("ingest", current_reason)
    operations.record_decision(candidate_ref, candidate, success)
    if operations.mark_graph and isinstance(export_result, dict):
        operations.mark_graph(candidate_ref, candidate, export_result)
    return success


def _record(
    operations: IngestionOperations,
    candidate_ref: Any,
    candidate: Any | None,
    outcome: IngestionOutcome,
) -> IngestionOutcome:
    operations.record_decision(candidate_ref, candidate, outcome)
    return outcome


__all__ = ["run_candidate"]
