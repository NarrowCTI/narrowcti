"""Explicit Worker handlers for bounded candidate-level ingestion jobs."""

from __future__ import annotations

from dataclasses import replace
from typing import Mapping

from narrowcti.adapters.sources.fingerprint import source_document_fingerprint
from narrowcti.ports.jobs import (
    INGESTION_DRY_RUN_JOB,
    INGESTION_JOB_TYPES,
    INGESTION_PREVIEW_JOB,
)


class IngestionJobFailure(RuntimeError):
    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


class _ReadOnlyState:
    """Preserve processed-state reads while preventing UI evaluation writes."""

    def __init__(self, repository):
        self._repository = repository

    def has_event(self, external_id):
        return self._repository.has_event(external_id)

    def has_pulse(self, external_id):
        return self._repository.has_pulse(external_id)

    def mark_event(self, _external_id):
        return None

    def mark_pulse(self, _external_id):
        return None


class _DiscardAudit:
    def record(self, _record):
        return None


def _job_identity(job: Mapping[str, object]) -> tuple[str, str, str]:
    payload = job.get("payload")
    expected_fields = {
        "source_key",
        "external_id",
        "expected_fingerprint",
        "request_id",
        "requester",
    }
    if not isinstance(payload, Mapping) or set(payload) != expected_fields:
        raise IngestionJobFailure("invalid_job")
    source_key = str(payload.get("source_key") or "").strip().lower()
    external_id = str(payload.get("external_id") or "")
    expected = str(payload.get("expected_fingerprint") or "")
    request_id = str(payload.get("request_id") or "")
    requester = str(payload.get("requester") or "")
    if (
        source_key not in {"misp", "otx"}
        or not external_id
        or len(external_id) > 256
        or any(ord(char) < 32 for char in external_id)
        or len(expected) != 64
        or any(char not in "0123456789abcdef" for char in expected)
        or not 8 <= len(request_id) <= 64
        or any(not (char.isalnum() or char in "_-") for char in request_id)
        or not requester
        or len(requester) > 128
        or any(ord(char) < 32 for char in requester)
    ):
        raise IngestionJobFailure("invalid_job")
    return source_key, external_id, expected


def _unwrap_misp(value):
    if isinstance(value, dict) and isinstance(value.get("Event"), dict):
        return value["Event"]
    return value


def _refetch_candidate(processor, source_key: str, external_id: str, expected: str):
    if source_key == "misp":
        raw = processor.misp_client.get_event(external_id)
        raw = _unwrap_misp(raw)
        if not isinstance(raw, dict):
            raise IngestionJobFailure("provider_unavailable")
        if source_document_fingerprint(raw) != expected:
            raise IngestionJobFailure("candidate_changed")
        candidate_ref = processor.feed_adapter.normalize_event(raw, external_id=external_id)
    else:
        raw = processor.otx_client.enrich_pulse(external_id)
        if not isinstance(raw, dict):
            raise IngestionJobFailure("provider_unavailable")
        if source_document_fingerprint(raw) != expected:
            raise IngestionJobFailure("candidate_changed")
        # Keep source-specific normalization on the existing processor seam;
        # the CLI must not import the legacy feed-adapter implementation.
        raw = dict(raw)
        raw.setdefault("id", external_id)
        candidate_ref = processor.normalize_feed_candidate(raw)
    if candidate_ref is None or candidate_ref.external_id != external_id:
        raise IngestionJobFailure("provider_unavailable")
    return candidate_ref


def execute_ingestion_job(job, settings, registry, logger):
    """Refetch by identity, verify revision and invoke the existing processor path."""

    job_type = str(job.get("job_type") or "")
    if job_type not in INGESTION_JOB_TYPES:
        raise IngestionJobFailure("invalid_job")
    if int(job.get("attempt") or 1) > 1:
        raise IngestionJobFailure("execution_ambiguous")
    source_key, external_id, expected = _job_identity(job)
    try:
        runner = registry.get(source_key).factory()
        processor = runner.processor
        candidate_ref = _refetch_candidate(processor, source_key, external_id, expected)
    except IngestionJobFailure:
        raise
    except Exception:
        logger(f"ingestion job source refetch failed: source={source_key}")
        raise IngestionJobFailure("provider_unavailable") from None

    # Reuse the verified fetch for the existing processor enrichment stage.
    # This closes the TOCTOU gap without persisting the raw source document.
    processor.feed_adapter.enrich = lambda _candidate: candidate_ref
    mode = job_type
    is_preview = mode == INGESTION_PREVIEW_JOB
    is_governed_dry_run = mode in {INGESTION_PREVIEW_JOB, INGESTION_DRY_RUN_JOB}
    if is_governed_dry_run:
        processor.settings = replace(processor.settings, dry_run=True)

    state = processor.state_repository_factory(processor.settings.state_file)
    if is_governed_dry_run:
        state = _ReadOnlyState(state)
    if is_preview:
        processor.decision_audit = _DiscardAudit()
        processor.quarantine_repository = None

    try:
        if source_key == "misp":
            action = processor.process_event_outcome("Community Web", candidate_ref, state)
        else:
            action = processor.process_pulse_outcome("Community Web", candidate_ref, state)
    except Exception:
        logger(f"ingestion job execution failed: source={source_key} mode={mode}")
        raise IngestionJobFailure("ingestion_failed") from None

    return {
        "action": str(action),
        "source_key": source_key,
        "external_id": external_id,
    }


__all__ = ["IngestionJobFailure", "execute_ingestion_job"]
