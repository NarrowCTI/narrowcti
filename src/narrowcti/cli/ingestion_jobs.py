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


def _job_identity(job: Mapping[str, object]) -> tuple[str, str, str | None]:
    job_type = str(job.get("job_type") or "")
    if job_type not in INGESTION_JOB_TYPES:
        raise IngestionJobFailure("invalid_job")
    payload = job.get("payload")
    required_fields = {
        "source_key",
        "external_id",
        "request_id",
        "requester",
    }
    allowed_fields = required_fields | {"expected_fingerprint"}
    required = required_fields if job_type == INGESTION_PREVIEW_JOB else allowed_fields
    if (
        not isinstance(payload, Mapping)
        or not required.issubset(payload)
        or not set(payload).issubset(allowed_fields)
    ):
        raise IngestionJobFailure("invalid_job")
    if any(not isinstance(payload.get(key), str) for key in required_fields):
        raise IngestionJobFailure("invalid_job")
    source_key = payload["source_key"].strip().lower()
    external_id = payload["external_id"]
    has_expected = "expected_fingerprint" in payload
    expected_value = payload.get("expected_fingerprint")
    expected = expected_value if has_expected and isinstance(expected_value, str) else None
    request_id = payload["request_id"]
    requester = payload["requester"]
    if (
        source_key not in {"misp", "otx"}
        or not external_id
        or len(external_id) > 256
        or any(ord(char) < 32 for char in external_id)
        or (has_expected and (not isinstance(expected_value, str) or len(expected_value) != 64))
        or (job_type != INGESTION_PREVIEW_JOB and not has_expected)
        or (expected is not None and any(char not in "0123456789abcdef" for char in expected))
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


def _refetch_candidate_with_revision(
    processor,
    source_key: str,
    external_id: str,
    expected: str | None,
    *,
    allow_missing_candidate: bool = False,
):
    if source_key == "misp":
        raw = processor.misp_client.get_event(external_id)
        raw = _unwrap_misp(raw)
        if not isinstance(raw, dict):
            raise IngestionJobFailure("provider_unavailable")
        revision_fingerprint = source_document_fingerprint(raw)
        if expected is not None and revision_fingerprint != expected:
            raise IngestionJobFailure("candidate_changed")
        candidate_ref = processor.feed_adapter.normalize_event(raw, external_id=external_id)
    else:
        raw = processor.otx_client.enrich_pulse(external_id)
        if not isinstance(raw, dict):
            raise IngestionJobFailure("provider_unavailable")
        revision_fingerprint = source_document_fingerprint(raw)
        if expected is not None and revision_fingerprint != expected:
            raise IngestionJobFailure("candidate_changed")
        # Keep source-specific normalization on the existing processor seam;
        # the CLI must not import the legacy feed-adapter implementation.
        raw = dict(raw)
        raw.setdefault("id", external_id)
        candidate_ref = processor.normalize_feed_candidate(raw)
    if candidate_ref is None and allow_missing_candidate:
        return None, revision_fingerprint
    if candidate_ref is None or candidate_ref.external_id != external_id:
        raise IngestionJobFailure("provider_unavailable")
    return candidate_ref, revision_fingerprint


def _refetch_candidate(processor, source_key: str, external_id: str, expected: str):
    candidate_ref, _revision_fingerprint = _refetch_candidate_with_revision(
        processor,
        source_key,
        external_id,
        expected,
    )
    return candidate_ref


def _preview_candidate_projection(candidate_ref, *, source_key, external_id, revision_fingerprint, action):
    """Return only the bounded operator-facing fields for an evaluated candidate."""
    raw_title = getattr(candidate_ref, "title", "")
    title = raw_title[:512] if isinstance(raw_title, str) else ""

    raw_tags = getattr(candidate_ref, "tags", ()) or ()
    if not isinstance(raw_tags, (list, tuple)):
        raw_tags = ()
    tags = []
    for tag in raw_tags:
        if isinstance(tag, str) and tag.strip():
            tags.append(tag[:128])
            if len(tags) == 20:
                break

    indicators = getattr(candidate_ref, "indicators", ()) or ()
    indicator_count = len(indicators) if isinstance(indicators, (list, tuple)) else 0

    result = {
        "action": str(action),
        "source_key": source_key,
        "external_id": external_id,
        "revision_fingerprint": revision_fingerprint,
        "title": title,
        "indicator_count": indicator_count,
        "tags": tags,
    }
    tlp = next((tag for tag in tags if tag.lower().startswith("tlp:")), None)
    if tlp is not None:
        result["tlp"] = tlp[:64]
    return result


def execute_ingestion_job(job, settings, registry, logger):
    """Refetch by identity, verify revision and invoke the existing processor path."""

    job_type = str(job.get("job_type") or "")
    if job_type not in INGESTION_JOB_TYPES:
        raise IngestionJobFailure("invalid_job")
    if int(job.get("attempt") or 1) > 1:
        raise IngestionJobFailure("execution_ambiguous")
    source_key, external_id, expected = _job_identity(job)
    is_preview = job_type == INGESTION_PREVIEW_JOB
    try:
        runner = registry.get(source_key).factory()
        processor = runner.processor
        candidate_ref, revision_fingerprint = _refetch_candidate_with_revision(
            processor,
            source_key,
            external_id,
            expected,
            allow_missing_candidate=is_preview,
        )
    except IngestionJobFailure:
        raise
    except Exception:
        logger(f"ingestion job source refetch failed: source={source_key}")
        raise IngestionJobFailure("provider_unavailable") from None

    if candidate_ref is None:
        return {
            "action": "skip",
            "source_key": source_key,
            "external_id": external_id,
            "revision_fingerprint": revision_fingerprint,
        }

    # Reuse the verified fetch for the existing processor enrichment stage.
    # This closes the TOCTOU gap without persisting the raw source document.
    processor.feed_adapter.enrich = lambda _candidate: candidate_ref
    mode = job_type
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

    result = {
        "action": str(action),
        "source_key": source_key,
        "external_id": external_id,
    }
    if is_preview:
        return _preview_candidate_projection(
            candidate_ref,
            source_key=source_key,
            external_id=external_id,
            revision_fingerprint=revision_fingerprint,
            action=action,
        )
    return result


__all__ = ["IngestionJobFailure", "execute_ingestion_job"]
