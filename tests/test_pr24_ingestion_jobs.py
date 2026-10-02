"""Safety contracts for identity-only Community Web ingestion jobs."""

from __future__ import annotations

import unittest
from dataclasses import dataclass
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace

from connectors.misp.settings import load_settings as load_misp_settings
from narrowcti.adapters.sources.fingerprint import source_document_fingerprint
from narrowcti.cli.ingestion_jobs import (
    IngestionJobFailure,
    _refetch_candidate,
    execute_ingestion_job,
)
from narrowcti.adapters.persistence.local.job_repository import SQLiteJobRepository
from narrowcti.adapters.persistence.local.sqlite_runtime_store import SQLiteRuntimeStore
from narrowcti.ports.jobs import (
    ActiveJobLimitReached,
    INGESTION_DRY_RUN_JOB,
    INGESTION_PREVIEW_JOB,
    INGESTION_RUN_ONCE_JOB,
)


EVENT = {"uuid": "event-42", "info": "Synthetic incident", "Tag": []}


def _settings():
    return load_misp_settings(
        {
            "OPENCTI_URL": "https://opencti.invalid",
            "OPENCTI_TOKEN": "synthetic-opencti-token",
            "MISP_URL": "https://misp.invalid",
            "MISP_KEY": "synthetic-misp-token",
            "MISP_QUERIES": "*",
            "MISP_DRY_RUN": "false",
            "MISP_STATE_FILE": "synthetic-state.json",
        }
    )


@dataclass(frozen=True)
class _CandidateRef:
    external_id: str
    title: str
    raw: dict
    indicators: tuple = ()
    tags: tuple = ()


class _State:
    def __init__(self):
        self.events = []
        self.pulses = []

    def has_event(self, _external_id):
        return False

    def has_pulse(self, _external_id):
        return False

    def mark_event(self, external_id):
        self.events.append(external_id)

    def mark_pulse(self, external_id):
        self.pulses.append(external_id)


class _MISPClient:
    def __init__(self, event):
        self.event = event
        self.calls = []

    def get_event(self, external_id):
        self.calls.append(external_id)
        return self.event


class _FeedAdapter:
    def __init__(self):
        self.enrich = lambda _candidate: None
        self.normalizations = []

    def normalize_event(self, raw, *, external_id):
        self.normalizations.append(raw)
        indicators = tuple(raw.get("Attribute") or ())
        tags = tuple(
            tag.get("name", "") if isinstance(tag, dict) else str(tag)
            for tag in raw.get("Tag", ())
        )
        return _CandidateRef(external_id, raw["info"], raw, indicators, tags)


class _Processor:
    def __init__(self, event):
        self.settings = _settings()
        self.misp_client = _MISPClient(event)
        self.feed_adapter = _FeedAdapter()
        self.state = _State()
        self.state_repository_factory = lambda _path: self.state
        self.decision_audit = _Audit()
        self.quarantine_repository = _Quarantine()
        self.received = None

    def process_event_outcome(self, query, candidate_ref, state):
        self.received = (query, candidate_ref, state)
        if not self.settings.dry_run:
            state.mark_event(candidate_ref.external_id)
        self.decision_audit.record({"external_id": candidate_ref.external_id})
        if self.quarantine_repository is not None:
            self.quarantine_repository.add({"external_id": candidate_ref.external_id})
        return "ingest"

    def process_pulse_outcome(self, query, candidate_ref, state):
        return self.process_event_outcome(query, candidate_ref, state)


class _Audit:
    def __init__(self):
        self.records = []

    def record(self, record):
        self.records.append(record)


class _Quarantine:
    def __init__(self):
        self.records = []

    def add(self, record):
        self.records.append(record)


class _Registry:
    def __init__(self, processor):
        self.processor = processor
        self.lookups = []

    def get(self, key):
        self.lookups.append(key)
        return SimpleNamespace(factory=lambda: SimpleNamespace(processor=self.processor))


def _job(job_type=INGESTION_PREVIEW_JOB, *, event=EVENT, attempt=1, payload_updates=None):
    payload = {
        "source_key": "misp",
        "external_id": "event-42",
        "expected_fingerprint": source_document_fingerprint(event),
        "request_id": "request_12345",
        "requester": "reader",
    }
    payload.update(payload_updates or {})
    return {"job_type": job_type, "attempt": attempt, "payload": payload}


class IngestionJobTests(unittest.TestCase):
    def test_otx_refetch_uses_processor_normalizer_and_supplies_requested_id(self):
        pulse = {"name": "Synthetic pulse", "created": "2026-09-27T00:00:00Z"}
        processor = SimpleNamespace(
            otx_client=SimpleNamespace(enrich_pulse=lambda _external_id: dict(pulse)),
            normalize_feed_candidate=lambda raw: _CandidateRef(
                raw["id"], raw["name"], raw
            ),
        )

        candidate = _refetch_candidate(
            processor,
            "otx",
            "pulse-42",
            source_document_fingerprint(pulse),
        )

        self.assertEqual(candidate.external_id, "pulse-42")
        self.assertEqual(candidate.raw["id"], "pulse-42")

    def test_job_submission_is_idempotent_and_run_once_active_limit_is_atomic(self):
        with TemporaryDirectory() as directory:
            repository = SQLiteJobRepository(
                SQLiteRuntimeStore(str(Path(directory) / "runtime.db"))
            )
            payload = {"source_key": "misp", "external_id": "event-42"}
            first = repository.submit(
                INGESTION_RUN_ONCE_JOB,
                "misp",
                payload,
                idempotency_key="same-request",
                active_limit=1,
            )
            duplicate = repository.submit(
                INGESTION_RUN_ONCE_JOB,
                "misp",
                payload,
                idempotency_key="same-request",
                active_limit=1,
            )
            self.assertEqual(duplicate["job_id"], first["job_id"])
            with self.assertRaises(ActiveJobLimitReached):
                repository.submit(
                    INGESTION_RUN_ONCE_JOB,
                    "misp",
                    {**payload, "external_id": "event-43"},
                    idempotency_key="new-request",
                    active_limit=1,
                )

    def test_preview_refetches_by_identity_and_disables_all_durable_candidate_effects(self):
        processor = _Processor(dict(EVENT))
        original_audit = processor.decision_audit
        original_quarantine = processor.quarantine_repository
        registry = _Registry(processor)
        logs = []

        result = execute_ingestion_job(_job(), None, registry, logs.append)

        self.assertEqual(
            result,
            {
                "action": "ingest",
                "source_key": "misp",
                "external_id": "event-42",
                "revision_fingerprint": source_document_fingerprint(processor.misp_client.event),
                "title": "Synthetic incident",
                "indicator_count": 0,
                "tags": [],
            },
        )
        self.assertEqual(processor.misp_client.calls, ["event-42"])
        self.assertEqual(registry.lookups, ["misp"])
        self.assertTrue(processor.settings.dry_run)
        self.assertEqual(processor.state.events, [])
        self.assertEqual(processor.state.pulses, [])
        self.assertIsNot(processor.decision_audit, original_audit)
        self.assertEqual(original_audit.records, [])
        self.assertIsNone(processor.quarantine_repository)
        self.assertEqual(original_quarantine.records, [])
        self.assertEqual(processor.received[0], "Community Web")
        self.assertEqual(processor.received[1].external_id, "event-42")
        self.assertIs(processor.feed_adapter.normalizations[0], processor.misp_client.event)
        self.assertNotIn("raw_event", _job()["payload"])
        self.assertNotIn("raw", result)
        self.assertNotIn("indicators", result)

    def test_preview_projects_bounded_candidate_context_without_indicator_values(self):
        event = {
            **EVENT,
            "info": "L" * 700,
            "Tag": [{"name": "tlp:amber"}, {"name": "actor:example"}, {"name": "secret-tag-value"}],
            "Attribute": [
                {"type": "domain", "value": "private-observable.example"},
                {"type": "sha256", "value": "private-hash-value"},
            ],
        }
        processor = _Processor(event)
        job = _job(event=event)
        del job["payload"]["expected_fingerprint"]

        result = execute_ingestion_job(job, None, _Registry(processor), lambda _message: None)

        self.assertEqual(1, len(processor.misp_client.calls))
        self.assertEqual(source_document_fingerprint(event), result["revision_fingerprint"])
        self.assertEqual(512, len(result["title"]))
        self.assertEqual(2, result["indicator_count"])
        self.assertEqual(["tlp:amber", "actor:example", "secret-tag-value"], result["tags"])
        self.assertEqual("tlp:amber", result["tlp"])
        self.assertNotIn("private-observable.example", repr(result))
        self.assertNotIn("private-hash-value", repr(result))
        self.assertNotIn("Attribute", repr(result))

    def test_preview_without_fingerprint_issues_revision_for_same_single_fetch(self):
        event = dict(EVENT)
        processor = _Processor(event)
        original_audit = processor.decision_audit
        job = _job(event=event)
        del job["payload"]["expected_fingerprint"]

        result = execute_ingestion_job(job, None, _Registry(processor), lambda _message: None)

        self.assertEqual(1, len(processor.misp_client.calls))
        self.assertEqual(source_document_fingerprint(event), result["revision_fingerprint"])
        self.assertIs(processor.feed_adapter.normalizations[0], event)
        self.assertIs(processor.received[1].raw, event)
        self.assertEqual(processor.state.events, [])
        self.assertEqual(processor.state.pulses, [])
        self.assertIsNot(processor.decision_audit, original_audit)
        self.assertEqual([], original_audit.records)
        self.assertEqual(processor.quarantine_repository, None)

    def test_preview_returns_revision_for_source_normalization_skip(self):
        event = dict(EVENT)
        processor = _Processor(event)
        processor.feed_adapter.normalize_event = lambda _raw, external_id=None: None
        job = _job(event=event)
        del job["payload"]["expected_fingerprint"]

        result = execute_ingestion_job(job, None, _Registry(processor), lambda _message: None)

        self.assertEqual(
            result,
            {
                "action": "skip",
                "source_key": "misp",
                "external_id": "event-42",
                "revision_fingerprint": source_document_fingerprint(event),
            },
        )
        self.assertEqual(["event-42"], processor.misp_client.calls)
        self.assertIsNone(processor.received)
        self.assertEqual([], processor.state.events)
        self.assertEqual([], processor.state.pulses)

    def test_dry_run_keeps_fail_closed_behavior_when_normalization_returns_no_candidate(self):
        processor = _Processor(dict(EVENT))
        processor.feed_adapter.normalize_event = lambda _raw, external_id=None: None

        with self.assertRaisesRegex(IngestionJobFailure, "provider_unavailable"):
            execute_ingestion_job(
                _job(INGESTION_DRY_RUN_JOB),
                None,
                _Registry(processor),
                lambda _message: None,
            )

        self.assertEqual(["event-42"], processor.misp_client.calls)
        self.assertIsNone(processor.received)

    def test_dry_run_keeps_local_evidence_contract_but_wraps_checkpoint_state(self):
        processor = _Processor(dict(EVENT))
        registry = _Registry(processor)

        execute_ingestion_job(_job(INGESTION_DRY_RUN_JOB), None, registry, lambda _message: None)

        self.assertTrue(processor.settings.dry_run)
        self.assertEqual(processor.state.events, [])
        self.assertEqual(len(processor.decision_audit.records), 1)
        self.assertEqual(len(processor.quarantine_repository.records), 1)

    def test_dry_run_and_run_once_require_a_fingerprint_before_provider_fetch(self):
        for job_type in (INGESTION_DRY_RUN_JOB, INGESTION_RUN_ONCE_JOB):
            with self.subTest(job_type=job_type):
                processor = _Processor(dict(EVENT))
                job = _job(job_type)
                del job["payload"]["expected_fingerprint"]
                with self.assertRaisesRegex(IngestionJobFailure, "invalid_job"):
                    execute_ingestion_job(job, None, _Registry(processor), lambda _message: None)
                self.assertEqual(processor.misp_client.calls, [])

    def test_run_once_uses_worker_state_and_preserves_real_ingestion_mode(self):
        processor = _Processor(dict(EVENT))
        registry = _Registry(processor)

        execute_ingestion_job(_job(INGESTION_RUN_ONCE_JOB), None, registry, lambda _message: None)

        self.assertFalse(processor.settings.dry_run)
        self.assertEqual(processor.state.events, ["event-42"])
        self.assertEqual(processor.misp_client.calls, ["event-42"])

    def test_changed_source_revision_fails_closed_before_processor_execution(self):
        changed = {**EVENT, "info": "Changed after browsing"}
        processor = _Processor(changed)
        registry = _Registry(processor)

        with self.assertRaisesRegex(IngestionJobFailure, "candidate_changed"):
            execute_ingestion_job(_job(), None, registry, lambda _message: None)
        self.assertEqual(processor.misp_client.calls, ["event-42"])
        self.assertEqual(processor.feed_adapter.normalizations, [])
        self.assertIsNone(processor.received)

    def test_preview_with_fingerprint_still_rejects_changed_source(self):
        changed = {**EVENT, "info": "Changed after detail"}
        processor = _Processor(changed)
        with self.assertRaisesRegex(IngestionJobFailure, "candidate_changed"):
            execute_ingestion_job(_job(), None, _Registry(processor), lambda _message: None)
        self.assertEqual(processor.feed_adapter.normalizations, [])

    def test_otx_preview_with_existing_fingerprint_keeps_full_document_contract(self):
        pulse = {"name": "Synthetic pulse", "created": "2026-09-27T00:00:00Z"}
        processor = _Processor(dict(EVENT))
        processor.otx_client = SimpleNamespace(enrich_pulse=lambda _external_id: pulse)
        processor.normalize_feed_candidate = lambda raw: _CandidateRef("pulse-42", raw["name"], raw)
        job = _job(payload_updates={"source_key": "otx", "external_id": "pulse-42"})
        job["payload"]["expected_fingerprint"] = source_document_fingerprint(pulse)

        result = execute_ingestion_job(job, None, _Registry(processor), lambda _message: None)

        self.assertEqual(source_document_fingerprint(pulse), result["revision_fingerprint"])
        self.assertEqual("pulse-42", result["external_id"])
        self.assertEqual(processor.state.events, [])
        self.assertEqual(processor.misp_client.calls, [])

    def test_reclaimed_attempt_is_ambiguous_and_never_replayed(self):
        processor = _Processor(dict(EVENT))
        registry = _Registry(processor)

        with self.assertRaisesRegex(IngestionJobFailure, "execution_ambiguous"):
            execute_ingestion_job(_job(attempt=2), None, registry, lambda _message: None)
        self.assertEqual(registry.lookups, [])
        self.assertEqual(processor.misp_client.calls, [])

    def test_worker_rejects_payloads_containing_raw_or_unknown_fields(self):
        processor = _Processor(dict(EVENT))
        registry = _Registry(processor)

        with self.assertRaisesRegex(IngestionJobFailure, "invalid_job"):
            execute_ingestion_job(
                _job(payload_updates={"raw_event": dict(EVENT)}),
                None,
                registry,
                lambda _message: None,
            )
        self.assertEqual(registry.lookups, [])


if __name__ == "__main__":
    unittest.main()
