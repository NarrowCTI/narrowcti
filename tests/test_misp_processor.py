import unittest
from types import SimpleNamespace

from connectors.misp.processor import MISPProcessor, decision_metadata
from core.feed_contract import FeedCandidate, FeedRunSummary, FeedSource


MISP_TEST_SOURCE = FeedSource(name="MISP", source_type="external_import", provider="MISP")


def candidate(external_id="event-1", title="Search result", raw=None):
    return FeedCandidate(
        source=MISP_TEST_SOURCE,
        external_id=external_id,
        title=title,
        raw=raw or {},
    )


def enriched_event(name="tlp green event", indicator_count=10):
    indicators = [
        {"type": "domain", "indicator": f"host-{index}.example"}
        for index in range(indicator_count)
    ]
    return {
        "id": "event-1",
        "name": name,
        "description": "description",
        "created": "2099-01-01T00:00:00Z",
        "tags": ["tlp:green"],
        "indicators": indicators,
        "provenance": {
            "collector": "misp",
            "original_source": "AlienVault",
            "misp_event_id": "12",
            "misp_event_uuid": "event-1",
        },
        "narrowcti_controls": {
            "attribute_count": 10,
            "max_attributes_per_event": 1000,
            "oversized": False,
            "oversized_event_action": "skip",
        },
    }


class MISPProcessorTests(unittest.TestCase):
    def settings(self):
        return SimpleNamespace(
            max_events_per_run=10,
            max_iocs_per_event=1,
            quarantine_score_threshold=50,
            enable_quarantine=True,
            min_score_to_ingest=60,
            max_days_old=1095,
            min_score_for_old_event=80,
            max_days_hard_filter=0,
            allowed_tlp=[],
            allowed_indicator_types=[],
            connector_name="Test Connector",
            state_file="misp-state.json",
            decision_audit_file="",
            misp_queries=["tlp:green", "ransomware"],
            adapter_limits=None,
            dry_run=False,
        )

    def adapter(self, search_candidates=None, enriched=None):
        return SimpleNamespace(
            source=MISP_TEST_SOURCE,
            search=lambda query: search_candidates or [],
            enrich=lambda event: enriched,
        )

    def test_run_once_builds_state_repository_and_processes_queries(self):
        states = []
        processed_queries = []

        def state_repository_factory(path):
            state = SimpleNamespace(path=path)
            states.append(state)
            return state

        processor = MISPProcessor(
            self.settings(),
            misp_client=None,
            api_client=None,
            logger=lambda message: None,
            state_repository_factory=state_repository_factory,
            feed_adapter=self.adapter(),
        )

        def process_query(query, state):
            processed_queries.append((query, state.path))
            return FeedRunSummary(MISP_TEST_SOURCE, query, reviewed=1, available=1)

        processor.process_query = process_query

        summaries = processor.run_once()

        self.assertEqual(["misp-state.json"], [state.path for state in states])
        self.assertEqual(
            [("tlp:green", "misp-state.json"), ("ransomware", "misp-state.json")],
            processed_queries,
        )
        self.assertEqual(2, len(summaries))

    def test_prepare_candidate_limits_exported_indicators_but_keeps_original_count(self):
        logs = []
        processor = MISPProcessor(
            self.settings(),
            misp_client=None,
            api_client=None,
            logger=logs.append,
            feed_adapter=self.adapter(),
        )

        prepared = processor.prepare_candidate("tlp:green", enriched_event())

        self.assertEqual("tlp green event", prepared.name)
        self.assertEqual(10, prepared.ioc_count)
        self.assertEqual(1, len(prepared.indicators))
        self.assertGreaterEqual(prepared.score, 60)
        self.assertEqual(
            {
                "attribute_count": 10,
                "max_attributes_per_event": 1000,
                "oversized": False,
                "oversized_event_action": "skip",
                "indicator_count": 10,
                "max_iocs_per_event": 1,
                "exported_indicator_count": 1,
                "iocs_truncated": True,
            },
            prepared.event["narrowcti_controls"],
        )
        self.assertIn(
            "MISP event exceeds IOC guardrail: event=event-1 "
            "iocs=10 limit=1 action=truncate",
            logs,
        )

    def test_process_query_counts_operational_outcomes(self):
        logs = []
        sleeps = []
        processed = []
        outcomes = ["drop", "skip", "ingest"]
        settings = self.settings()
        settings.max_events_per_run = 3
        candidates = [candidate(f"event-{index}") for index in range(1, 4)]
        processor = MISPProcessor(
            settings,
            misp_client=None,
            api_client=None,
            logger=logs.append,
            sleeper=sleeps.append,
            ingest_pause_seconds=7,
            feed_adapter=self.adapter(search_candidates=candidates),
        )

        def process_event_outcome(query, event, state):
            processed.append(event.external_id)
            return outcomes.pop(0)

        processor.process_event_outcome = process_event_outcome

        summary = processor.process_query("tlp:green", state="state")

        self.assertEqual(["event-1", "event-2", "event-3"], processed)
        self.assertEqual([7], sleeps)
        self.assertEqual(3, summary.reviewed)
        self.assertEqual(1, summary.dropped)
        self.assertEqual(1, summary.skipped)
        self.assertEqual(1, summary.ingested)
        self.assertEqual(3, summary.handled)
        self.assertIn(
            "MISP query summary: tlp:green reviewed=3 ingested=1 dropped=1 "
            "quarantined=0 skipped=1 errors=0 dry_run=0 available=3",
            logs,
        )

    def test_process_query_counts_adapter_guardrail_skips(self):
        logs = []
        adapter = self.adapter(search_candidates=[candidate("small-event")])
        adapter.last_search_available = 2
        adapter.last_search_skipped = 1
        processor = MISPProcessor(
            self.settings(),
            misp_client=None,
            api_client=None,
            logger=logs.append,
            feed_adapter=adapter,
        )
        processor.process_event_outcome = lambda query, event, state: "drop"

        summary = processor.process_query("type:OSINT", state="state")

        self.assertEqual(2, summary.available)
        self.assertEqual(1, summary.reviewed)
        self.assertEqual(1, summary.dropped)
        self.assertEqual(1, summary.skipped)
        self.assertEqual(2, summary.handled)
        self.assertIn(
            "MISP query summary: type:OSINT reviewed=1 ingested=0 dropped=1 "
            "quarantined=0 skipped=1 errors=0 dry_run=0 available=2",
            logs,
        )


    def test_process_event_skips_existing_state(self):
        records = []
        state = SimpleNamespace(
            has_event=lambda event_id: True,
            mark_event=lambda event_id: self.fail("state should not be marked"),
        )
        processor = MISPProcessor(
            self.settings(),
            misp_client=None,
            api_client=None,
            logger=lambda message: None,
            decision_audit=SimpleNamespace(record=records.append),
            feed_adapter=self.adapter(enriched=None),
        )

        processed = processor.process_event("tlp:green", candidate(), state)

        self.assertFalse(processed)
        self.assertEqual("skip", records[0].action)
        self.assertEqual("already processed", records[0].reason)
        self.assertEqual("misp:misp", records[0].source_key)

    def test_decision_metadata_prefers_enriched_provenance(self):
        candidate_ref = candidate(
            external_id="event-1",
            raw={
                "provenance": {
                    "collector": "misp",
                    "original_source": "Search Metadata",
                    "misp_event_id": "search-id",
                    "misp_event_uuid": "event-1",
                },
                "tags": ["tlp:green"],
            },
        )
        prepared = SimpleNamespace(
            event=enriched_event(),
            score_details={"final_score": 100, "source_confidence": 50},
        )

        metadata = decision_metadata(candidate_ref, prepared)

        self.assertEqual("misp", metadata["collector"])
        self.assertEqual("AlienVault", metadata["original_source"])
        self.assertEqual("12", metadata["misp_event_id"])
        self.assertEqual("event-1", metadata["misp_event_uuid"])
        self.assertEqual(["tlp:green"], metadata["tags"])
        self.assertFalse(metadata["guardrails"]["oversized"])
        self.assertEqual(100, metadata["scoring"]["final_score"])
        graph_evidence = metadata["graph_evidence"]
        self.assertEqual("v0.7.0-dev", graph_evidence["version"])
        self.assertEqual("misp:misp", graph_evidence["source_key"])
        self.assertEqual(3, graph_evidence["record_count"])
        self.assertEqual(1, graph_evidence["counts"]["marking"])
        self.assertTrue(
            any(
                record["entity_type"] == "source_identity"
                and record["value"] == "AlienVault"
                for record in graph_evidence["records"]
            )
        )

    def test_process_event_skips_when_all_artifacts_are_known(self):
        records = []
        marked = []
        logs = []
        state = SimpleNamespace(
            has_event=lambda event_id: False,
            mark_event=lambda event_id: marked.append(event_id),
        )
        artifact_dedup = SimpleNamespace(
            filter_new_indicators=lambda indicators: ([], len(indicators)),
            mark_indicators=lambda indicators: self.fail("artifacts should not be marked"),
        )

        processor = MISPProcessor(
            self.settings(),
            misp_client=None,
            api_client="api",
            logger=logs.append,
            exporter=lambda *args, **kwargs: self.fail("export should not be called"),
            decision_audit=SimpleNamespace(record=records.append),
            feed_adapter=self.adapter(enriched=candidate(raw=enriched_event())),
            artifact_dedup=artifact_dedup,
        )

        outcome = processor.process_event_outcome("tlp:green", candidate(), state)

        self.assertEqual("skip", outcome)
        self.assertEqual([], marked)
        self.assertEqual("skip", records[0].action)
        self.assertEqual("all indicators already known", records[0].reason)
        self.assertIn("MISP artifact dedup: tlp green event duplicates=1", logs)

    def test_process_event_drops_disallowed_tlp(self):
        records = []
        marked = []
        logs = []
        settings = self.settings()
        settings.allowed_tlp = ["green"]
        state = SimpleNamespace(
            has_event=lambda event_id: False,
            mark_event=lambda event_id: marked.append(event_id),
        )
        event = enriched_event(name="tlp red event")
        event["tags"] = ["tlp:red"]

        processor = MISPProcessor(
            settings,
            misp_client=None,
            api_client="api",
            logger=logs.append,
            exporter=lambda *args, **kwargs: self.fail("export should not be called"),
            decision_audit=SimpleNamespace(record=records.append),
            feed_adapter=self.adapter(enriched=candidate(raw=event)),
        )

        outcome = processor.process_event_outcome("tlp:any", candidate(), state)

        self.assertEqual("drop", outcome)
        self.assertEqual([], marked)
        self.assertEqual("drop", records[0].action)
        self.assertEqual("tlp not allowed: red", records[0].reason)
        self.assertIn("MISP drop: tlp red event reason=tlp not allowed: red", logs)

    def test_process_event_writes_quarantine_record(self):
        records = []
        queued = []
        marked = []
        logs = []
        state = SimpleNamespace(
            has_event=lambda event_id: False,
            mark_event=lambda event_id: marked.append(event_id),
        )
        event = enriched_event(name="old weak misp event", indicator_count=1)
        event["created"] = "2020-01-01T00:00:00Z"
        event["tags"] = []
        quarantine_repository = SimpleNamespace(
            add=lambda record: queued.append(record.to_dict()) or queued[-1]
        )

        processor = MISPProcessor(
            self.settings(),
            misp_client=None,
            api_client="api",
            logger=logs.append,
            exporter=lambda *args, **kwargs: self.fail("export should not be called"),
            decision_audit=SimpleNamespace(record=records.append),
            feed_adapter=self.adapter(enriched=candidate(raw=event)),
            quarantine_repository=quarantine_repository,
        )

        outcome = processor.process_event_outcome("unrelated", candidate(), state)

        self.assertEqual("quarantine", outcome)
        self.assertEqual([], marked)
        self.assertEqual("quarantine", records[0].action)
        self.assertEqual("low score", records[0].reason)
        self.assertEqual(1, len(queued))
        self.assertEqual("misp:misp", queued[0]["source_key"])
        self.assertEqual("event-1", queued[0]["external_id"])
        self.assertEqual("old weak misp event", queued[0]["title"])
        self.assertEqual("low score", queued[0]["reason"])
        self.assertEqual(1, queued[0]["indicator_count"])
        self.assertEqual("AlienVault", queued[0]["metadata"]["original_source"])
        self.assertEqual(
            "AlienVault",
            next(
                record["value"]
                for record in queued[0]["metadata"]["graph_evidence"]["records"]
                if record["entity_type"] == "source_identity"
            ),
        )
        self.assertTrue(
            any("MISP quarantine queued: old weak misp event" in log for log in logs)
        )

    def test_process_event_skips_disallowed_indicator_types(self):
        records = []
        marked = []
        logs = []
        settings = self.settings()
        settings.allowed_indicator_types = ["domain"]
        settings.max_iocs_per_event = 10
        state = SimpleNamespace(
            has_event=lambda event_id: False,
            mark_event=lambda event_id: marked.append(event_id),
        )
        event = enriched_event(name="email only event", indicator_count=0)
        event["indicators"] = [{"type": "email", "indicator": "user@example.com"}]

        processor = MISPProcessor(
            settings,
            misp_client=None,
            api_client="api",
            logger=logs.append,
            exporter=lambda *args, **kwargs: self.fail("export should not be called"),
            decision_audit=SimpleNamespace(record=records.append),
            feed_adapter=self.adapter(enriched=candidate(raw=event)),
        )

        outcome = processor.process_event_outcome("tlp:green", candidate(), state)

        self.assertEqual("skip", outcome)
        self.assertEqual([], marked)
        self.assertEqual("skip", records[0].action)
        self.assertEqual("all indicators disallowed by type", records[0].reason)
        self.assertIn(
            "MISP indicator type filter: email only event dropped=1 kept=0",
            logs,
        )

    def test_process_event_dry_run_records_decision_without_export_or_state(self):
        records = []
        marked = []
        logs = []
        settings = self.settings()
        settings.dry_run = True
        state = SimpleNamespace(
            has_event=lambda event_id: False,
            mark_event=lambda event_id: marked.append(event_id),
        )

        def exporter(*args, **kwargs):
            self.fail("exporter should not be called in dry-run")

        processor = MISPProcessor(
            settings,
            misp_client=None,
            api_client="api",
            logger=logs.append,
            exporter=exporter,
            decision_audit=SimpleNamespace(record=records.append),
            feed_adapter=self.adapter(enriched=candidate(raw=enriched_event())),
        )

        outcome = processor.process_event_outcome("tlp:green", candidate(), state)

        self.assertEqual("dry_run", outcome)
        self.assertEqual([], marked)
        self.assertEqual("dry_run", records[0].action)
        self.assertEqual("ok", records[0].reason)
        self.assertEqual("AlienVault", records[0].metadata["original_source"])
        self.assertEqual(50, records[0].metadata["scoring"]["source_confidence"])
        self.assertIn("MISP dry-run: tlp green event score=100 reason=ok", logs)

    def test_process_event_records_successful_ingest_and_marks_state(self):
        records = []
        marked = []
        export_calls = []
        state = SimpleNamespace(
            has_event=lambda event_id: False,
            mark_event=lambda event_id: marked.append(event_id),
        )

        def exporter(api_client, name, description, score, indicators, identity_name):
            export_calls.append(
                {
                    "api_client": api_client,
                    "name": name,
                    "description": description,
                    "score": score,
                    "indicators": indicators,
                    "identity_name": identity_name,
                }
            )
            return len(indicators)

        processor = MISPProcessor(
            self.settings(),
            misp_client=None,
            api_client="api",
            logger=lambda message: None,
            exporter=exporter,
            decision_audit=SimpleNamespace(record=records.append),
            feed_adapter=self.adapter(enriched=candidate(raw=enriched_event())),
        )

        processed = processor.process_event("tlp:green", candidate(), state)

        self.assertTrue(processed)
        self.assertEqual(["event-1"], marked)
        self.assertEqual("ingest", records[0].action)
        self.assertEqual("ok", records[0].reason)
        self.assertEqual("misp", records[0].metadata["collector"])
        self.assertEqual("AlienVault", records[0].metadata["original_source"])
        self.assertEqual(10, records[0].indicator_count)
        self.assertEqual(records[0].score, records[0].metadata["scoring"]["final_score"])
        self.assertEqual("tlp green event", export_calls[0]["name"])
        self.assertEqual("Test Connector", export_calls[0]["identity_name"])
        self.assertEqual(1, len(export_calls[0]["indicators"]))

    def test_process_event_does_not_mark_state_when_export_fails(self):
        records = []
        marked = []
        logs = []
        state = SimpleNamespace(
            has_event=lambda event_id: False,
            mark_event=lambda event_id: marked.append(event_id),
        )

        def exporter(*args, **kwargs):
            raise RuntimeError("OpenCTI unavailable")

        processor = MISPProcessor(
            self.settings(),
            misp_client=None,
            api_client="api",
            logger=logs.append,
            exporter=exporter,
            decision_audit=SimpleNamespace(record=records.append),
            feed_adapter=self.adapter(enriched=candidate(raw=enriched_event())),
        )

        processed = processor.process_event("tlp:green", candidate(), state)

        self.assertFalse(processed)
        self.assertEqual([], marked)
        self.assertEqual("error", records[0].action)
        self.assertIn("MISP ingest failed: tlp green event error=OpenCTI unavailable", logs)


if __name__ == "__main__":
    unittest.main()
