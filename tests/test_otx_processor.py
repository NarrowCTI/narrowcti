import unittest
from types import SimpleNamespace

from connectors.otx.models import PulseCandidate, QuerySummary
from connectors.otx.processor import OTXProcessor


class ProcessorTests(unittest.TestCase):
    def settings(self):
        return SimpleNamespace(
            max_iocs_per_pulse=1,
            quarantine_score_threshold=50,
            enable_quarantine=True,
            min_score_to_ingest=60,
            max_days_old=1095,
            min_score_for_old_pulse=80,
            max_days_hard_filter=0,
            connector_name="Test Connector",
            state_file="state.json",
            otx_queries=["lummac2", "stealc"],
        )

    def test_run_once_builds_state_repository_and_processes_queries(self):
        states = []
        processed_queries = []

        def state_repository_factory(path):
            state = SimpleNamespace(path=path)
            states.append(state)
            return state

        processor = OTXProcessor(
            self.settings(),
            otx_client=None,
            api_client=None,
            logger=None,
            state_repository_factory=state_repository_factory,
        )

        def process_query(query, state):
            processed_queries.append((query, state.path))
            return QuerySummary(query, 1, 0, 2)

        processor.process_query = process_query

        summaries = processor.run_once()

        self.assertEqual(["state.json"], [state.path for state in states])
        self.assertEqual(
            [("lummac2", "state.json"), ("stealc", "state.json")],
            processed_queries,
        )
        self.assertEqual(
            [
                QuerySummary("lummac2", 1, 0, 2),
                QuerySummary("stealc", 1, 0, 2),
            ],
            summaries,
        )

    def test_prepare_candidate_limits_exported_indicators_but_keeps_original_count(self):
        processor = OTXProcessor(
            self.settings(),
            otx_client=None,
            api_client=None,
            logger=None,
        )

        candidate = processor.prepare_candidate(
            "lummac2",
            {
                "name": "LummaC2 sample",
                "description": "description",
                "created": "2026-04-01T00:00:00Z",
                "indicators": [
                    {"type": "domain", "indicator": "one.example"},
                    {"type": "domain", "indicator": "two.example"},
                ],
            },
        )

        self.assertEqual("LummaC2 sample", candidate.name)
        self.assertEqual(2, candidate.ioc_count)
        self.assertEqual(1, len(candidate.indicators))
        self.assertGreaterEqual(candidate.score, 60)

    def test_process_query_respects_limits_and_sleeps_after_ingest(self):
        logs = []
        sleeps = []
        processed = []
        otx_client = SimpleNamespace(
            search_pulses=lambda query: [
                {"id": "pulse-1"},
                {"id": "pulse-2"},
                {"id": "pulse-3"},
            ]
        )
        settings = self.settings()
        settings.max_search_results_per_query = 3
        settings.max_pulses_per_query = 1

        processor = OTXProcessor(
            settings,
            otx_client=otx_client,
            api_client=None,
            logger=logs.append,
            sleeper=sleeps.append,
            ingest_pause_seconds=7,
        )
        processor.process_pulse = lambda query, pulse, state: processed.append(
            pulse["id"]
        ) or True

        summary = processor.process_query("lummac2", state="state")

        self.assertEqual(["pulse-1"], processed)
        self.assertEqual([7], sleeps)
        self.assertEqual(QuerySummary("lummac2", 1, 1, 3), summary)
        self.assertIn(
            "Query summary: lummac2 reviewed=1 ingested=1 available=3",
            logs,
        )

    def test_process_pulse_skips_missing_id(self):
        logs = []
        otx_client = SimpleNamespace(
            enrich_pulse=lambda pulse_id: self.fail("enrich should not be called")
        )
        state = SimpleNamespace(
            has_pulse=lambda pulse_id: self.fail("state should not be queried")
        )
        processor = OTXProcessor(
            self.settings(),
            otx_client=otx_client,
            api_client=None,
            logger=logs.append,
        )

        processed = processor.process_pulse("lummac2", {"name": "No ID"}, state)

        self.assertFalse(processed)
        self.assertIn("Skip pulse without id: No ID", logs)

    def test_process_pulse_skips_failed_enrich(self):
        logs = []
        otx_client = SimpleNamespace(enrich_pulse=lambda pulse_id: None)
        state = SimpleNamespace(
            has_pulse=lambda pulse_id: False,
            mark_pulse=lambda pulse_id: self.fail("state should not be marked"),
        )
        processor = OTXProcessor(
            self.settings(),
            otx_client=otx_client,
            api_client=None,
            logger=logs.append,
        )

        processed = processor.process_pulse(
            "lummac2",
            {"id": "pulse-1", "name": "Search result"},
            state,
        )

        self.assertFalse(processed)
        self.assertIn("Skip enrich failed: Search result", logs)

    def test_evaluate_candidate_policy_logs_drop(self):
        logs = []
        processor = OTXProcessor(
            self.settings(),
            otx_client=None,
            api_client=None,
            logger=logs.append,
        )
        candidate = PulseCandidate(
            pulse={"created": "2026-04-01T00:00:00Z"},
            name="Low score pulse",
            description="description",
            indicators=[],
            ioc_count=0,
            age=30,
            score=55,
        )

        should_ingest_candidate, reason = processor.evaluate_candidate_policy(
            candidate
        )

        self.assertFalse(should_ingest_candidate)
        self.assertEqual("below minimum score", reason)
        self.assertIn(
            "Drop: Low score pulse score=55 reason=below minimum score",
            logs,
        )

    def test_process_pulse_uses_exporter_and_marks_state_after_success(self):
        logs = []
        marked = []
        export_calls = []
        otx_client = SimpleNamespace(
            enrich_pulse=lambda pulse_id: {
                "name": "LummaC2 fresh",
                "description": "description",
                "created": "2026-04-01T00:00:00Z",
                "indicators": [{"type": "domain", "indicator": "one.example"}],
            }
        )
        state = SimpleNamespace(
            has_pulse=lambda pulse_id: False,
            mark_pulse=lambda pulse_id: marked.append(pulse_id),
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

        processor = OTXProcessor(
            self.settings(),
            otx_client=otx_client,
            api_client="api",
            logger=logs.append,
            exporter=exporter,
        )

        processed = processor.process_pulse(
            "lummac2",
            {"id": "pulse-1", "name": "Search result"},
            state,
        )

        self.assertTrue(processed)
        self.assertEqual(["pulse-1"], marked)
        self.assertEqual("LummaC2 fresh", export_calls[0]["name"])
        self.assertEqual("Test Connector", export_calls[0]["identity_name"])
        self.assertIn("Ingest complete: LummaC2 fresh indicators=1", logs)

    def test_process_pulse_does_not_mark_state_when_export_fails(self):
        logs = []
        marked = []
        otx_client = SimpleNamespace(
            enrich_pulse=lambda pulse_id: {
                "name": "LummaC2 fresh",
                "description": "description",
                "created": "2026-04-01T00:00:00Z",
                "indicators": [{"type": "domain", "indicator": "one.example"}],
            }
        )
        state = SimpleNamespace(
            has_pulse=lambda pulse_id: False,
            mark_pulse=lambda pulse_id: marked.append(pulse_id),
        )

        def exporter(*args, **kwargs):
            raise RuntimeError("OpenCTI unavailable")

        processor = OTXProcessor(
            self.settings(),
            otx_client=otx_client,
            api_client="api",
            logger=logs.append,
            exporter=exporter,
        )

        processed = processor.process_pulse(
            "lummac2",
            {"id": "pulse-1", "name": "Search result"},
            state,
        )

        self.assertFalse(processed)
        self.assertEqual([], marked)
        self.assertIn(
            "Ingest failed: LummaC2 fresh error=OpenCTI unavailable",
            logs,
        )


if __name__ == "__main__":
    unittest.main()
