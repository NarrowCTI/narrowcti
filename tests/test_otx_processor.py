import unittest
from types import SimpleNamespace

from connectors.otx.models import PulseCandidate, QuerySummary
from connectors.otx.processor import OTXProcessor, decision_metadata


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
            allowed_tlp=[],
            allowed_indicator_types=[],
            connector_name="Test Connector",
            state_file="state.json",
            decision_audit_file="",
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
        processor.process_pulse_outcome = lambda query, pulse, state: processed.append(
            pulse.external_id
        ) or "ingest"

        summary = processor.process_query("lummac2", state="state")

        self.assertEqual(["pulse-1"], processed)
        self.assertEqual([7], sleeps)
        self.assertEqual(QuerySummary("lummac2", 1, 1, 3), summary)
        self.assertIn(
            "Query summary: lummac2 reviewed=1 ingested=1 dropped=0 "
            "quarantined=0 skipped=0 errors=0 dry_run=0 available=3",
            logs,
        )

    def test_process_query_counts_operational_outcomes(self):
        logs = []
        sleeps = []
        processed = []
        outcomes = ["drop", "quarantine", "skip", "error", "ingest"]
        otx_client = SimpleNamespace(
            search_pulses=lambda query: [
                {"id": "pulse-1"},
                {"id": "pulse-2"},
                {"id": "pulse-3"},
                {"id": "pulse-4"},
                {"id": "pulse-5"},
            ]
        )
        settings = self.settings()
        settings.max_search_results_per_query = 5
        settings.max_pulses_per_query = 5

        processor = OTXProcessor(
            settings,
            otx_client=otx_client,
            api_client=None,
            logger=logs.append,
            sleeper=sleeps.append,
            ingest_pause_seconds=7,
        )

        def process_pulse_outcome(query, pulse, state):
            processed.append(pulse.external_id)
            return outcomes.pop(0)

        processor.process_pulse_outcome = process_pulse_outcome

        summary = processor.process_query("stealc", state="state")

        self.assertEqual(
            ["pulse-1", "pulse-2", "pulse-3", "pulse-4", "pulse-5"],
            processed,
        )
        self.assertEqual([7], sleeps)
        self.assertEqual(
            QuerySummary(
                query="stealc",
                reviewed=5,
                ingested=1,
                available=5,
                dropped=1,
                quarantined=1,
                skipped=1,
                errors=1,
            ),
            summary,
        )
        self.assertEqual(5, summary.handled)

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

    def test_process_pulse_records_policy_decision(self):
        records = []
        otx_client = SimpleNamespace(
            enrich_pulse=lambda pulse_id: {
                "name": "Low score pulse",
                "description": "description",
                "created": "2026-04-01T00:00:00Z",
                "indicators": [],
            }
        )
        state = SimpleNamespace(
            has_pulse=lambda pulse_id: False,
            mark_pulse=lambda pulse_id: self.fail("state should not be marked"),
        )
        settings = self.settings()
        settings.min_score_to_ingest = 60

        processor = OTXProcessor(
            settings,
            otx_client=otx_client,
            api_client=None,
            logger=lambda message: None,
            decision_audit=SimpleNamespace(record=records.append),
        )

        processed = processor.process_pulse(
            "unrelated query",
            {"id": "pulse-1", "name": "Search result"},
            state,
        )

        self.assertFalse(processed)
        self.assertEqual("drop", records[0].action)
        self.assertEqual("below minimum score", records[0].reason)
        self.assertEqual("alienvault:otx", records[0].source_key)
        self.assertEqual("pulse-1", records[0].external_id)
        self.assertEqual("Low score pulse", records[0].title)
        self.assertEqual(50, records[0].metadata["scoring"]["source_confidence"])

    def test_process_pulse_records_otx_entity_metadata(self):
        records = []
        otx_client = SimpleNamespace(
            enrich_pulse=lambda pulse_id: {
                "id": pulse_id,
                "name": "LummaC2 actor pulse",
                "description": "description",
                "created": "2026-04-01T00:00:00Z",
                "modified": "2026-04-03T00:00:00Z",
                "author_name": "AlienVault Research",
                "upvotes_count": 7,
                "downvotes_count": 1,
                "adversary": "APT Example",
                "malware_families": ["LummaC2"],
                "attack_ids": ["T1059"],
                "cves": ["CVE-2024-12345"],
                "industries": ["Finance"],
                "targeted_countries": ["BR"],
                "TLP": "tlp:green",
                "references": ["https://example.com/report"],
                "indicators": [
                    {
                        "id": "indicator-yara-1",
                        "type": "YARA",
                        "indicator": "rule SuspiciousRule { condition: true }",
                        "description": "Suspicious YARA rule",
                    }
                ],
            }
        )
        state = SimpleNamespace(
            has_pulse=lambda pulse_id: False,
            mark_pulse=lambda pulse_id: self.fail("state should not be marked"),
        )
        settings = self.settings()
        settings.min_score_to_ingest = 60
        mitre_resolver = SimpleNamespace(
            resolve=lambda attack_ids: [
                {
                    "attack_id": attack_ids[0],
                    "found": True,
                    "name": "Command and Scripting Interpreter",
                    "tactics": ["execution"],
                }
            ]
        )

        processor = OTXProcessor(
            settings,
            otx_client=otx_client,
            api_client=None,
            logger=lambda message: None,
            decision_audit=SimpleNamespace(record=records.append),
            mitre_resolver=mitre_resolver,
        )

        processed = processor.process_pulse(
            "unrelated query",
            {"id": "pulse-1", "name": "Search result"},
            state,
        )

        self.assertFalse(processed)
        entities = records[0].metadata["otx_entities"]
        self.assertEqual(["APT Example"], entities["adversaries"])
        self.assertEqual(["LummaC2"], entities["malware_families"])
        self.assertEqual(["T1059"], entities["attack_ids"])
        self.assertEqual(["CVE-2024-12345"], entities["vulnerabilities"])
        self.assertEqual(["Finance"], entities["industries"])
        self.assertEqual(["BR"], entities["targeted_countries"])
        self.assertEqual(["AlienVault Research"], entities["authors"])
        self.assertEqual("2026-04-03T00:00:00Z", entities["lifecycle"]["modified"])
        self.assertEqual(7, entities["vote_summary"]["upvotes"])
        self.assertEqual(["green"], entities["tlp"])
        mitre_attack = records[0].metadata["mitre_attack"]
        self.assertTrue(mitre_attack["available"])
        self.assertEqual("T1059", mitre_attack["resolved"][0]["attack_id"])
        self.assertEqual(
            "Command and Scripting Interpreter",
            mitre_attack["resolved"][0]["name"],
        )
        graph_evidence = records[0].metadata["graph_evidence"]
        self.assertEqual("v0.7.0-dev", graph_evidence["version"])
        self.assertEqual("alienvault:otx", graph_evidence["source_key"])
        self.assertEqual(2, graph_evidence["counts"]["attack_pattern"])
        self.assertEqual(1, graph_evidence["counts"]["vulnerability"])
        self.assertEqual(1, graph_evidence["counts"]["detection_rule"])
        self.assertTrue(
            any(
                record["entity_type"] == "threat_actor"
                and record["value"] == "APT Example"
                and record["stix_object_type"] == "threat-actor"
                for record in graph_evidence["records"]
            )
        )
        self.assertTrue(
            any(
                record["entity_type"] == "vulnerability"
                and record["value"] == "CVE-2024-12345"
                and record["stix_object_type"] == "vulnerability"
                for record in graph_evidence["records"]
            )
        )
        self.assertTrue(
            any(
                record["entity_type"] == "attack_tactic"
                and record["value"] == "execution"
                for record in graph_evidence["records"]
            )
        )
        self.assertTrue(
            any(
                record["entity_type"] == "detection_rule"
                and record["value"] == "Suspicious YARA rule"
                and record["attributes"]["pattern_type"] == "yara"
                for record in graph_evidence["records"]
            )
        )
        graph_candidates = records[0].metadata["graph_candidates"]
        self.assertEqual("v0.7.0-dev", graph_candidates["version"])
        self.assertEqual("pulse-1", graph_candidates["external_id"])
        self.assertEqual(
            graph_evidence["record_count"],
            graph_candidates["candidate_count"],
        )
        self.assertEqual(2, graph_candidates["counts"]["attack_pattern"])
        self.assertEqual(1, graph_candidates["counts"]["vulnerability"])
        self.assertEqual(1, graph_candidates["counts"]["detection_rule"])
        self.assertTrue(
            any(
                candidate["entity_type"] == "threat_actor"
                and candidate["value"] == "APT Example"
                and candidate["relationship_type"] == "attributed-to"
                for candidate in graph_candidates["candidates"]
            )
        )
        self.assertTrue(
            any(
                candidate["entity_type"] == "detection_rule"
                and candidate["relationship_type"] == "detects"
                and candidate["attributes"]["pattern"]
                == "rule SuspiciousRule { condition: true }"
                for candidate in graph_candidates["candidates"]
            )
        )
        graph_policy = records[0].metadata["graph_candidate_policy"]
        self.assertEqual(
            graph_candidates["candidate_count"],
            graph_policy["candidate_count"],
        )
        self.assertEqual(
            graph_candidates["candidate_count"],
            graph_policy["accepted_count"],
        )
        self.assertEqual(0, graph_policy["held_count"])
        graph_plan = records[0].metadata["graph_export_plan"]
        self.assertEqual("audit", graph_plan["mode"])
        self.assertEqual("audit-only", graph_plan["status"])
        self.assertEqual(graph_policy["accepted_count"], graph_plan["accepted_count"])
        self.assertEqual(0, graph_plan["would_create_object_count"])
        contextual_scoring = records[0].metadata["contextual_scoring"]
        self.assertEqual("dry-run", contextual_scoring["mode"])
        self.assertFalse(contextual_scoring["applied_to_decision"])
        self.assertEqual(
            graph_policy["accepted_count"],
            contextual_scoring["accepted_candidate_count"],
        )
        self.assertGreater(contextual_scoring["contextual_score"], 0)
        self.assertIn("ttp", contextual_scoring["category_counts"])
        graph_preview = records[0].metadata["graph_stix_preview"]
        self.assertEqual("preview", graph_preview["status"])
        self.assertFalse(graph_preview["export_enabled"])
        self.assertEqual("bundle", graph_preview["bundle_type"])
        self.assertEqual(
            graph_policy["accepted_count"],
            graph_preview["accepted_candidate_count"],
        )
        self.assertGreater(graph_preview["graph_object_count"], 0)
        self.assertGreater(graph_preview["graph_relationship_count"], 0)

    def test_decision_metadata_uses_graph_dedup_known_keys(self):
        candidate = SimpleNamespace(
            pulse={
                "id": "pulse-1",
                "name": "Technique pulse",
                "attack_ids": ["T1059"],
                "indicators": [],
            },
            name="Technique pulse",
            score_details={},
        )
        mitre_resolver = SimpleNamespace(
            resolve=lambda attack_ids: [
                {
                    "attack_id": attack_ids[0],
                    "found": True,
                    "name": "Command and Scripting Interpreter",
                    "tactics": ["execution"],
                }
            ]
        )

        metadata = decision_metadata(
            candidate,
            mitre_resolver=mitre_resolver,
            source_key="alienvault:otx",
            external_id="pulse-1",
            title="Technique pulse",
            graph_export_mode="dry-run",
            graph_deduplication_index=FirstActionEntityKnownIndex(),
        )

        graph_plan = metadata["graph_export_plan"]
        self.assertGreaterEqual(graph_plan["deduplicated_entity_count"], 1)
        self.assertLess(
            graph_plan["would_create_object_count"],
            graph_plan["accepted_count"],
        )
        self.assertGreaterEqual(graph_plan["would_create_relationship_count"], 1)
        self.assertIn("graph_export_plan_known_keys", metadata)
        self.assertEqual(
            "internal--1",
            metadata["graph_export_plan_lookup_matches"][0]["match"]["opencti_id"],
        )

    def test_process_pulse_writes_quarantine_record(self):
        records = []
        queued = []
        marked = []
        logs = []
        otx_client = SimpleNamespace(
            enrich_pulse=lambda pulse_id: {
                "id": pulse_id,
                "name": "Old weak pulse",
                "description": "needs analyst review",
                "created": "2020-01-01T00:00:00Z",
                "indicators": [{"type": "domain", "indicator": "old.example"}],
            }
        )
        state = SimpleNamespace(
            has_pulse=lambda pulse_id: False,
            mark_pulse=lambda pulse_id: marked.append(pulse_id),
        )
        quarantine_repository = SimpleNamespace(
            add=lambda record: queued.append(record.to_dict()) or queued[-1]
        )

        processor = OTXProcessor(
            self.settings(),
            otx_client=otx_client,
            api_client="api",
            logger=logs.append,
            exporter=lambda *args, **kwargs: self.fail("export should not be called"),
            decision_audit=SimpleNamespace(record=records.append),
            quarantine_repository=quarantine_repository,
        )

        outcome = processor.process_pulse_outcome(
            "unrelated",
            {"id": "pulse-1", "name": "Search result"},
            state,
        )

        self.assertEqual("quarantine", outcome)
        self.assertEqual([], marked)
        self.assertEqual("quarantine", records[0].action)
        self.assertEqual("low score", records[0].reason)
        self.assertEqual(1, len(queued))
        self.assertEqual("alienvault:otx", queued[0]["source_key"])
        self.assertEqual("pulse-1", queued[0]["external_id"])
        self.assertEqual("Old weak pulse", queued[0]["title"])
        self.assertEqual("low score", queued[0]["reason"])
        self.assertEqual(1, queued[0]["indicator_count"])
        self.assertEqual("domain", queued[0]["indicators"][0]["type"])
        self.assertEqual([], queued[0]["metadata"]["otx_entities"]["attack_ids"])
        self.assertEqual(1, queued[0]["metadata"]["graph_evidence"]["record_count"])
        self.assertEqual(
            1,
            queued[0]["metadata"]["graph_evidence"]["counts"]["observable"],
        )
        self.assertEqual(
            1,
            queued[0]["metadata"]["graph_candidates"]["candidate_count"],
        )
        self.assertTrue(any("Quarantine queued: Old weak pulse" in log for log in logs))

    def test_process_pulse_records_missing_mitre_cache_evidence(self):
        records = []
        otx_client = SimpleNamespace(
            enrich_pulse=lambda pulse_id: {
                "id": pulse_id,
                "name": "Technique pulse",
                "description": "description",
                "created": "2026-04-01T00:00:00Z",
                "attack_ids": ["T1059"],
                "indicators": [],
            }
        )
        state = SimpleNamespace(
            has_pulse=lambda pulse_id: False,
            mark_pulse=lambda pulse_id: self.fail("state should not be marked"),
        )
        settings = self.settings()
        settings.min_score_to_ingest = 60

        processor = OTXProcessor(
            settings,
            otx_client=otx_client,
            api_client=None,
            logger=lambda message: None,
            decision_audit=SimpleNamespace(record=records.append),
        )

        processed = processor.process_pulse(
            "unrelated query",
            {"id": "pulse-1", "name": "Search result"},
            state,
        )

        self.assertFalse(processed)
        self.assertEqual(["T1059"], records[0].metadata["otx_entities"]["attack_ids"])
        self.assertFalse(records[0].metadata["mitre_attack"]["available"])
        self.assertEqual(
            "mitre cache unavailable",
            records[0].metadata["mitre_attack"]["reason"],
        )

    def test_process_pulse_drops_disallowed_tlp(self):
        records = []
        marked = []
        logs = []
        otx_client = SimpleNamespace(
            enrich_pulse=lambda pulse_id: {
                "id": pulse_id,
                "name": "TLP red pulse",
                "description": "restricted",
                "created": "2099-01-01T00:00:00Z",
                "tags": ["tlp:red"],
                "indicators": [{"type": "domain", "indicator": "red.example"}],
            }
        )
        state = SimpleNamespace(
            has_pulse=lambda pulse_id: False,
            mark_pulse=lambda pulse_id: marked.append(pulse_id),
        )
        settings = self.settings()
        settings.allowed_tlp = ["green"]
        processor = OTXProcessor(
            settings,
            otx_client=otx_client,
            api_client=None,
            logger=logs.append,
            exporter=lambda *args, **kwargs: self.fail("export should not be called"),
            decision_audit=SimpleNamespace(record=records.append),
        )

        processed = processor.process_pulse(
            "lummac2",
            {"id": "pulse-1", "name": "Search result"},
            state,
        )

        self.assertFalse(processed)
        self.assertEqual([], marked)
        self.assertEqual("drop", records[0].action)
        self.assertEqual("tlp not allowed: red", records[0].reason)
        self.assertIn("Drop: TLP red pulse reason=tlp not allowed: red", logs)

    def test_process_pulse_skips_disallowed_indicator_types(self):
        records = []
        marked = []
        logs = []
        otx_client = SimpleNamespace(
            enrich_pulse=lambda pulse_id: {
                "id": pulse_id,
                "name": "LummaC2 email pulse",
                "description": "email only",
                "created": "2099-01-01T00:00:00Z",
                "indicators": [{"type": "email", "indicator": "user@example.com"}],
            }
        )
        state = SimpleNamespace(
            has_pulse=lambda pulse_id: False,
            mark_pulse=lambda pulse_id: marked.append(pulse_id),
        )
        settings = self.settings()
        settings.allowed_indicator_types = ["domain"]
        processor = OTXProcessor(
            settings,
            otx_client=otx_client,
            api_client=None,
            logger=logs.append,
            exporter=lambda *args, **kwargs: self.fail("export should not be called"),
            decision_audit=SimpleNamespace(record=records.append),
        )

        processed = processor.process_pulse(
            "lummac2",
            {"id": "pulse-1", "name": "Search result"},
            state,
        )

        self.assertFalse(processed)
        self.assertEqual([], marked)
        self.assertEqual("skip", records[0].action)
        self.assertEqual("all indicators disallowed by type", records[0].reason)
        self.assertIn(
            "Indicator type filter: LummaC2 email pulse dropped=1 kept=0",
            logs,
        )

    def test_process_pulse_records_successful_ingest(self):
        records = []
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

        processor = OTXProcessor(
            self.settings(),
            otx_client=otx_client,
            api_client="api",
            logger=lambda message: None,
            exporter=lambda *args, **kwargs: 1,
            decision_audit=SimpleNamespace(record=records.append),
        )

        processed = processor.process_pulse(
            "lummac2",
            {"id": "pulse-1", "name": "Search result"},
            state,
        )

        self.assertTrue(processed)
        self.assertEqual(["pulse-1"], marked)
        self.assertEqual("ingest", records[0].action)
        self.assertEqual("ok", records[0].reason)
        self.assertEqual(1, records[0].indicator_count)
        self.assertEqual(records[0].score, records[0].metadata["scoring"]["final_score"])

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


    def test_process_pulse_skips_when_all_artifacts_are_known(self):
        records = []
        marked = []
        logs = []
        otx_client = SimpleNamespace(
            enrich_pulse=lambda pulse_id: {
                "name": "LummaC2 known pulse",
                "description": "description",
                "created": "2026-04-01T00:00:00Z",
                "indicators": [{"type": "domain", "indicator": "known.example"}],
            }
        )
        state = SimpleNamespace(
            has_pulse=lambda pulse_id: False,
            mark_pulse=lambda pulse_id: marked.append(pulse_id),
        )
        artifact_dedup = SimpleNamespace(
            filter_new_indicators=lambda indicators: ([], len(indicators)),
            mark_indicators=lambda indicators: self.fail("artifacts should not be marked"),
        )

        processor = OTXProcessor(
            self.settings(),
            otx_client=otx_client,
            api_client="api",
            logger=logs.append,
            exporter=lambda *args, **kwargs: self.fail("export should not be called"),
            decision_audit=SimpleNamespace(record=records.append),
            artifact_dedup=artifact_dedup,
        )

        processed = processor.process_pulse(
            "lummac2",
            {"id": "pulse-1", "name": "Search result"},
            state,
        )

        self.assertFalse(processed)
        self.assertEqual([], marked)
        self.assertEqual("skip", records[0].action)
        self.assertEqual("all indicators already known", records[0].reason)
        self.assertIn("Artifact dedup: LummaC2 known pulse duplicates=1", logs)
    def test_process_pulse_dry_run_records_decision_without_export_or_state(self):
        records = []
        marked = []
        logs = []
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
        settings = self.settings()
        settings.dry_run = True

        processor = OTXProcessor(
            settings,
            otx_client=otx_client,
            api_client="api",
            logger=logs.append,
            exporter=lambda *args, **kwargs: self.fail("export should not be called"),
            decision_audit=SimpleNamespace(record=records.append),
        )

        processed = processor.process_pulse(
            "lummac2",
            {"id": "pulse-1", "name": "Search result"},
            state,
        )

        self.assertFalse(processed)
        self.assertEqual([], marked)
        self.assertEqual("dry_run", records[0].action)
        self.assertEqual("ok", records[0].reason)
        self.assertIn("scoring", records[0].metadata)
        self.assertIn("Dry-run: LummaC2 fresh", logs[1])


class FirstActionEntityKnownIndex:
    def known_keys_for_plan(self, plan):
        return {
            "entity_keys": [plan["actions"][0]["deduplication"]["entity_key"]],
            "relationship_keys": [],
            "matches": [
                {
                    "entity_key": plan["actions"][0]["deduplication"]["entity_key"],
                    "stix_object_type": "attack-pattern",
                    "value": "T1059",
                    "match": {
                        "opencti_id": "internal--1",
                        "standard_id": "attack-pattern--1111",
                        "entity_type": "Attack-Pattern",
                        "name": "Command and Scripting Interpreter",
                    },
                }
            ],
        }


if __name__ == "__main__":
    unittest.main()
