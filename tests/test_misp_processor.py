import ipaddress
import unittest
from types import SimpleNamespace

from connectors.misp.processor import (
    MISPProcessor,
    decision_metadata,
    graph_candidate_policy_from_settings,
)
from core.feed_contract import FeedCandidate, FeedRunSummary, FeedSource
from core.ip_asn_enrichment import IPASNRecord, OfflineIPASNEnricher


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

    def test_export_mode_uses_safe_graph_policy_defaults(self):
        settings = SimpleNamespace(
            graph_export_mode="export",
            graph_min_entity_confidence=0,
            graph_min_relationship_confidence=0,
            graph_require_relationship_provenance=False,
            graph_allowed_entity_types=[],
            graph_allowed_stix_object_types=[],
        )

        policy = graph_candidate_policy_from_settings(settings)

        self.assertIn("infrastructure", policy["allowed_entity_types"])
        self.assertIn("autonomous_system", policy["allowed_entity_types"])
        self.assertIn("target_sector", policy["allowed_entity_types"])
        self.assertNotIn("source_identity", policy["allowed_entity_types"])
        self.assertNotIn("collector", policy["allowed_entity_types"])
        self.assertIn("identity", policy["allowed_stix_object_types"])
        self.assertNotIn("marking-definition", policy["allowed_stix_object_types"])

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

        metadata = decision_metadata(
            candidate_ref,
            prepared,
            graph_candidate_policy={
                "min_entity_confidence": 50,
                "min_relationship_confidence": 50,
                "allowed_entity_types": ["source_identity", "collector"],
                "require_relationship_provenance": True,
            },
        )

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
        graph_candidates = metadata["graph_candidates"]
        self.assertEqual("v0.7.0-dev", graph_candidates["version"])
        self.assertEqual("event-1", graph_candidates["external_id"])
        self.assertEqual(3, graph_candidates["candidate_count"])
        self.assertEqual(1, graph_candidates["counts"]["marking"])
        self.assertTrue(
            any(
                candidate["entity_type"] == "source_identity"
                and candidate["value"] == "AlienVault"
                and candidate["stix_object_type"] == "identity"
                for candidate in graph_candidates["candidates"]
            )
        )
        graph_policy = metadata["graph_candidate_policy"]
        self.assertEqual(3, graph_policy["candidate_count"])
        self.assertEqual(2, graph_policy["accepted_count"])
        self.assertEqual(1, graph_policy["held_count"])
        self.assertEqual({"entity_type_not_allowed": 1}, graph_policy["held_reasons"])
        graph_plan = metadata["graph_export_plan"]
        self.assertEqual("audit", graph_plan["mode"])
        self.assertEqual("audit-only", graph_plan["status"])
        self.assertEqual(2, graph_plan["accepted_count"])
        self.assertEqual(1, graph_plan["held_count"])
        contextual_scoring = metadata["contextual_scoring"]
        self.assertEqual("dry-run", contextual_scoring["mode"])
        self.assertFalse(contextual_scoring["applied_to_decision"])
        self.assertEqual(2, contextual_scoring["accepted_candidate_count"])
        self.assertGreaterEqual(contextual_scoring["contextual_score"], 100)
        self.assertIn("author", contextual_scoring["category_counts"])
        graph_preview = metadata["graph_stix_preview"]
        self.assertEqual("preview", graph_preview["status"])
        self.assertFalse(graph_preview["export_enabled"])
        self.assertEqual("bundle", graph_preview["bundle_type"])
        self.assertEqual(2, graph_preview["accepted_candidate_count"])
        self.assertGreaterEqual(graph_preview["graph_object_count"], 1)
        self.assertGreaterEqual(graph_preview["bundle_object_count"], 2)

    def test_decision_metadata_extracts_misp_galaxies(self):
        candidate_ref = candidate(external_id="event-1", raw={"tags": ["tlp:green"]})
        event = enriched_event()
        event["Galaxy"] = [
            {
                "type": "mitre-attack-pattern",
                "name": "MITRE ATT&CK",
                "GalaxyCluster": [
                    {
                        "type": "mitre-attack-pattern",
                        "value": "Command and Scripting Interpreter - T1059",
                        "uuid": "cluster-attack",
                        "tag_name": 'misp-galaxy:mitre-attack-pattern="T1059"',
                        "meta": {
                            "external_id": ["T1059"],
                            "refs": ["https://attack.mitre.org/techniques/T1059/"],
                        },
                    }
                ],
            },
            {
                "type": "threat-actor",
                "name": "Threat Actor",
                "GalaxyCluster": [
                    {
                        "type": "threat-actor",
                        "value": "APT Example",
                        "uuid": "cluster-actor",
                        "meta": {
                            "synonyms": ["Example Group"],
                            "targeted-sector": ["Activists"],
                        },
                    }
                ],
            },
        ]
        event["Object"] = [
            {
                "name": "victimology",
                "GalaxyCluster": [
                    {
                        "type": "sector",
                        "value": "Finance",
                        "uuid": "cluster-sector",
                    }
                ],
            }
        ]
        event["Attribute"] = {
            "type": "md5",
            "value": "a" * 32,
            "GalaxyCluster": {
                "type": "malware",
                "value": "LummaC2",
                "uuid": "cluster-malware",
            },
        }
        prepared = SimpleNamespace(event=event, score_details={})

        metadata = decision_metadata(candidate_ref, prepared)

        self.assertEqual(4, len(metadata["misp_galaxies"]))
        graph_evidence = metadata["graph_evidence"]
        self.assertEqual(1, graph_evidence["counts"]["attack_pattern"])
        self.assertEqual(1, graph_evidence["counts"]["threat_actor"])
        self.assertEqual(1, graph_evidence["counts"]["malware"])
        self.assertEqual(2, graph_evidence["counts"]["target_sector"])
        graph_candidates = metadata["graph_candidates"]
        self.assertTrue(
            any(
                candidate["entity_type"] == "attack_pattern"
                and candidate["value"] == "T1059"
                and candidate["name"] == "Command and Scripting Interpreter - T1059"
                for candidate in graph_candidates["candidates"]
            )
        )
        self.assertTrue(
            any(
                candidate["entity_type"] == "target_sector"
                and candidate["value"] == "Finance"
                and candidate["source_field"] == "Object[0].GalaxyCluster"
                for candidate in graph_candidates["candidates"]
            )
        )
        self.assertTrue(
            any(
                candidate["entity_type"] == "target_sector"
                and candidate["value"] == "Activists"
                and candidate["source_field"] == "Galaxy.meta.targeted-sector"
                and candidate["attributes"]["parent_cluster_value"] == "APT Example"
                for candidate in graph_candidates["candidates"]
            )
        )

    def test_decision_metadata_extracts_misp_operational_meta_candidates(self):
        candidate_ref = candidate(external_id="event-1", raw={"tags": ["tlp:green"]})
        event = enriched_event()
        event["Galaxy"] = {
            "type": "campaign",
            "name": "Campaign",
            "GalaxyCluster": {
                "type": "campaign",
                "value": "Operation Example",
                "uuid": "cluster-campaign",
                "meta": {
                    "c2-channel": ["Telegram"],
                    "objective": ["Credential theft"],
                    "incident-name": ["Observed phishing wave"],
                    "security-platform": ["Microsoft Defender for Endpoint"],
                    "targeted-system": ["Windows Workstations"],
                },
            },
        }
        prepared = SimpleNamespace(event=event, score_details={})

        metadata = decision_metadata(candidate_ref, prepared)

        graph_evidence = metadata["graph_evidence"]
        self.assertEqual(1, graph_evidence["counts"]["campaign"])
        self.assertEqual(1, graph_evidence["counts"]["channel"])
        self.assertEqual(1, graph_evidence["counts"]["event"])
        self.assertEqual(1, graph_evidence["counts"]["narrative"])
        self.assertEqual(1, graph_evidence["counts"]["security_platform"])
        self.assertEqual(1, graph_evidence["counts"]["target_system"])
        graph_candidates = metadata["graph_candidates"]
        self.assertTrue(
            any(
                candidate["entity_type"] == "channel"
                and candidate["value"] == "Telegram"
                and candidate["stix_object_type"] == "channel"
                and candidate["attributes"]["channel_types"] == ["c2"]
                for candidate in graph_candidates["candidates"]
            )
        )
        self.assertTrue(
            any(
                candidate["entity_type"] == "security_platform"
                and candidate["value"] == "Microsoft Defender for Endpoint"
                and candidate["stix_object_type"] == "security-platform"
                and candidate["attributes"]["security_platform_type"]
                == "Detection Platform"
                for candidate in graph_candidates["candidates"]
            )
        )
        self.assertTrue(
            any(
                candidate["entity_type"] == "target_system"
                and candidate["value"] == "Windows Workstations"
                and candidate["stix_object_type"] == "identity"
                for candidate in graph_candidates["candidates"]
            )
        )

    def test_decision_metadata_extracts_misp_vulnerabilities(self):
        candidate_ref = candidate(
            external_id="event-1",
            raw={"tags": ["tlp:green", "cve:CVE-2024-12345"]},
        )
        event = enriched_event(name="Exploit chain for CVE-2022-1111")
        event["tags"] = ["tlp:green", "cve:CVE-2024-12345"]
        event["Attribute"] = [
            {
                "type": "vulnerability",
                "category": "External analysis",
                "value": "CVE-2023-9999",
                "uuid": "attr-cve",
                "Tag": [{"name": "exploit:known"}],
            }
        ]
        event["Object"] = [
            {
                "name": "vulnerability",
                "uuid": "object-cve",
                "Attribute": {
                    "type": "text",
                    "value": "Observed exploitation of CVE-2021-0001",
                    "uuid": "object-attr-cve",
                },
            }
        ]
        prepared = SimpleNamespace(event=event, score_details={})

        metadata = decision_metadata(candidate_ref, prepared)

        self.assertEqual(
            ["CVE-2024-12345", "CVE-2022-1111", "CVE-2023-9999", "CVE-2021-0001"],
            [item["value"] for item in metadata["misp_vulnerabilities"]],
        )
        graph_evidence = metadata["graph_evidence"]
        self.assertEqual(4, graph_evidence["counts"]["vulnerability"])
        self.assertTrue(
            any(
                record["entity_type"] == "vulnerability"
                and record["value"] == "CVE-2023-9999"
                and record["attributes"]["attribute_type"] == "vulnerability"
                for record in graph_evidence["records"]
            )
        )
        graph_candidates = metadata["graph_candidates"]
        self.assertEqual(4, graph_candidates["counts"]["vulnerability"])
        self.assertTrue(
            any(
                candidate["entity_type"] == "vulnerability"
                and candidate["value"] == "CVE-2021-0001"
                and candidate["source_field"] == "Object[0].Attribute[0]"
                for candidate in graph_candidates["candidates"]
            )
        )

    def test_decision_metadata_extracts_misp_event_reports(self):
        candidate_ref = candidate(external_id="event-1", raw={"tags": ["tlp:green"]})
        event = enriched_event()
        event["EventReport"] = [
            {
                "uuid": "event-report-1",
                "name": "Initial analyst report",
                "content": "The event describes exploitation activity.",
                "timestamp": "1782004900",
            },
            {
                "uuid": "event-report-deleted",
                "name": "Deleted report",
                "content": "Should not be represented.",
                "deleted": "1",
            },
        ]
        prepared = SimpleNamespace(event=event, score_details={})

        metadata = decision_metadata(candidate_ref, prepared)

        self.assertEqual(1, len(metadata["misp_event_reports"]))
        self.assertEqual(
            "Initial analyst report",
            metadata["misp_event_reports"][0]["title"],
        )
        graph_evidence = metadata["graph_evidence"]
        self.assertEqual(1, graph_evidence["counts"]["event_report"])
        self.assertTrue(
            any(
                record["entity_type"] == "event_report"
                and record["stix_object_type"] == "note"
                and record["attributes"]["content"]
                == "The event describes exploitation activity."
                for record in graph_evidence["records"]
            )
        )
        graph_candidates = metadata["graph_candidates"]
        self.assertEqual(1, graph_candidates["counts"]["event_report"])
        self.assertTrue(
            any(
                candidate["entity_type"] == "event_report"
                and candidate["name"] == "Initial analyst report"
                and candidate["relationship_type"] == "documents"
                for candidate in graph_candidates["candidates"]
            )
        )

    def test_decision_metadata_extracts_misp_sightings(self):
        candidate_ref = candidate(external_id="event-1", raw={"tags": ["tlp:green"]})
        event = enriched_event()
        event["Attribute"] = [
            {
                "uuid": "attribute-1",
                "type": "domain",
                "category": "Network activity",
                "value": "evil.example",
                "Sighting": [
                    {
                        "id": "42",
                        "type": "0",
                        "date_sighting": "1782004900",
                        "source": "SOC",
                        "Organisation": {
                            "uuid": "org-1",
                            "name": "Example Org",
                        },
                    },
                    {
                        "id": "43",
                        "value": "ignored.example",
                        "deleted": "1",
                    },
                ],
            }
        ]
        prepared = SimpleNamespace(event=event, score_details={})

        metadata = decision_metadata(candidate_ref, prepared)

        self.assertEqual(1, len(metadata["misp_sightings"]))
        self.assertEqual("evil.example", metadata["misp_sightings"][0]["value"])
        self.assertEqual("Example Org", metadata["misp_sightings"][0]["organization"])
        graph_evidence = metadata["graph_evidence"]
        self.assertEqual(1, graph_evidence["counts"]["sighting"])
        self.assertTrue(
            any(
                record["entity_type"] == "sighting"
                and record["stix_object_type"] == "sighting"
                and record["attributes"]["organization"] == "Example Org"
                for record in graph_evidence["records"]
            )
        )
        graph_candidates = metadata["graph_candidates"]
        self.assertEqual(1, graph_candidates["counts"]["sighting"])
        self.assertTrue(
            any(
                candidate["entity_type"] == "sighting"
                and candidate["value"] == "evil.example"
                and candidate["relationship_type"] == "sighting-of"
                for candidate in graph_candidates["candidates"]
            )
        )

    def test_decision_metadata_extracts_misp_object_references(self):
        candidate_ref = candidate(external_id="event-1", raw={"tags": ["tlp:green"]})
        event = enriched_event()
        event["Object"] = [
            {
                "uuid": "object-1",
                "name": "malware",
                "meta-category": "misc",
                "ObjectReference": [
                    {
                        "uuid": "reference-1",
                        "relationship_type": "uses",
                        "referenced_uuid": "object-2",
                        "referenced_type": "object",
                        "comment": "Malware uses this infrastructure.",
                    },
                    {
                        "uuid": "reference-deleted",
                        "relationship_type": "uses",
                        "referenced_uuid": "object-3",
                        "deleted": "1",
                    },
                ],
            }
        ]
        prepared = SimpleNamespace(event=event, score_details={})

        metadata = decision_metadata(candidate_ref, prepared)

        self.assertEqual(1, len(metadata["misp_object_references"]))
        self.assertEqual(
            "object-1 uses object-2",
            metadata["misp_object_references"][0]["value"],
        )
        graph_evidence = metadata["graph_evidence"]
        self.assertEqual(1, graph_evidence["counts"]["object_reference"])
        self.assertTrue(
            any(
                record["entity_type"] == "object_reference"
                and record["stix_object_type"] == "relationship"
                and record["relationship_type"] == "uses"
                and record["attributes"]["target_uuid"] == "object-2"
                for record in graph_evidence["records"]
            )
        )
        graph_candidates = metadata["graph_candidates"]
        self.assertEqual(1, graph_candidates["counts"]["object_reference"])
        self.assertTrue(
            any(
                candidate["entity_type"] == "object_reference"
                and candidate["relationship_type"] == "uses"
                and candidate["stix_object_type"] == "relationship"
                for candidate in graph_candidates["candidates"]
            )
        )

    def test_decision_metadata_extracts_misp_infrastructure_objects(self):
        candidate_ref = candidate(external_id="event-1", raw={"tags": ["tlp:green"]})
        event = enriched_event()
        event["Object"] = [
            {
                "uuid": "object-domain-ip",
                "name": "domain-ip",
                "meta-category": "network",
                "Attribute": [
                    {
                        "uuid": "attribute-domain",
                        "object_relation": "domain",
                        "type": "domain",
                        "value": "c2.example.com",
                    },
                    {
                        "uuid": "attribute-ip",
                        "object_relation": "ip",
                        "type": "ip-dst",
                        "value": "203.0.113.10",
                    },
                    {
                        "uuid": "attribute-port",
                        "object_relation": "port",
                        "type": "port",
                        "value": "443",
                    },
                ],
            },
            {
                "uuid": "object-netblock",
                "name": "netblock",
                "meta-category": "network",
                "Attribute": [
                    {
                        "uuid": "attribute-cidr",
                        "object_relation": "subnet-announced",
                        "type": "ip-src",
                        "value": "203.0.113.0/24",
                    },
                    {
                        "uuid": "attribute-asn",
                        "object_relation": "asn",
                        "type": "AS",
                        "value": "AS64512",
                    },
                    {
                        "uuid": "attribute-as-name",
                        "object_relation": "as-name",
                        "type": "text",
                        "value": "NarrowCTI Validation ASN",
                    },
                    {
                        "uuid": "attribute-rir",
                        "object_relation": "rir",
                        "type": "text",
                        "value": "PRIVATE",
                    },
                ],
            },
            {
                "uuid": "object-asn",
                "name": "asn",
                "Attribute": [
                    {
                        "uuid": "attribute-asn-only",
                        "object_relation": "asn",
                        "type": "AS",
                        "value": "AS64513",
                    }
                ],
            },
            {
                "uuid": "object-ip-port",
                "name": "ip-port",
                "Attribute": [
                    {
                        "uuid": "attribute-ip-port",
                        "object_relation": "ip",
                        "type": "ip-dst|port",
                        "value": "203.0.113.20|443",
                    }
                ],
            },
        ]
        prepared = SimpleNamespace(event=event, score_details={})

        metadata = decision_metadata(candidate_ref, prepared)

        self.assertIn("misp_infrastructure", metadata)
        graph_evidence = metadata["graph_evidence"]
        self.assertEqual(3, graph_evidence["counts"]["infrastructure"])
        self.assertEqual(4, graph_evidence["counts"]["observable"])
        self.assertEqual(3, graph_evidence["counts"]["autonomous_system"])
        graph_candidates = metadata["graph_candidates"]
        self.assertEqual(3, graph_candidates["counts"]["infrastructure"])
        self.assertEqual(4, graph_candidates["counts"]["observable"])
        self.assertEqual(3, graph_candidates["counts"]["autonomous_system"])
        self.assertTrue(
            any(
                candidate["entity_type"] == "observable"
                and candidate["value"] == "203.0.113.0/24"
                and candidate["relationship_type"] == "consists-of"
                and candidate["attributes"]["relationship_source_value"]
                == "MISP netblock 203.0.113.0/24"
                for candidate in graph_candidates["candidates"]
            )
        )
        self.assertTrue(
            any(
                candidate["entity_type"] == "autonomous_system"
                and candidate["value"] == "AS64512 NarrowCTI Validation ASN"
                and candidate["relationship_type"] == "belongs-to"
                and candidate["attributes"]["relationship_source_stix_object_type"]
                == "observable"
                and candidate["attributes"]["relationship_source_value"]
                == "203.0.113.0/24"
                for candidate in graph_candidates["candidates"]
            )
        )
        self.assertFalse(
            any(
                candidate["entity_type"] == "autonomous_system"
                and candidate["value"] == "AS64512"
                for candidate in graph_candidates["candidates"]
            )
        )
        self.assertTrue(
            any(
                candidate["entity_type"] == "observable"
                and candidate["value"] == "203.0.113.20"
                and candidate["attributes"]["port"] == "443"
                for candidate in graph_candidates["candidates"]
            )
        )
        self.assertTrue(
            any(
                candidate["entity_type"] == "autonomous_system"
                and candidate["value"] == "AS64513"
                and candidate["relationship_type"] == "related-to"
                for candidate in graph_candidates["candidates"]
            )
        )
        self.assertFalse(
            any(
                candidate["entity_type"] == "autonomous_system"
                and candidate["value"] == "AS443"
                for candidate in graph_candidates["candidates"]
            )
        )

    def test_decision_metadata_extracts_misp_detection_rules(self):
        candidate_ref = candidate(external_id="event-1", raw={"tags": ["tlp:green"]})
        event = enriched_event()
        event["Attribute"] = [
            {
                "uuid": "attribute-rule-1",
                "type": "sigma",
                "category": "Payload delivery",
                "value": "title: Suspicious PowerShell",
                "comment": "Suspicious PowerShell",
                "Tag": [{"name": "tlp:green"}],
            },
            {
                "uuid": "attribute-rule-deleted",
                "type": "yara",
                "value": "rule DeletedRule { condition: true }",
                "deleted": "1",
            },
        ]
        prepared = SimpleNamespace(event=event, score_details={})

        metadata = decision_metadata(candidate_ref, prepared)

        self.assertEqual(1, len(metadata["misp_detection_rules"]))
        self.assertEqual("sigma", metadata["misp_detection_rules"][0]["rule_type"])
        self.assertEqual(
            "title: Suspicious PowerShell",
            metadata["misp_detection_rules"][0]["pattern"],
        )
        graph_evidence = metadata["graph_evidence"]
        self.assertEqual(1, graph_evidence["counts"]["detection_rule"])
        self.assertTrue(
            any(
                record["entity_type"] == "detection_rule"
                and record["stix_object_type"] == "indicator"
                and record["attributes"]["pattern_type"] == "sigma"
                for record in graph_evidence["records"]
            )
        )
        graph_candidates = metadata["graph_candidates"]
        self.assertEqual(1, graph_candidates["counts"]["detection_rule"])
        self.assertTrue(
            any(
                candidate["entity_type"] == "detection_rule"
                and candidate["relationship_type"] == "detects"
                and candidate["attributes"]["pattern"] == "title: Suspicious PowerShell"
                for candidate in graph_candidates["candidates"]
            )
        )

    def test_decision_metadata_enriches_misp_ip_with_offline_asn(self):
        candidate_ref = candidate(external_id="event-1", raw={"tags": ["tlp:green"]})
        event = enriched_event()
        event["Object"] = [
            {
                "uuid": "object-domain-ip",
                "name": "domain-ip",
                "Attribute": [
                    {
                        "uuid": "attribute-domain",
                        "object_relation": "domain",
                        "type": "domain",
                        "value": "c2.example.com",
                    },
                    {
                        "uuid": "attribute-ip",
                        "object_relation": "ip",
                        "type": "ip-dst",
                        "value": "203.0.113.10",
                    },
                ],
            }
        ]
        prepared = SimpleNamespace(event=event, score_details={})
        enricher = OfflineIPASNEnricher(
            [
                IPASNRecord(
                    network=ipaddress.ip_network("203.0.113.0/24"),
                    asn=64512,
                    as_name="Offline Validation ASN",
                    rir="TEST",
                    source="unit-test",
                )
            ]
        )

        metadata = decision_metadata(
            candidate_ref,
            prepared,
            ip_asn_enricher=enricher,
        )

        graph_candidates = metadata["graph_candidates"]
        self.assertTrue(
            any(
                candidate["entity_type"] == "autonomous_system"
                and candidate["value"] == "AS64512 Offline Validation ASN"
                and candidate["relationship_type"] == "belongs-to"
                and candidate["attributes"]["relationship_source_value"]
                == "203.0.113.10"
                and candidate["attributes"]["enrichment_source"] == "unit-test"
                for candidate in graph_candidates["candidates"]
            )
        )

    def test_decision_metadata_builds_dry_run_graph_export_plan(self):
        candidate_ref = candidate(external_id="event-1", raw={"tags": ["tlp:green"]})
        prepared = SimpleNamespace(event=enriched_event(), score_details={})

        metadata = decision_metadata(
            candidate_ref,
            prepared,
            graph_export_mode="dry-run",
        )

        graph_plan = metadata["graph_export_plan"]
        self.assertEqual("dry-run", graph_plan["mode"])
        self.assertEqual("dry-run", graph_plan["status"])
        self.assertEqual(
            graph_plan["accepted_count"],
            graph_plan["would_create_object_count"],
        )
        self.assertTrue(
            any(action["action"] == "would_create" for action in graph_plan["actions"])
        )

    def test_decision_metadata_uses_graph_dedup_known_keys(self):
        candidate_ref = candidate(external_id="event-1", raw={"tags": ["tlp:green"]})
        prepared = SimpleNamespace(event=enriched_event(), score_details={})

        metadata = decision_metadata(
            candidate_ref,
            prepared,
            graph_export_mode="dry-run",
            graph_deduplication_index=FirstActionEntityKnownIndex(),
        )

        graph_plan = metadata["graph_export_plan"]
        self.assertEqual(1, graph_plan["deduplicated_entity_count"])
        self.assertEqual(
            graph_plan["accepted_count"] - 1,
            graph_plan["would_create_object_count"],
        )
        self.assertIn("graph_export_plan_known_keys", metadata)
        self.assertEqual(
            "internal--1",
            metadata["graph_export_plan_lookup_matches"][0]["match"]["opencti_id"],
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
        self.assertEqual(
            2,
            queued[0]["metadata"]["graph_candidates"]["candidate_count"],
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
        self.assertEqual("MISP via NarrowCTI", export_calls[0]["identity_name"])
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
