import unittest
from types import SimpleNamespace

from core.graph_candidates import apply_graph_candidate_policy, build_graph_candidates
from core.graph_export_plan import build_graph_export_plan_with_known_keys
from core.opencti_graph_lookup import (
    CompositeGraphLookup,
    OpenCTIGraphLookup,
    attack_pattern_external_id,
    attack_pattern_standard_id,
    graph_object_standard_id,
)


class OpenCTIGraphLookupTests(unittest.TestCase):
    def test_known_keys_for_plan_resolves_attack_pattern_by_mitre_id(self):
        calls = []

        def query(query_text, variables):
            calls.append((query_text, variables))
            return {
                "data": {
                    "attackPatterns": {
                        "edges": [
                            {
                                "node": {
                                    "id": "internal--1",
                                    "standard_id": "attack-pattern--1111",
                                    "entity_type": "Attack-Pattern",
                                    "name": "Command and Scripting Interpreter",
                                    "x_mitre_id": "T1059",
                                }
                            }
                        ]
                    }
                }
            }

        lookup = OpenCTIGraphLookup(SimpleNamespace(query=query))
        policy = accepted_attack_pattern_policy()
        plan, known, error = build_graph_export_plan_with_known_keys(
            policy,
            mode="dry-run",
            graph_deduplication_index=lookup,
        )

        self.assertEqual("", error)
        self.assertEqual(1, len(known["entity_keys"]))
        self.assertEqual(1, len(known["matches"]))
        self.assertEqual(
            "internal--1",
            known["matches"][0]["match"]["opencti_id"],
        )
        self.assertEqual(1, plan["deduplicated_entity_count"])
        self.assertEqual(0, plan["would_create_object_count"])
        lookup_known = lookup.known_keys_for_plan(plan)
        self.assertEqual(1, len(lookup_known["matches"]))
        self.assertIn("attackPatterns", calls[0][0])
        self.assertEqual(
            "x_mitre_id",
            calls[0][1]["filters"]["filters"][0]["key"],
        )
        self.assertEqual(
            ["T1059"],
            calls[0][1]["filters"]["filters"][0]["values"],
        )

    def test_lookup_fails_open_when_opencti_query_errors(self):
        logs = []

        def query(*args, **kwargs):
            raise RuntimeError("OpenCTI unavailable")

        lookup = OpenCTIGraphLookup(SimpleNamespace(query=query), logger=logs.append)
        policy = accepted_attack_pattern_policy()

        plan, known, error = build_graph_export_plan_with_known_keys(
            policy,
            mode="dry-run",
            graph_deduplication_index=lookup,
        )

        self.assertEqual("", error)
        self.assertEqual([], known["entity_keys"])
        self.assertEqual(1, plan["would_create_object_count"])
        self.assertIn("OpenCTI graph lookup failed", logs[0])

    def test_attack_pattern_external_id_prefers_mitre_references(self):
        candidate = {
            "stix_object_type": "attack-pattern",
            "value": "Command and Scripting Interpreter",
            "attributes": {
                "external_references": [
                    {"source_name": "other", "external_id": "X1"},
                    {"source_name": "mitre-attack", "external_id": "T1059.001"},
                ]
            },
        }

        self.assertEqual("T1059.001", attack_pattern_external_id(candidate))

    def test_attack_pattern_standard_id_uses_stix_id_when_mitre_id_is_absent(self):
        calls = []

        def query(query_text, variables):
            calls.append((query_text, variables))
            return {"data": {"attackPatterns": {"edges": []}}}

        lookup = OpenCTIGraphLookup(SimpleNamespace(query=query))
        lookup.find_attack_pattern(
            {
                "stix_object_type": "attack-pattern",
                "value": "Command and Scripting Interpreter",
                "attributes": {"stix_id": "attack-pattern--1111"},
            }
        )

        self.assertEqual(
            "attack-pattern--1111",
            attack_pattern_standard_id(
                {"attributes": {"stix_id": "attack-pattern--1111"}}
            ),
        )
        self.assertEqual(
            "standard_id",
            calls[0][1]["filters"]["filters"][0]["key"],
        )

    def test_known_keys_for_plan_resolves_malware_by_name(self):
        calls = []

        def query(query_text, variables):
            calls.append((query_text, variables))
            return {
                "data": {
                    "malwares": {
                        "edges": [
                            {
                                "node": {
                                    "id": "internal--malware",
                                    "standard_id": (
                                        "malware--11111111-1111-4111-8111-"
                                        "111111111111"
                                    ),
                                    "entity_type": "Malware",
                                    "name": "LummaC2",
                                }
                            }
                        ]
                    }
                }
            }

        lookup = OpenCTIGraphLookup(SimpleNamespace(query=query))
        plan, known, error = build_graph_export_plan_with_known_keys(
            accepted_named_object_policy(
                stix_object_type="malware",
                entity_type="malware",
                value="LummaC2",
                name="LummaC2",
                relationship_type="uses",
            ),
            mode="dry-run",
            graph_deduplication_index=lookup,
        )

        self.assertEqual("", error)
        self.assertEqual(1, len(known["entity_keys"]))
        self.assertEqual("Malware", known["matches"][0]["match"]["entity_type"])
        self.assertEqual(1, plan["deduplicated_entity_count"])
        self.assertIn("malwares", calls[0][0])
        self.assertEqual("name", calls[0][1]["filters"]["filters"][0]["key"])
        self.assertEqual(["LummaC2"], calls[0][1]["filters"]["filters"][0]["values"])

    def test_known_keys_for_plan_resolves_tool_by_name(self):
        calls = []

        def query(query_text, variables):
            calls.append((query_text, variables))
            return {
                "data": {
                    "tools": {
                        "edges": [
                            {
                                "node": {
                                    "id": "internal--tool",
                                    "standard_id": (
                                        "tool--11111111-1111-4111-8111-111111111111"
                                    ),
                                    "entity_type": "Tool",
                                    "name": "Mimikatz",
                                }
                            }
                        ]
                    }
                }
            }

        lookup = OpenCTIGraphLookup(SimpleNamespace(query=query))
        plan, known, error = build_graph_export_plan_with_known_keys(
            accepted_named_object_policy(
                stix_object_type="tool",
                entity_type="tool",
                value="Mimikatz",
                name="Mimikatz",
                relationship_type="uses",
            ),
            mode="dry-run",
            graph_deduplication_index=lookup,
        )

        self.assertEqual("", error)
        self.assertEqual(1, len(known["entity_keys"]))
        self.assertEqual("Tool", known["matches"][0]["match"]["entity_type"])
        self.assertEqual(1, plan["deduplicated_entity_count"])
        self.assertIn("tools", calls[0][0])
        self.assertEqual(["Mimikatz"], calls[0][1]["filters"]["filters"][0]["values"])

    def test_tool_standard_id_uses_stix_id_before_name(self):
        calls = []

        def query(query_text, variables):
            calls.append((query_text, variables))
            return {"data": {"tools": {"edges": []}}}

        lookup = OpenCTIGraphLookup(SimpleNamespace(query=query))
        lookup.find_candidate(
            {
                "stix_object_type": "tool",
                "name": "Mimikatz",
                "attributes": {
                    "stix_id": "tool--11111111-1111-4111-8111-111111111111"
                },
            }
        )

        self.assertEqual(
            "tool--11111111-1111-4111-8111-111111111111",
            graph_object_standard_id(
                {
                    "stix_object_type": "tool",
                    "attributes": {
                        "stix_id": "tool--11111111-1111-4111-8111-111111111111"
                    },
                },
                "tool",
            ),
        )
        self.assertEqual("standard_id", calls[0][1]["filters"]["filters"][0]["key"])

    def test_unsupported_candidate_does_not_query_opencti(self):
        calls = []
        lookup = OpenCTIGraphLookup(
            SimpleNamespace(query=lambda *args: calls.append(args))
        )

        self.assertIsNone(
            lookup.find_candidate(
                {
                    "stix_object_type": "vulnerability",
                    "value": "CVE-2024-0001",
                }
            )
        )
        self.assertEqual([], calls)

    def test_composite_graph_lookup_merges_known_keys(self):
        first = SimpleNamespace(
            known_keys_for_plan=lambda plan: {
                "entity_keys": ["entity:a"],
                "relationship_keys": [],
                "matches": [{"value": "T1059"}],
            }
        )
        second = SimpleNamespace(
            known_keys_for_plan=lambda plan: {
                "entity_keys": ["entity:a", "entity:b"],
                "relationship_keys": ["relationship:1"],
            }
        )

        known = CompositeGraphLookup(first, second).known_keys_for_plan({"actions": []})

        self.assertEqual(["entity:a", "entity:b"], known["entity_keys"])
        self.assertEqual(["relationship:1"], known["relationship_keys"])
        self.assertEqual([{"value": "T1059"}], known["matches"])

    def test_composite_graph_lookup_marks_exported_plan_on_marking_indexes(self):
        calls = []

        def mark_exported_plan(plan, source_key="", external_id="", title=""):
            calls.append(
                {
                    "plan": plan,
                    "source_key": source_key,
                    "external_id": external_id,
                    "title": title,
                }
            )
            return {"entities": 1, "relationships": 2}

        marker = SimpleNamespace(
            known_keys_for_plan=lambda plan: {},
            mark_exported_plan=mark_exported_plan,
        )
        lookup_only = SimpleNamespace(known_keys_for_plan=lambda plan: {})

        added = CompositeGraphLookup(marker, lookup_only).mark_exported_plan(
            {"actions": []},
            source_key="alienvault:otx",
            external_id="pulse-1",
            title="Technique pulse",
        )

        self.assertEqual({"entities": 1, "relationships": 2}, added)
        self.assertEqual("alienvault:otx", calls[0]["source_key"])
        self.assertEqual("pulse-1", calls[0]["external_id"])
        self.assertEqual("Technique pulse", calls[0]["title"])


def accepted_attack_pattern_policy():
    candidates = build_graph_candidates(
        {
            "version": "v0.8.0-dev",
            "source_key": "alienvault:otx",
            "external_id": "pulse-1",
            "title": "Technique pulse",
            "records": [
                {
                    "entity_type": "attack_pattern",
                    "value": "T1059",
                    "display_name": "Command and Scripting Interpreter",
                    "stix_object_type": "attack-pattern",
                    "relationship_type": "uses",
                    "source_key": "alienvault:otx",
                    "source_name": "mitre-attack",
                    "source_field": "mitre_attack.resolved",
                    "confidence": 90,
                    "relationship_confidence": 85,
                }
            ],
        }
    )
    return apply_graph_candidate_policy(
        candidates,
        min_entity_confidence=50,
        min_relationship_confidence=60,
    ).to_dict()


def accepted_named_object_policy(
    stix_object_type,
    entity_type,
    value,
    name,
    relationship_type,
):
    candidates = build_graph_candidates(
        {
            "version": "v0.8.0-dev",
            "source_key": "alienvault:otx",
            "external_id": "pulse-1",
            "title": "Arsenal pulse",
            "records": [
                {
                    "entity_type": entity_type,
                    "value": value,
                    "display_name": name,
                    "stix_object_type": stix_object_type,
                    "relationship_type": relationship_type,
                    "source_key": "alienvault:otx",
                    "source_name": "otx",
                    "source_field": "graph_evidence",
                    "confidence": 85,
                    "relationship_confidence": 80,
                }
            ],
        }
    )
    return apply_graph_candidate_policy(
        candidates,
        min_entity_confidence=50,
        min_relationship_confidence=60,
    ).to_dict()


if __name__ == "__main__":
    unittest.main()
