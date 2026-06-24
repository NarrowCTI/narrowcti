import unittest
from types import SimpleNamespace

from core.graph_candidates import apply_graph_candidate_policy, build_graph_candidates
from core.graph_export_plan import build_graph_export_plan_with_known_keys
from core.opencti_graph_lookup import (
    CompositeGraphLookup,
    OpenCTIGraphLookup,
    attack_pattern_external_id,
    attack_pattern_standard_id,
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

    def test_unsupported_candidate_does_not_query_opencti(self):
        calls = []
        lookup = OpenCTIGraphLookup(SimpleNamespace(query=lambda *args: calls.append(args)))

        self.assertIsNone(
            lookup.find_candidate(
                {
                    "stix_object_type": "malware",
                    "value": "LummaC2",
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


if __name__ == "__main__":
    unittest.main()
