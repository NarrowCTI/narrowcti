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
    vulnerability_external_id,
)


class OpenCTIGraphLookupTests(unittest.TestCase):
    def test_known_keys_for_plan_resolves_exact_existing_relationship_once(self):
        calls = []

        def query(query_text, variables):
            calls.append((query_text, variables))
            if "malwares" in query_text:
                return graph_node_response(
                    "malwares", "target--1", "Malware", "Lumma Stealer"
                )
            if "intrusionSets" in query_text:
                return graph_node_response(
                    "intrusionSets", "source--1", "Intrusion-Set", "APT Example"
                )
            if "stixCoreRelationships" in query_text:
                return {
                    "data": {
                        "stixCoreRelationships": {
                            "edges": [
                                {
                                    "node": {
                                        "id": "relationship--1",
                                        "standard_id": "relationship--standard-1",
                                        "relationship_type": "uses",
                                    }
                                }
                            ]
                        }
                    }
                }
            return {}

        candidate = relationship_candidate()
        action = {
            "candidate": candidate,
            "deduplication": {
                "entity_key": "entity:malware:lumma",
                "relationship_key": "relationship:apt-uses-lumma",
            },
        }
        lookup = OpenCTIGraphLookup(SimpleNamespace(query=query))

        known = lookup.known_keys_for_plan({"actions": [action, action]})

        self.assertEqual(["entity:malware:lumma"], known["entity_keys"])
        self.assertEqual(
            ["relationship:apt-uses-lumma"], known["relationship_keys"]
        )
        self.assertTrue(known["matches"][0]["match"]["relationship_exists"])
        relationship = known["matches"][0]["match"]["relationship_match"]
        self.assertEqual("source--1", relationship["source_opencti_id"])
        self.assertEqual("target--1", relationship["target_opencti_id"])
        relationship_calls = [
            call for call in calls if "stixCoreRelationships" in call[0]
        ]
        self.assertEqual(1, len(relationship_calls))
        self.assertEqual(["source--1"], relationship_calls[0][1]["fromIds"])
        self.assertEqual(["target--1"], relationship_calls[0][1]["toIds"])

    def test_known_keys_for_plan_does_not_deduplicate_different_relationship_type(self):
        def query(query_text, variables):
            if "malwares" in query_text:
                return graph_node_response(
                    "malwares", "target--1", "Malware", "Lumma Stealer"
                )
            if "intrusionSets" in query_text:
                return graph_node_response(
                    "intrusionSets", "source--1", "Intrusion-Set", "APT Example"
                )
            if "stixCoreRelationships" in query_text:
                return {
                    "data": {
                        "stixCoreRelationships": {
                            "edges": [
                                {
                                    "node": {
                                        "id": "relationship--1",
                                        "relationship_type": "related-to",
                                    }
                                }
                            ]
                        }
                    }
                }
            return {}

        known = OpenCTIGraphLookup(
            SimpleNamespace(query=query)
        ).known_keys_for_plan(
            {
                "actions": [
                    {
                        "candidate": relationship_candidate(),
                        "deduplication": {
                            "entity_key": "entity:malware:lumma",
                            "relationship_key": "relationship:apt-uses-lumma",
                        },
                    }
                ]
            }
        )

        self.assertEqual(["entity:malware:lumma"], known["entity_keys"])
        self.assertEqual([], known["relationship_keys"])
        self.assertNotIn("relationship_exists", known["matches"][0]["match"])

    def test_relationship_lookup_fails_open_when_opencti_query_errors(self):
        logs = []

        def query(query_text, variables):
            if "malwares" in query_text:
                return graph_node_response(
                    "malwares", "target--1", "Malware", "Lumma Stealer"
                )
            if "intrusionSets" in query_text:
                return graph_node_response(
                    "intrusionSets", "source--1", "Intrusion-Set", "APT Example"
                )
            raise RuntimeError("relationship service unavailable")

        lookup = OpenCTIGraphLookup(SimpleNamespace(query=query), logger=logs.append)
        known = lookup.known_keys_for_plan(
            {
                "actions": [
                    {
                        "candidate": relationship_candidate(),
                        "deduplication": {
                            "entity_key": "entity:malware:lumma",
                            "relationship_key": "relationship:apt-uses-lumma",
                        },
                    }
                ]
            }
        )

        self.assertEqual([], known["relationship_keys"])
        self.assertIn("OpenCTI relationship lookup failed", logs[0])

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
                                    "name": "ExampleMalware",
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
                value="ExampleMalware",
                name="ExampleMalware",
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
        self.assertEqual(
            ["ExampleMalware"],
            calls[0][1]["filters"]["filters"][0]["values"],
        )

    def test_known_keys_for_plan_prefers_curated_malware_alias(self):
        calls = []

        def query(query_text, variables):
            calls.append((query_text, variables))
            return {
                "data": {
                    "malwares": {
                        "edges": [
                            {
                                "node": {
                                    "id": "internal--lumma-stealer",
                                    "standard_id": (
                                        "malware--22222222-2222-4222-8222-"
                                        "222222222222"
                                    ),
                                    "entity_type": "Malware",
                                    "name": "Lumma Stealer",
                                    "aliases": ["LummaStealer"],
                                }
                            },
                            {
                                "node": {
                                    "id": "internal--lummac2-duplicate",
                                    "standard_id": (
                                        "malware--11111111-1111-4111-8111-"
                                        "111111111111"
                                    ),
                                    "entity_type": "Malware",
                                    "name": "LummaC2",
                                    "aliases": [],
                                }
                            },
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
        self.assertEqual("Lumma Stealer", known["matches"][0]["match"]["name"])
        self.assertEqual("alias", known["matches"][0]["match"]["match_type"])
        self.assertEqual(1, plan["deduplicated_entity_count"])
        self.assertIn("malwares", calls[0][0])
        self.assertEqual("Lumma", calls[0][1]["search"])

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

    def test_known_keys_for_plan_resolves_intrusion_set_by_alias(self):
        calls = []

        def query(query_text, variables):
            calls.append((query_text, variables))
            return {
                "data": {
                    "intrusionSets": {
                        "edges": [
                            {
                                "node": {
                                    "id": "internal--blacktech",
                                    "standard_id": (
                                        "intrusion-set--11111111-1111-4111-8111-"
                                        "111111111111"
                                    ),
                                    "entity_type": "Intrusion-Set",
                                    "name": "BlackTech",
                                    "aliases": ["Palmerworm"],
                                }
                            }
                        ]
                    }
                }
            }

        lookup = OpenCTIGraphLookup(SimpleNamespace(query=query))
        plan, known, error = build_graph_export_plan_with_known_keys(
            accepted_named_object_policy(
                stix_object_type="intrusion-set",
                entity_type="intrusion_set",
                value="Palmerworm",
                name="Palmerworm",
                relationship_type="attributed-to",
            ),
            mode="dry-run",
            graph_deduplication_index=lookup,
        )

        self.assertEqual("", error)
        self.assertEqual(1, len(known["entity_keys"]))
        self.assertEqual("BlackTech", known["matches"][0]["match"]["name"])
        self.assertEqual("alias", known["matches"][0]["match"]["match_type"])
        self.assertEqual(1, plan["deduplicated_entity_count"])
        self.assertIn("intrusionSets", calls[0][0])
        self.assertEqual("Palmerworm", calls[0][1]["search"])

    def test_known_keys_for_plan_resolves_lazarus_intrusion_set_alias(self):
        calls = []

        def query(query_text, variables):
            calls.append((query_text, variables))
            return {
                "data": {
                    "intrusionSets": {
                        "edges": [
                            {
                                "node": {
                                    "id": "internal--lazarus",
                                    "standard_id": (
                                        "intrusion-set--11111111-1111-4111-8111-"
                                        "111111111111"
                                    ),
                                    "entity_type": "Intrusion-Set",
                                    "name": "Lazarus Group",
                                    "aliases": ["HIDDEN COBRA"],
                                }
                            }
                        ]
                    }
                }
            }

        lookup = OpenCTIGraphLookup(SimpleNamespace(query=query))
        plan, known, error = build_graph_export_plan_with_known_keys(
            accepted_named_object_policy(
                stix_object_type="intrusion-set",
                entity_type="intrusion_set",
                value="Lazarus",
                name="Lazarus",
                relationship_type="attributed-to",
            ),
            mode="dry-run",
            graph_deduplication_index=lookup,
        )

        self.assertEqual("", error)
        self.assertEqual(1, len(known["entity_keys"]))
        self.assertEqual("Lazarus Group", known["matches"][0]["match"]["name"])
        self.assertEqual("alias", known["matches"][0]["match"]["match_type"])
        self.assertEqual(1, plan["deduplicated_entity_count"])
        self.assertIn("intrusionSets", calls[0][0])
        self.assertEqual("Lazarus", calls[0][1]["search"])

    def test_known_keys_for_plan_resolves_threat_actor_by_name(self):
        calls = []

        def query(query_text, variables):
            calls.append((query_text, variables))
            if "ThreatActorGroupGraphSearch" in query_text:
                return {"data": {"threatActorsGroup": {"edges": []}}}
            return {
                "data": {
                    "threatActorsGroup": {
                        "edges": [
                            {
                                "node": {
                                    "id": "internal--actor",
                                    "standard_id": (
                                        "threat-actor--11111111-1111-4111-8111-"
                                        "111111111111"
                                    ),
                                    "entity_type": "Threat-Actor-Group",
                                    "name": "Example Actor",
                                }
                            }
                        ]
                    }
                }
            }

        lookup = OpenCTIGraphLookup(SimpleNamespace(query=query))
        plan, known, error = build_graph_export_plan_with_known_keys(
            accepted_named_object_policy(
                stix_object_type="threat-actor",
                entity_type="threat_actor",
                value="Example Actor",
                name="Example Actor",
                relationship_type="attributed-to",
            ),
            mode="dry-run",
            graph_deduplication_index=lookup,
        )

        self.assertEqual("", error)
        self.assertEqual(1, len(known["entity_keys"]))
        self.assertEqual(
            "Threat-Actor-Group",
            known["matches"][0]["match"]["entity_type"],
        )
        self.assertEqual("name", known["matches"][0]["match"]["match_type"])
        self.assertEqual(1, plan["deduplicated_entity_count"])
        self.assertIn("threatActorsGroup", calls[-1][0])
        self.assertEqual("name", calls[-1][1]["filters"]["filters"][0]["key"])

    def test_known_keys_for_plan_resolves_threat_actor_group_by_name(self):
        calls = []

        def query(query_text, variables):
            calls.append((query_text, variables))
            if "ThreatActorGroupGraphSearch" in query_text:
                return {"data": {"threatActorsGroup": {"edges": []}}}
            return {
                "data": {
                    "threatActorsGroup": {
                        "edges": [
                            {
                                "node": {
                                    "id": "internal--actor-group",
                                    "standard_id": (
                                        "threat-actor--11111111-1111-4111-8111-"
                                        "111111111111"
                                    ),
                                    "entity_type": "Threat-Actor-Group",
                                    "name": "Example Group",
                                }
                            }
                        ]
                    }
                }
            }

        lookup = OpenCTIGraphLookup(SimpleNamespace(query=query))
        plan, known, error = build_graph_export_plan_with_known_keys(
            accepted_named_object_policy(
                stix_object_type="threat-actor",
                entity_type="threat_actor",
                value="Example Group",
                name="Example Group",
                relationship_type="attributed-to",
                attributes={"threat_actor_class": "group"},
            ),
            mode="dry-run",
            graph_deduplication_index=lookup,
        )

        self.assertEqual("", error)
        self.assertEqual(1, len(known["entity_keys"]))
        self.assertEqual(
            "Threat-Actor-Group",
            known["matches"][0]["match"]["entity_type"],
        )
        self.assertEqual("name", known["matches"][0]["match"]["match_type"])
        self.assertEqual(1, plan["deduplicated_entity_count"])
        self.assertIn("threatActorsGroup", calls[-1][0])
        self.assertEqual("name", calls[-1][1]["filters"]["filters"][0]["key"])

    def test_known_keys_for_plan_resolves_threat_actor_individual_by_name(self):
        calls = []

        def query(query_text, variables):
            calls.append((query_text, variables))
            if "ThreatActorIndividualGraphSearch" in query_text:
                return {"data": {"threatActorsIndividuals": {"edges": []}}}
            return {
                "data": {
                    "threatActorsIndividuals": {
                        "edges": [
                            {
                                "node": {
                                    "id": "internal--actor-individual",
                                    "standard_id": (
                                        "threat-actor--22222222-2222-4222-8222-"
                                        "222222222222"
                                    ),
                                    "entity_type": "Threat-Actor-Individual",
                                    "name": "Example Operator",
                                }
                            }
                        ]
                    }
                }
            }

        lookup = OpenCTIGraphLookup(SimpleNamespace(query=query))
        plan, known, error = build_graph_export_plan_with_known_keys(
            accepted_named_object_policy(
                stix_object_type="threat-actor",
                entity_type="threat_actor_individual",
                value="Example Operator",
                name="Example Operator",
                relationship_type="attributed-to",
                attributes={"threat_actor_class": "individual"},
            ),
            mode="dry-run",
            graph_deduplication_index=lookup,
        )

        self.assertEqual("", error)
        self.assertEqual(1, len(known["entity_keys"]))
        self.assertEqual(
            "Threat-Actor-Individual",
            known["matches"][0]["match"]["entity_type"],
        )
        self.assertEqual("name", known["matches"][0]["match"]["match_type"])
        self.assertEqual(1, plan["deduplicated_entity_count"])
        self.assertIn("threatActorsIndividuals", calls[-1][0])
        self.assertEqual("name", calls[-1][1]["filters"]["filters"][0]["key"])

    def test_known_keys_for_plan_resolves_campaign_by_name(self):
        calls = []

        def query(query_text, variables):
            calls.append((query_text, variables))
            return {
                "data": {
                    "campaigns": {
                        "edges": [
                            {
                                "node": {
                                    "id": "internal--campaign",
                                    "standard_id": (
                                        "campaign--11111111-1111-4111-8111-"
                                        "111111111111"
                                    ),
                                    "entity_type": "Campaign",
                                    "name": "Operation Example",
                                }
                            }
                        ]
                    }
                }
            }

        lookup = OpenCTIGraphLookup(SimpleNamespace(query=query))
        plan, known, error = build_graph_export_plan_with_known_keys(
            accepted_named_object_policy(
                stix_object_type="campaign",
                entity_type="campaign",
                value="Operation Example",
                name="Operation Example",
                relationship_type="related-to",
            ),
            mode="dry-run",
            graph_deduplication_index=lookup,
        )

        self.assertEqual("", error)
        self.assertEqual(1, len(known["entity_keys"]))
        self.assertEqual("Campaign", known["matches"][0]["match"]["entity_type"])
        self.assertEqual("name", known["matches"][0]["match"]["match_type"])
        self.assertEqual(1, plan["deduplicated_entity_count"])
        self.assertIn("campaigns", calls[0][0])
        self.assertEqual("name", calls[0][1]["filters"]["filters"][0]["key"])

    def test_known_keys_for_plan_resolves_course_of_action_by_name(self):
        calls = []

        def query(query_text, variables):
            calls.append((query_text, variables))
            return {
                "data": {
                    "coursesOfAction": {
                        "edges": [
                            {
                                "node": {
                                    "id": "internal--course",
                                    "standard_id": (
                                        "course-of-action--11111111-1111-4111-8111-"
                                        "111111111111"
                                    ),
                                    "entity_type": "Course-Of-Action",
                                    "name": "Boot Integrity",
                                }
                            }
                        ]
                    }
                }
            }

        lookup = OpenCTIGraphLookup(SimpleNamespace(query=query))
        plan, known, error = build_graph_export_plan_with_known_keys(
            accepted_named_object_policy(
                stix_object_type="course-of-action",
                entity_type="course_of_action",
                value="Boot Integrity",
                name="Boot Integrity",
                relationship_type="related-to",
            ),
            mode="dry-run",
            graph_deduplication_index=lookup,
        )

        self.assertEqual("", error)
        self.assertEqual(1, len(known["entity_keys"]))
        self.assertEqual(
            "Course-Of-Action",
            known["matches"][0]["match"]["entity_type"],
        )
        self.assertEqual("name", known["matches"][0]["match"]["match_type"])
        self.assertEqual(1, plan["deduplicated_entity_count"])
        self.assertIn("coursesOfAction", calls[0][0])
        self.assertEqual("name", calls[0][1]["filters"]["filters"][0]["key"])

    def test_known_keys_for_plan_resolves_data_component_by_name(self):
        calls = []

        def query(query_text, variables):
            calls.append((query_text, variables))
            return {
                "data": {
                    "dataComponents": {
                        "edges": [
                            {
                                "node": {
                                    "id": "internal--data-component",
                                    "standard_id": (
                                        "data-component--11111111-1111-4111-8111-"
                                        "111111111111"
                                    ),
                                    "entity_type": "Data-Component",
                                    "name": "Process Creation",
                                }
                            }
                        ]
                    }
                }
            }

        lookup = OpenCTIGraphLookup(SimpleNamespace(query=query))
        plan, known, error = build_graph_export_plan_with_known_keys(
            accepted_named_object_policy(
                stix_object_type="x-mitre-data-component",
                entity_type="attack_data_component",
                value="Process Creation",
                name="Process Creation",
                relationship_type="detects",
            ),
            mode="dry-run",
            graph_deduplication_index=lookup,
        )

        self.assertEqual("", error)
        self.assertEqual(1, len(known["entity_keys"]))
        self.assertEqual(
            "Data-Component",
            known["matches"][0]["match"]["entity_type"],
        )
        self.assertEqual("name", known["matches"][0]["match"]["match_type"])
        self.assertEqual(1, plan["deduplicated_entity_count"])
        self.assertIn("dataComponents", calls[0][0])
        self.assertEqual("name", calls[0][1]["filters"]["filters"][0]["key"])

    def test_known_keys_for_plan_resolves_data_source_by_name(self):
        calls = []

        def query(query_text, variables):
            calls.append((query_text, variables))
            return {
                "data": {
                    "dataSources": {
                        "edges": [
                            {
                                "node": {
                                    "id": "internal--data-source",
                                    "standard_id": (
                                        "data-source--11111111-1111-4111-8111-"
                                        "111111111111"
                                    ),
                                    "entity_type": "Data-Source",
                                    "name": "Process: Process Creation",
                                }
                            }
                        ]
                    }
                }
            }

        lookup = OpenCTIGraphLookup(SimpleNamespace(query=query))
        plan, known, error = build_graph_export_plan_with_known_keys(
            accepted_named_object_policy(
                stix_object_type="x-mitre-data-source",
                entity_type="attack_data_source",
                value="Process: Process Creation",
                name="Process: Process Creation",
                relationship_type="detects",
            ),
            mode="dry-run",
            graph_deduplication_index=lookup,
        )

        self.assertEqual("", error)
        self.assertEqual(1, len(known["entity_keys"]))
        self.assertEqual(
            "Data-Source",
            known["matches"][0]["match"]["entity_type"],
        )
        self.assertEqual("name", known["matches"][0]["match"]["match_type"])
        self.assertEqual(1, plan["deduplicated_entity_count"])
        self.assertIn("dataSources", calls[0][0])
        self.assertEqual("name", calls[0][1]["filters"]["filters"][0]["key"])

    def test_data_component_lookup_accepts_opencti_canonical_standard_id(self):
        calls = []

        def query(query_text, variables):
            calls.append((query_text, variables))
            return {"data": {"dataComponents": {"edges": []}}}

        lookup = OpenCTIGraphLookup(SimpleNamespace(query=query))
        lookup.find_candidate(
            {
                "stix_object_type": "x-mitre-data-component",
                "value": "Process Creation",
                "attributes": {
                    "stix_id": (
                        "data-component--11111111-1111-4111-8111-111111111111"
                    )
                },
            }
        )

        self.assertEqual("standard_id", calls[0][1]["filters"]["filters"][0]["key"])
        self.assertEqual(
            ["data-component--11111111-1111-4111-8111-111111111111"],
            calls[0][1]["filters"]["filters"][0]["values"],
        )

    def test_data_source_lookup_accepts_opencti_canonical_standard_id(self):
        calls = []

        def query(query_text, variables):
            calls.append((query_text, variables))
            return {"data": {"dataSources": {"edges": []}}}

        lookup = OpenCTIGraphLookup(SimpleNamespace(query=query))
        lookup.find_candidate(
            {
                "stix_object_type": "x-mitre-data-source",
                "value": "Process",
                "attributes": {
                    "stix_id": (
                        "data-source--11111111-1111-4111-8111-111111111111"
                    )
                },
            }
        )

        self.assertEqual("standard_id", calls[0][1]["filters"]["filters"][0]["key"])
        self.assertEqual(
            ["data-source--11111111-1111-4111-8111-111111111111"],
            calls[0][1]["filters"]["filters"][0]["values"],
        )

    def test_intrusion_set_lookup_prefers_standard_id_before_alias(self):
        calls = []

        def query(query_text, variables):
            calls.append((query_text, variables))
            return {"data": {"intrusionSets": {"edges": []}}}

        lookup = OpenCTIGraphLookup(SimpleNamespace(query=query))
        lookup.find_candidate(
            {
                "stix_object_type": "intrusion-set",
                "value": "Palmerworm",
                "attributes": {
                    "stix_id": (
                        "intrusion-set--11111111-1111-4111-8111-111111111111"
                    )
                },
            }
        )

        self.assertEqual("standard_id", calls[0][1]["filters"]["filters"][0]["key"])

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

    def test_known_keys_for_plan_resolves_vulnerability_by_cve_name(self):
        calls = []

        def query(query_text, variables):
            calls.append((query_text, variables))
            return {
                "data": {
                    "vulnerabilities": {
                        "edges": [
                            {
                                "node": {
                                    "id": "internal--vuln",
                                    "standard_id": (
                                        "vulnerability--11111111-1111-4111-8111-"
                                        "111111111111"
                                    ),
                                    "entity_type": "Vulnerability",
                                    "name": "CVE-2026-0001",
                                }
                            }
                        ]
                    }
                }
            }

        lookup = OpenCTIGraphLookup(SimpleNamespace(query=query))
        plan, known, error = build_graph_export_plan_with_known_keys(
            accepted_named_object_policy(
                stix_object_type="vulnerability",
                entity_type="vulnerability",
                value="cve-2026-0001",
                name="CVE-2026-0001",
                relationship_type="related-to",
            ),
            mode="dry-run",
            graph_deduplication_index=lookup,
        )

        self.assertEqual("", error)
        self.assertEqual(1, len(known["entity_keys"]))
        self.assertEqual("Vulnerability", known["matches"][0]["match"]["entity_type"])
        self.assertEqual("cve_id", known["matches"][0]["match"]["match_type"])
        self.assertEqual(1, plan["deduplicated_entity_count"])
        self.assertIn("vulnerabilities", calls[0][0])
        self.assertEqual("name", calls[0][1]["filters"]["filters"][0]["key"])
        self.assertEqual(
            ["CVE-2026-0001"],
            calls[0][1]["filters"]["filters"][0]["values"],
        )

    def test_known_keys_for_plan_resolves_location_by_name(self):
        calls = []

        def query(query_text, variables):
            calls.append((query_text, variables))
            return {
                "data": {
                    "locations": {
                        "edges": [
                            {
                                "node": {
                                    "id": "internal--country",
                                    "standard_id": (
                                        "location--11111111-1111-4111-8111-"
                                        "111111111111"
                                    ),
                                    "entity_type": "Country",
                                    "name": "Argentina",
                                }
                            }
                        ]
                    }
                }
            }

        lookup = OpenCTIGraphLookup(SimpleNamespace(query=query))
        plan, known, error = build_graph_export_plan_with_known_keys(
            accepted_named_object_policy(
                stix_object_type="location",
                entity_type="target_country",
                value="Argentina",
                name="Argentina",
                relationship_type="targets",
            ),
            mode="dry-run",
            graph_deduplication_index=lookup,
        )

        self.assertEqual("", error)
        self.assertEqual(1, len(known["entity_keys"]))
        self.assertEqual("Country", known["matches"][0]["match"]["entity_type"])
        self.assertEqual("name", known["matches"][0]["match"]["match_type"])
        self.assertEqual(1, plan["deduplicated_entity_count"])
        self.assertIn("locations", calls[0][0])
        self.assertEqual("name", calls[0][1]["filters"]["filters"][0]["key"])
        self.assertEqual(
            ["Argentina"],
            calls[0][1]["filters"]["filters"][0]["values"],
        )

    def test_known_keys_for_plan_resolves_target_organization_by_name(self):
        calls = []

        def query(query_text, variables):
            calls.append((query_text, variables))
            return {
                "data": {
                    "organizations": {
                        "edges": [
                            {
                                "node": {
                                    "id": "internal--organization",
                                    "standard_id": (
                                        "identity--11111111-1111-4111-8111-"
                                        "111111111111"
                                    ),
                                    "entity_type": "Organization",
                                    "name": "Example Energy Co",
                                }
                            }
                        ]
                    }
                }
            }

        lookup = OpenCTIGraphLookup(SimpleNamespace(query=query))
        plan, known, error = build_graph_export_plan_with_known_keys(
            accepted_named_object_policy(
                stix_object_type="identity",
                entity_type="target_organization",
                value="Example Energy Co",
                name="Example Energy Co",
                relationship_type="targets",
            ),
            mode="dry-run",
            graph_deduplication_index=lookup,
        )

        self.assertEqual("", error)
        self.assertEqual(1, len(known["entity_keys"]))
        self.assertEqual("Organization", known["matches"][0]["match"]["entity_type"])
        self.assertEqual("name", known["matches"][0]["match"]["match_type"])
        self.assertEqual(1, plan["deduplicated_entity_count"])
        self.assertIn("organizations", calls[0][0])
        self.assertEqual("name", calls[0][1]["filters"]["filters"][0]["key"])

    def test_known_keys_for_plan_resolves_target_sector_by_name(self):
        calls = []

        def query(query_text, variables):
            calls.append((query_text, variables))
            return {
                "data": {
                    "sectors": {
                        "edges": [
                            {
                                "node": {
                                    "id": "internal--sector",
                                    "standard_id": (
                                        "identity--22222222-2222-4222-8222-"
                                        "222222222222"
                                    ),
                                    "entity_type": "Sector",
                                    "name": "Energy",
                                }
                            }
                        ]
                    }
                }
            }

        lookup = OpenCTIGraphLookup(SimpleNamespace(query=query))
        plan, known, error = build_graph_export_plan_with_known_keys(
            accepted_named_object_policy(
                stix_object_type="identity",
                entity_type="target_sector",
                value="Energy",
                name="Energy",
                relationship_type="targets",
            ),
            mode="dry-run",
            graph_deduplication_index=lookup,
        )

        self.assertEqual("", error)
        self.assertEqual(1, len(known["entity_keys"]))
        self.assertEqual("Sector", known["matches"][0]["match"]["entity_type"])
        self.assertEqual("name", known["matches"][0]["match"]["match_type"])
        self.assertEqual(1, plan["deduplicated_entity_count"])
        self.assertIn("sectors", calls[0][0])
        self.assertEqual("name", calls[0][1]["filters"]["filters"][0]["key"])

    def test_known_keys_for_plan_resolves_target_system_by_name(self):
        calls = []

        def query(query_text, variables):
            calls.append((query_text, variables))
            return {
                "data": {
                    "systems": {
                        "edges": [
                            {
                                "node": {
                                    "id": "internal--system",
                                    "standard_id": (
                                        "identity--33333333-3333-4333-8333-"
                                        "333333333333"
                                    ),
                                    "entity_type": "System",
                                    "name": "SAP ERP",
                                }
                            }
                        ]
                    }
                }
            }

        lookup = OpenCTIGraphLookup(SimpleNamespace(query=query))
        plan, known, error = build_graph_export_plan_with_known_keys(
            accepted_named_object_policy(
                stix_object_type="identity",
                entity_type="target_system",
                value="SAP ERP",
                name="SAP ERP",
                relationship_type="targets",
            ),
            mode="dry-run",
            graph_deduplication_index=lookup,
        )

        self.assertEqual("", error)
        self.assertEqual(1, len(known["entity_keys"]))
        self.assertEqual("System", known["matches"][0]["match"]["entity_type"])
        self.assertEqual("name", known["matches"][0]["match"]["match_type"])
        self.assertEqual(1, plan["deduplicated_entity_count"])
        self.assertIn("systems", calls[0][0])
        self.assertEqual("name", calls[0][1]["filters"]["filters"][0]["key"])

    def test_known_keys_for_plan_resolves_target_individual_by_name(self):
        calls = []

        def query(query_text, variables):
            calls.append((query_text, variables))
            return {
                "data": {
                    "individuals": {
                        "edges": [
                            {
                                "node": {
                                    "id": "internal--individual",
                                    "standard_id": (
                                        "identity--44444444-4444-4444-8444-"
                                        "444444444444"
                                    ),
                                    "entity_type": "Individual",
                                    "name": "Incident Responder",
                                }
                            }
                        ]
                    }
                }
            }

        lookup = OpenCTIGraphLookup(SimpleNamespace(query=query))
        plan, known, error = build_graph_export_plan_with_known_keys(
            accepted_named_object_policy(
                stix_object_type="identity",
                entity_type="target_individual",
                value="Incident Responder",
                name="Incident Responder",
                relationship_type="targets",
            ),
            mode="dry-run",
            graph_deduplication_index=lookup,
        )

        self.assertEqual("", error)
        self.assertEqual(1, len(known["entity_keys"]))
        self.assertEqual("Individual", known["matches"][0]["match"]["entity_type"])
        self.assertEqual("name", known["matches"][0]["match"]["match_type"])
        self.assertEqual(1, plan["deduplicated_entity_count"])
        self.assertIn("individuals", calls[0][0])
        self.assertEqual("name", calls[0][1]["filters"]["filters"][0]["key"])

    def test_known_keys_for_plan_resolves_security_platform_by_name(self):
        calls = []

        def query(query_text, variables):
            calls.append((query_text, variables))
            return {
                "data": {
                    "securityPlatforms": {
                        "edges": [
                            {
                                "node": {
                                    "id": "internal--security-platform",
                                    "standard_id": (
                                        "identity--44444444-4444-4444-8444-"
                                        "444444444444"
                                    ),
                                    "entity_type": "SecurityPlatform",
                                    "name": "Example SIEM",
                                    "security_platform_type": "SIEM",
                                }
                            }
                        ]
                    }
                }
            }

        lookup = OpenCTIGraphLookup(SimpleNamespace(query=query))
        plan, known, error = build_graph_export_plan_with_known_keys(
            accepted_named_object_policy(
                stix_object_type="security-platform",
                entity_type="security_platform",
                value="Example SIEM",
                name="Example SIEM",
                relationship_type="related-to",
                attributes={"security_platform_type": "SIEM"},
            ),
            mode="dry-run",
            graph_deduplication_index=lookup,
        )

        self.assertEqual("", error)
        self.assertEqual(1, len(known["entity_keys"]))
        self.assertEqual(
            "SecurityPlatform",
            known["matches"][0]["match"]["entity_type"],
        )
        self.assertEqual("name", known["matches"][0]["match"]["match_type"])
        self.assertEqual(1, plan["deduplicated_entity_count"])
        self.assertIn("securityPlatforms", calls[0][0])
        self.assertEqual("name", calls[0][1]["filters"]["filters"][0]["key"])

    def test_source_identity_does_not_query_organization_lookup(self):
        calls = []
        lookup = OpenCTIGraphLookup(
            SimpleNamespace(query=lambda *args: calls.append(args))
        )

        self.assertIsNone(
            lookup.find_candidate(
                {
                    "stix_object_type": "identity",
                    "entity_type": "source_identity",
                    "value": "OTX AlienVault",
                }
            )
        )
        self.assertEqual([], calls)

    def test_known_keys_for_plan_resolves_infrastructure_by_name(self):
        calls = []

        def query(query_text, variables):
            calls.append((query_text, variables))
            return {
                "data": {
                    "infrastructures": {
                        "edges": [
                            {
                                "node": {
                                    "id": "internal--infra",
                                    "standard_id": (
                                        "infrastructure--11111111-1111-4111-8111-"
                                        "111111111111"
                                    ),
                                    "entity_type": "Infrastructure",
                                    "name": "Validation C2 Infrastructure",
                                }
                            }
                        ]
                    }
                }
            }

        lookup = OpenCTIGraphLookup(SimpleNamespace(query=query))
        plan, known, error = build_graph_export_plan_with_known_keys(
            accepted_named_object_policy(
                stix_object_type="infrastructure",
                entity_type="infrastructure",
                value="Validation C2 Infrastructure",
                name="Validation C2 Infrastructure",
                relationship_type="uses",
            ),
            mode="dry-run",
            graph_deduplication_index=lookup,
        )

        self.assertEqual("", error)
        self.assertEqual(1, len(known["entity_keys"]))
        self.assertEqual(
            "Infrastructure",
            known["matches"][0]["match"]["entity_type"],
        )
        self.assertEqual("name", known["matches"][0]["match"]["match_type"])
        self.assertEqual(1, plan["deduplicated_entity_count"])
        self.assertIn("infrastructures", calls[0][0])
        self.assertEqual("name", calls[0][1]["filters"]["filters"][0]["key"])
        self.assertEqual(
            ["Validation C2 Infrastructure"],
            calls[0][1]["filters"]["filters"][0]["values"],
        )

    def test_known_keys_for_plan_resolves_autonomous_system_by_name(self):
        calls = []

        def query(query_text, variables):
            calls.append((query_text, variables))
            return {
                "data": {
                    "stixCyberObservables": {
                        "edges": [
                            {
                                "node": {
                                    "id": "internal--asn",
                                    "standard_id": (
                                        "autonomous-system--11111111-1111-4111-"
                                        "8111-111111111111"
                                    ),
                                    "entity_type": "Autonomous-System",
                                    "observable_value": (
                                        "AS64512 NarrowCTI Validation ASN"
                                    ),
                                }
                            }
                        ]
                    }
                }
            }

        lookup = OpenCTIGraphLookup(SimpleNamespace(query=query))
        plan, known, error = build_graph_export_plan_with_known_keys(
            accepted_named_object_policy(
                stix_object_type="autonomous-system",
                entity_type="autonomous_system",
                value="AS64512",
                name="NarrowCTI Validation ASN",
                relationship_type="related-to",
                attributes={"asn": 64512},
            ),
            mode="dry-run",
            graph_deduplication_index=lookup,
        )

        self.assertEqual("", error)
        self.assertEqual(1, len(known["entity_keys"]))
        self.assertEqual(
            "Autonomous-System",
            known["matches"][0]["match"]["entity_type"],
        )
        self.assertEqual(
            "AS64512 NarrowCTI Validation ASN",
            known["matches"][0]["match"]["observable_value"],
        )
        self.assertEqual("name", known["matches"][0]["match"]["match_type"])
        self.assertEqual(1, plan["deduplicated_entity_count"])
        self.assertIn("stixCyberObservables", calls[0][0])
        self.assertEqual("name", calls[0][1]["filters"]["filters"][0]["key"])
        self.assertEqual(
            ["AS64512 NarrowCTI Validation ASN"],
            calls[0][1]["filters"]["filters"][0]["values"],
        )

    def test_known_keys_for_plan_resolves_ipv4_observable_by_value(self):
        calls = []

        def query(query_text, variables):
            calls.append((query_text, variables))
            return {
                "data": {
                    "stixCyberObservables": {
                        "edges": [
                            {
                                "node": {
                                    "id": "internal--ipv4",
                                    "standard_id": (
                                        "ipv4-addr--11111111-1111-4111-"
                                        "8111-111111111111"
                                    ),
                                    "entity_type": "IPv4-Addr",
                                    "observable_value": "203.0.113.11",
                                }
                            }
                        ]
                    }
                }
            }

        lookup = OpenCTIGraphLookup(SimpleNamespace(query=query))
        plan, known, error = build_graph_export_plan_with_known_keys(
            accepted_named_object_policy(
                stix_object_type="observable",
                entity_type="observable",
                value="203.0.113.11",
                name="203.0.113.11",
                relationship_type="related-to",
                attributes={"observable_type": "ipv4-addr"},
            ),
            mode="dry-run",
            graph_deduplication_index=lookup,
        )

        self.assertEqual("", error)
        self.assertEqual(1, len(known["entity_keys"]))
        self.assertEqual(
            "IPv4-Addr",
            known["matches"][0]["match"]["entity_type"],
        )
        self.assertEqual(
            "203.0.113.11",
            known["matches"][0]["match"]["observable_value"],
        )
        self.assertEqual("value", known["matches"][0]["match"]["match_type"])
        self.assertEqual(1, plan["deduplicated_entity_count"])
        self.assertIn("stixCyberObservables", calls[0][0])
        self.assertEqual("value", calls[0][1]["filters"]["filters"][0]["key"])
        self.assertEqual(
            ["203.0.113.11"],
            calls[0][1]["filters"]["filters"][0]["values"],
        )

    def test_known_keys_for_plan_resolves_artifact_observable_by_hash(self):
        calls = []
        artifact_hash = (
            "0123456789abcdef0123456789abcdef"
            "0123456789abcdef0123456789abcdef"
        )

        def query(query_text, variables):
            calls.append((query_text, variables))
            if "GraphLookup" in query_text:
                return {"data": {"stixCyberObservables": {"edges": []}}}
            return {
                "data": {
                    "stixCyberObservables": {
                        "edges": [
                            {
                                "node": {
                                    "id": "internal--artifact",
                                    "standard_id": (
                                        "artifact--11111111-1111-4111-8111-"
                                        "111111111111"
                                    ),
                                    "entity_type": "Artifact",
                                    "observable_value": artifact_hash,
                                }
                            }
                        ]
                    }
                }
            }

        lookup = OpenCTIGraphLookup(SimpleNamespace(query=query))
        plan, known, error = build_graph_export_plan_with_known_keys(
            accepted_named_object_policy(
                stix_object_type="observable",
                entity_type="artifact",
                value=artifact_hash,
                name="NarrowCTI sample artifact",
                relationship_type="related-to",
                attributes={
                    "observable_type": "artifact",
                    "hash_algorithm": "SHA-256",
                    "artifact_url": "https://narrowcti.local/artifacts/sample.bin",
                },
            ),
            mode="dry-run",
            graph_deduplication_index=lookup,
        )

        self.assertEqual("", error)
        self.assertEqual(1, len(known["entity_keys"]))
        self.assertEqual("Artifact", known["matches"][0]["match"]["entity_type"])
        self.assertEqual(artifact_hash, known["matches"][0]["match"]["observable_value"])
        self.assertEqual("value", known["matches"][0]["match"]["match_type"])
        self.assertEqual(1, plan["deduplicated_entity_count"])
        self.assertIn("stixCyberObservables", calls[0][0])
        self.assertEqual("value", calls[0][1]["filters"]["filters"][0]["key"])
        self.assertIn("stixCyberObservables", calls[1][0])
        self.assertEqual(artifact_hash, calls[1][1]["search"])

    def test_vulnerability_lookup_prefers_standard_id_before_cve_name(self):
        calls = []

        def query(query_text, variables):
            calls.append((query_text, variables))
            return {"data": {"vulnerabilities": {"edges": []}}}

        lookup = OpenCTIGraphLookup(SimpleNamespace(query=query))
        lookup.find_candidate(
            {
                "stix_object_type": "vulnerability",
                "value": "CVE-2026-0001",
                "attributes": {
                    "stix_id": (
                        "vulnerability--11111111-1111-4111-8111-111111111111"
                    )
                },
            }
        )

        self.assertEqual("standard_id", calls[0][1]["filters"]["filters"][0]["key"])

    def test_location_lookup_prefers_standard_id_before_name(self):
        calls = []

        def query(query_text, variables):
            calls.append((query_text, variables))
            return {"data": {"locations": {"edges": []}}}

        lookup = OpenCTIGraphLookup(SimpleNamespace(query=query))
        lookup.find_candidate(
            {
                "stix_object_type": "location",
                "value": "Argentina",
                "attributes": {
                    "stix_id": "location--11111111-1111-4111-8111-111111111111"
                },
            }
        )

        self.assertEqual("standard_id", calls[0][1]["filters"]["filters"][0]["key"])

    def test_infrastructure_lookup_prefers_standard_id_before_name(self):
        calls = []

        def query(query_text, variables):
            calls.append((query_text, variables))
            return {"data": {"infrastructures": {"edges": []}}}

        lookup = OpenCTIGraphLookup(SimpleNamespace(query=query))
        lookup.find_candidate(
            {
                "stix_object_type": "infrastructure",
                "value": "Validation C2 Infrastructure",
                "attributes": {
                    "stix_id": (
                        "infrastructure--11111111-1111-4111-8111-111111111111"
                    )
                },
            }
        )

        self.assertEqual("standard_id", calls[0][1]["filters"]["filters"][0]["key"])

    def test_autonomous_system_lookup_prefers_standard_id_before_name(self):
        calls = []

        def query(query_text, variables):
            calls.append((query_text, variables))
            return {"data": {"stixCyberObservables": {"edges": []}}}

        lookup = OpenCTIGraphLookup(SimpleNamespace(query=query))
        lookup.find_candidate(
            {
                "stix_object_type": "autonomous-system",
                "value": "AS64512",
                "attributes": {
                    "stix_id": (
                        "autonomous-system--11111111-1111-4111-8111-111111111111"
                    )
                },
            }
        )

        self.assertEqual("standard_id", calls[0][1]["filters"]["filters"][0]["key"])

    def test_observable_lookup_prefers_actual_standard_id_before_value(self):
        calls = []

        def query(query_text, variables):
            calls.append((query_text, variables))
            return {"data": {"stixCyberObservables": {"edges": []}}}

        lookup = OpenCTIGraphLookup(SimpleNamespace(query=query))
        lookup.find_candidate(
            {
                "stix_object_type": "observable",
                "value": "203.0.113.11",
                "attributes": {
                    "observable_type": "ipv4-addr",
                    "stix_id": (
                        "ipv4-addr--11111111-1111-4111-8111-111111111111"
                    ),
                },
            }
        )

        self.assertEqual("standard_id", calls[0][1]["filters"]["filters"][0]["key"])

    def test_vulnerability_external_id_reads_cve_reference(self):
        self.assertEqual(
            "CVE-2026-0001",
            vulnerability_external_id(
                {
                    "stix_object_type": "vulnerability",
                    "value": "known vuln",
                    "attributes": {
                        "external_references": [
                            {"source_name": "vendor", "external_id": "X-1"},
                            {"source_name": "cve", "external_id": "cve-2026-0001"},
                        ]
                    },
                }
            ),
        )

    def test_lookup_resolves_opencti_custom_sdos_by_name(self):
        calls = []

        def query(query_text, variables):
            calls.append((query_text, variables))
            if "channels" in query_text:
                collection_name = "channels"
                standard_id = "channel--11111111-1111-4111-8111-111111111111"
                entity_type = "Channel"
            elif "narratives" in query_text:
                collection_name = "narratives"
                standard_id = "narrative--11111111-1111-4111-8111-111111111111"
                entity_type = "Narrative"
            else:
                collection_name = "events"
                standard_id = "event--11111111-1111-4111-8111-111111111111"
                entity_type = "Event"
            name = variables["filters"]["filters"][0]["values"][0]
            return {
                "data": {
                    collection_name: {
                        "edges": [
                            {
                                "node": {
                                    "id": f"internal--{collection_name}",
                                    "standard_id": standard_id,
                                    "entity_type": entity_type,
                                    "name": name,
                                }
                            }
                        ]
                    }
                }
            }

        lookup = OpenCTIGraphLookup(SimpleNamespace(query=query))

        for stix_object_type, value in (
            ("channel", "Telegram C2"),
            ("narrative", "Credential theft objective"),
            ("event", "Observed phishing wave"),
        ):
            match = lookup.find_candidate(
                {
                    "stix_object_type": stix_object_type,
                    "value": value,
                }
            )
            self.assertEqual(value, match["name"])
            self.assertEqual("name", match["match_type"])

        queried_collections = [call[0] for call in calls]
        self.assertTrue(any("channels" in query_text for query_text in queried_collections))
        self.assertTrue(any("narratives" in query_text for query_text in queried_collections))
        self.assertTrue(any("events" in query_text for query_text in queried_collections))

    def test_unsupported_candidate_does_not_query_opencti(self):
        calls = []
        lookup = OpenCTIGraphLookup(
            SimpleNamespace(query=lambda *args: calls.append(args))
        )

        self.assertIsNone(
            lookup.find_candidate(
                {
                    "stix_object_type": "identity",
                    "value": "Finance",
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


def graph_node_response(collection, opencti_id, entity_type, name):
    return {
        "data": {
            collection: {
                "edges": [
                    {
                        "node": {
                            "id": opencti_id,
                            "standard_id": f"{entity_type.lower()}--standard",
                            "entity_type": entity_type,
                            "name": name,
                        }
                    }
                ]
            }
        }
    }


def relationship_candidate():
    return {
        "entity_type": "malware",
        "value": "Lumma Stealer",
        "name": "Lumma Stealer",
        "stix_object_type": "malware",
        "relationship_type": "uses",
        "source_key": "alienvault:otx",
        "external_id": "pulse-1",
        "attributes": {
            "relationship_source_stix_object_type": "intrusion-set",
            "relationship_source_value": "APT Example",
        },
    }


def accepted_named_object_policy(
    stix_object_type,
    entity_type,
    value,
    name,
    relationship_type,
    attributes=None,
):
    record = {
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
    if attributes:
        record["attributes"] = attributes
    candidates = build_graph_candidates(
        {
            "version": "v0.8.0-dev",
            "source_key": "alienvault:otx",
            "external_id": "pulse-1",
            "title": "Arsenal pulse",
            "records": [record],
        }
    )
    return apply_graph_candidate_policy(
        candidates,
        min_entity_confidence=50,
        min_relationship_confidence=60,
    ).to_dict()


if __name__ == "__main__":
    unittest.main()
