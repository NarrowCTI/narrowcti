import json
import unittest

from exporters.stix_builder import build_graph_report_bundle


class GraphStixBuilderTests(unittest.TestCase):
    def test_builds_graph_report_bundle_from_accepted_candidates(self):
        bundle, summary = build_graph_report_bundle(
            "Curated graph report",
            "graph context",
            80,
            graph_candidate_policy={
                "accepted": [
                    attack_pattern_candidate(),
                    attack_pattern_candidate(),
                    threat_actor_candidate(),
                    vulnerability_candidate(),
                    observable_candidate(),
                    detection_rule_candidate(),
                ],
                "held": [
                    {
                        "candidate": unsupported_candidate(),
                        "reasons": ["entity_confidence_below_min"],
                    }
                ],
            },
        )

        data = json.loads(bundle.serialize())
        objects_by_type = {}
        for item in data["objects"]:
            objects_by_type.setdefault(item["type"], []).append(item)

        self.assertEqual(6, summary["accepted_candidate_count"])
        self.assertEqual(5, summary["graph_object_count"])
        self.assertEqual(5, summary["graph_relationship_count"])
        self.assertEqual(0, summary["skipped_candidate_count"])
        self.assertEqual(
            {
                "attack-pattern": 1,
                "domain-name": 1,
                "indicator": 1,
                "threat-actor": 1,
                "vulnerability": 1,
            },
            summary["object_counts"],
        )
        self.assertEqual(1, len(objects_by_type["attack-pattern"]))
        self.assertEqual(1, len(objects_by_type["threat-actor"]))
        self.assertEqual(1, len(objects_by_type["vulnerability"]))
        self.assertEqual(1, len(objects_by_type["domain-name"]))
        self.assertEqual(1, len(objects_by_type["indicator"]))
        self.assertEqual(5, len(objects_by_type["relationship"]))

        attack_pattern = objects_by_type["attack-pattern"][0]
        self.assertEqual("Command and Scripting Interpreter", attack_pattern["name"])
        self.assertIn(
            {"source_name": "mitre-attack", "external_id": "T1059"},
            attack_pattern["external_references"],
        )
        self.assertEqual(
            "uses",
            attack_pattern["x_narrowcti_proposed_relationship_type"],
        )

        reports = objects_by_type["report"]
        self.assertEqual(1, len(reports))
        self.assertEqual(5, len(reports[0]["object_refs"]))
        self.assertTrue(
            all(
                relationship["source_ref"] == reports[0]["id"]
                and relationship["relationship_type"] == "related-to"
                for relationship in objects_by_type["relationship"]
            )
        )

    def test_skips_invalid_or_unsupported_graph_candidates(self):
        _, summary = build_graph_report_bundle(
            "Curated graph report",
            "graph context",
            80,
            graph_candidate_policy={
                "accepted": [
                    unsupported_candidate(),
                    {
                        "entity_type": "observable",
                        "value": "bad-hash",
                        "name": "bad-hash",
                        "stix_object_type": "observable",
                        "relationship_type": "based-on",
                        "confidence": 65,
                        "attributes": {
                            "observable_type": "file",
                            "hash_algorithm": "SHA-256",
                        },
                    },
                ]
            },
        )

        self.assertEqual(2, summary["accepted_candidate_count"])
        self.assertEqual(0, summary["graph_object_count"])
        self.assertEqual(0, summary["graph_relationship_count"])
        self.assertEqual(2, summary["skipped_candidate_count"])


def attack_pattern_candidate():
    return {
        "fingerprint": "attack-1",
        "entity_type": "attack_pattern",
        "value": "T1059",
        "name": "Command and Scripting Interpreter",
        "stix_object_type": "attack-pattern",
        "relationship_type": "uses",
        "source_key": "alienvault:otx",
        "source_name": "mitre-attack",
        "source_field": "mitre_attack.resolved",
        "confidence": 90,
        "relationship_confidence": 85,
    }


def threat_actor_candidate():
    return {
        "fingerprint": "actor-1",
        "entity_type": "threat_actor",
        "value": "APT Example",
        "name": "APT Example",
        "stix_object_type": "threat-actor",
        "relationship_type": "attributed-to",
        "source_key": "alienvault:otx",
        "source_name": "otx",
        "source_field": "adversary",
        "confidence": 70,
        "relationship_confidence": 65,
    }


def vulnerability_candidate():
    return {
        "fingerprint": "vuln-1",
        "entity_type": "vulnerability",
        "value": "CVE-2026-0001",
        "name": "CVE-2026-0001",
        "stix_object_type": "vulnerability",
        "relationship_type": "related-to",
        "source_key": "alienvault:otx",
        "source_name": "otx",
        "source_field": "indicators",
        "confidence": 70,
        "relationship_confidence": 60,
    }


def observable_candidate():
    return {
        "fingerprint": "observable-1",
        "entity_type": "observable",
        "value": "one.example",
        "name": "one.example",
        "stix_object_type": "observable",
        "relationship_type": "based-on",
        "source_key": "alienvault:otx",
        "source_name": "otx",
        "source_field": "indicators",
        "confidence": 65,
        "relationship_confidence": 65,
        "attributes": {
            "observable_type": "domain-name",
            "indicator_type": "domain",
        },
    }


def detection_rule_candidate():
    return {
        "fingerprint": "rule-1",
        "entity_type": "detection_rule",
        "value": "Suspicious PowerShell",
        "name": "Suspicious PowerShell",
        "stix_object_type": "indicator",
        "relationship_type": "detects",
        "source_key": "misp:event",
        "source_name": "misp",
        "source_field": "Attribute[0]",
        "confidence": 75,
        "relationship_confidence": 70,
        "attributes": {
            "pattern": "title: Suspicious PowerShell",
            "pattern_type": "sigma",
        },
    }


def unsupported_candidate():
    return {
        "entity_type": "unknown",
        "value": "unknown",
        "name": "unknown",
        "stix_object_type": "x-unsupported",
        "relationship_type": "related-to",
        "confidence": 50,
        "relationship_confidence": 50,
    }


if __name__ == "__main__":
    unittest.main()
