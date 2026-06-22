import unittest

from core.graph_evidence import build_graph_evidence


class GraphEvidenceTests(unittest.TestCase):
    def test_builds_otx_and_mitre_graph_evidence_records(self):
        evidence = build_graph_evidence(
            {
                "otx_entities": {
                    "records": [
                        {
                            "entity_type": "threat_actor",
                            "value": "APT Example",
                            "source_field": "adversary",
                            "confidence": 60,
                        },
                        {
                            "entity_type": "attack_pattern",
                            "value": "T1059",
                            "source_field": "attack_ids",
                            "confidence": 70,
                        },
                    ]
                },
                "mitre_attack": {
                    "available": True,
                    "resolved": [
                        {
                            "attack_id": "T1059",
                            "found": True,
                            "name": "Command and Scripting Interpreter",
                            "tactics": ["execution"],
                            "stix_id": "attack-pattern--1",
                            "source_name": "mitre-attack",
                            "url": "https://attack.mitre.org/techniques/T1059/",
                        }
                    ],
                },
            },
            source_key="alienvault:otx",
            external_id="pulse-1",
            title="Technique pulse",
        )

        self.assertEqual("v0.7.0-dev", evidence["version"])
        self.assertEqual("alienvault:otx", evidence["source_key"])
        self.assertEqual(4, evidence["record_count"])
        self.assertEqual(2, evidence["counts"]["attack_pattern"])
        self.assertIn(
            {
                "entity_type": "threat_actor",
                "value": "APT Example",
                "stix_object_type": "threat-actor",
                "relationship_type": "attributed-to",
                "source_key": "alienvault:otx",
                "source_name": "otx",
                "source_field": "adversary",
                "confidence": 60,
            },
            evidence["records"],
        )
        self.assertIn(
            {
                "entity_type": "attack_tactic",
                "value": "execution",
                "stix_object_type": "x-mitre-tactic",
                "relationship_type": "uses",
                "source_key": "alienvault:otx",
                "source_name": "mitre-attack",
                "source_field": "mitre_attack.resolved.tactics",
                "confidence": 85,
                "attributes": {"technique": "T1059"},
            },
            evidence["records"],
        )

    def test_builds_misp_provenance_tags_and_marking_evidence(self):
        evidence = build_graph_evidence(
            {
                "collector": "misp",
                "original_source": "AlienVault",
                "tags": ["tlp:green", "ransomware"],
            },
            source_key="misp:misp",
            external_id="event-1",
            title="MISP event",
        )

        self.assertEqual(4, evidence["record_count"])
        self.assertEqual(1, evidence["counts"]["marking"])
        self.assertIn(
            {
                "entity_type": "source_identity",
                "value": "AlienVault",
                "stix_object_type": "identity",
                "relationship_type": "originated-from",
                "source_key": "misp:misp",
                "source_name": "misp",
                "source_field": "provenance.original_source",
                "confidence": 70,
            },
            evidence["records"],
        )
        self.assertIn(
            {
                "entity_type": "marking",
                "value": "green",
                "stix_object_type": "marking-definition",
                "relationship_type": "marked-with",
                "source_key": "misp:misp",
                "source_name": "misp",
                "source_field": "tags",
                "confidence": 80,
            },
            evidence["records"],
        )


if __name__ == "__main__":
    unittest.main()
