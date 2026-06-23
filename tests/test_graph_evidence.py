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
                            "description": "Interpreters execute commands.",
                            "tactics": ["execution"],
                            "stix_id": "attack-pattern--1",
                            "source_name": "mitre-attack",
                            "url": "https://attack.mitre.org/techniques/T1059/",
                            "platforms": ["Windows"],
                            "data_sources": ["Process: Process Creation"],
                            "detection": "Monitor process execution.",
                            "domains": ["enterprise-attack"],
                            "version": "2.6",
                            "attack_spec_version": "3.3.0",
                            "created": "2020-01-01T00:00:00.000Z",
                            "modified": "2026-01-01T00:00:00.000Z",
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
        self.assertEqual(8, evidence["record_count"])
        self.assertEqual(2, evidence["counts"]["attack_pattern"])
        self.assertEqual(1, evidence["counts"]["attack_platform"])
        self.assertEqual(1, evidence["counts"]["attack_data_source"])
        self.assertEqual(1, evidence["counts"]["detection_guidance"])
        self.assertEqual(1, evidence["counts"]["external_reference"])
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
        technique = next(
            record
            for record in evidence["records"]
            if record["entity_type"] == "attack_pattern"
            and record["source_field"] == "mitre_attack.resolved"
        )
        self.assertEqual(["Windows"], technique["attributes"]["platforms"])
        self.assertEqual(
            ["Process: Process Creation"],
            technique["attributes"]["data_sources"],
        )
        self.assertEqual(
            "Monitor process execution.",
            technique["attributes"]["detection"],
        )
        self.assertEqual(
            [
                {
                    "source_name": "mitre-attack",
                    "external_id": "T1059",
                    "url": "https://attack.mitre.org/techniques/T1059/",
                }
            ],
            technique["attributes"]["external_references"],
        )
        self.assertEqual(
            [{"kill_chain_name": "mitre-attack", "phase_name": "execution"}],
            technique["attributes"]["kill_chain_phases"],
        )
        self.assertIn(
            {
                "entity_type": "external_reference",
                "value": "https://attack.mitre.org/techniques/T1059/",
                "stix_object_type": "external-reference",
                "relationship_type": "references",
                "source_key": "alienvault:otx",
                "source_name": "mitre-attack",
                "source_field": "mitre_attack.resolved.url",
                "confidence": 90,
                "display_name": "MITRE ATT&CK T1059",
                "attributes": {
                    "source_name": "mitre-attack",
                    "external_id": "T1059",
                    "technique": "T1059",
                    "url": "https://attack.mitre.org/techniques/T1059/",
                },
            },
            evidence["records"],
        )
        self.assertIn(
            {
                "entity_type": "attack_platform",
                "value": "Windows",
                "stix_object_type": "x-narrowcti-attack-platform",
                "relationship_type": "applies-to",
                "source_key": "alienvault:otx",
                "source_name": "mitre-attack",
                "source_field": "mitre_attack.resolved.platforms",
                "confidence": 75,
                "attributes": {"technique": "T1059"},
            },
            evidence["records"],
        )
        self.assertIn(
            {
                "entity_type": "attack_data_source",
                "value": "Process: Process Creation",
                "stix_object_type": "x-mitre-data-source",
                "relationship_type": "detects",
                "source_key": "alienvault:otx",
                "source_name": "mitre-attack",
                "source_field": "mitre_attack.resolved.data_sources",
                "confidence": 80,
                "attributes": {"technique": "T1059"},
            },
            evidence["records"],
        )
        self.assertTrue(
            any(
                record["entity_type"] == "detection_guidance"
                and record["display_name"] == "Detection guidance for T1059"
                and record["value"] == "Monitor process execution."
                for record in evidence["records"]
            )
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
