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
                        {
                            "entity_type": "vulnerability",
                            "value": "CVE-2024-12345",
                            "source_field": "vulnerabilities",
                            "confidence": 75,
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
        self.assertEqual(9, evidence["record_count"])
        self.assertEqual(2, evidence["counts"]["attack_pattern"])
        self.assertEqual(1, evidence["counts"]["vulnerability"])
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
                "entity_type": "vulnerability",
                "value": "CVE-2024-12345",
                "stix_object_type": "vulnerability",
                "relationship_type": "related-to",
                "source_key": "alienvault:otx",
                "source_name": "otx",
                "source_field": "vulnerabilities",
                "confidence": 75,
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

    def test_builds_otx_detection_rule_evidence(self):
        evidence = build_graph_evidence(
            {
                "otx_entities": {
                    "records": [
                        {
                            "entity_type": "detection_rule",
                            "value": "Suspicious YARA rule",
                            "source_field": "indicators",
                            "confidence": 70,
                            "attributes": {
                                "rule_type": "yara",
                                "pattern_type": "yara",
                                "pattern": "rule SuspiciousRule { condition: true }",
                                "indicator_type": "YARA",
                                "indicator_id": "indicator-yara-1",
                            },
                        }
                    ]
                }
            },
            source_key="alienvault:otx",
            external_id="pulse-1",
            title="OTX pulse",
        )

        self.assertEqual(1, evidence["record_count"])
        self.assertEqual(1, evidence["counts"]["detection_rule"])
        self.assertIn(
            {
                "entity_type": "detection_rule",
                "value": "Suspicious YARA rule",
                "stix_object_type": "indicator",
                "relationship_type": "detects",
                "source_key": "alienvault:otx",
                "source_name": "otx",
                "source_field": "indicators",
                "confidence": 70,
                "attributes": {
                    "rule_type": "yara",
                    "pattern_type": "yara",
                    "pattern": "rule SuspiciousRule { condition: true }",
                    "indicator_type": "YARA",
                    "indicator_id": "indicator-yara-1",
                },
            },
            evidence["records"],
        )

    def test_builds_otx_observable_evidence(self):
        evidence = build_graph_evidence(
            {
                "otx_entities": {
                    "records": [
                        {
                            "entity_type": "observable",
                            "value": "one.example",
                            "source_field": "indicators",
                            "confidence": 65,
                            "attributes": {
                                "observable_type": "domain-name",
                                "indicator_type": "domain",
                                "first_seen": "2026-04-01T10:00:00Z",
                                "last_seen": "2026-04-02T10:00:00Z",
                            },
                        }
                    ]
                }
            },
            source_key="alienvault:otx",
            external_id="pulse-1",
            title="OTX pulse",
        )

        self.assertEqual(1, evidence["record_count"])
        self.assertEqual(1, evidence["counts"]["observable"])
        self.assertIn(
            {
                "entity_type": "observable",
                "value": "one.example",
                "stix_object_type": "observable",
                "relationship_type": "based-on",
                "source_key": "alienvault:otx",
                "source_name": "otx",
                "source_field": "indicators",
                "confidence": 65,
                "attributes": {
                    "observable_type": "domain-name",
                    "indicator_type": "domain",
                    "first_seen": "2026-04-01T10:00:00Z",
                    "last_seen": "2026-04-02T10:00:00Z",
                },
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

    def test_builds_misp_galaxy_graph_evidence(self):
        evidence = build_graph_evidence(
            {
                "collector": "misp",
                "misp_galaxies": [
                    {
                        "type": "mitre-attack-pattern",
                        "value": "Command and Scripting Interpreter - T1059",
                        "uuid": "cluster-attack",
                        "tag_name": 'misp-galaxy:mitre-attack-pattern="T1059"',
                        "galaxy_type": "mitre-attack-pattern",
                        "galaxy_name": "MITRE ATT&CK",
                        "source_field": "Galaxy",
                        "meta": {
                            "external_id": ["T1059"],
                            "refs": ["https://attack.mitre.org/techniques/T1059/"],
                        },
                    },
                    {
                        "type": "threat-actor",
                        "value": "APT Example",
                        "uuid": "cluster-actor",
                        "galaxy_type": "threat-actor",
                        "galaxy_name": "Threat Actor",
                        "source_field": "Galaxy",
                        "meta": {
                            "synonyms": ["Example Group"],
                            "targeted-sector": ["Activists", "Journalist"],
                            "targeted-country": ["AR"],
                        },
                    },
                    {
                        "type": "sector",
                        "value": "Finance",
                        "galaxy_type": "sector",
                        "source_field": "Galaxy",
                    },
                ],
            },
            source_key="misp:misp",
            external_id="event-1",
            title="MISP event",
        )

        self.assertEqual(7, evidence["record_count"])
        self.assertEqual(1, evidence["counts"]["attack_pattern"])
        self.assertEqual(1, evidence["counts"]["threat_actor"])
        self.assertEqual(3, evidence["counts"]["target_sector"])
        self.assertEqual(1, evidence["counts"]["target_country"])
        attack = next(
            record for record in evidence["records"] if record["entity_type"] == "attack_pattern"
        )
        self.assertEqual("T1059", attack["value"])
        self.assertEqual("attack-pattern", attack["stix_object_type"])
        self.assertEqual(
            "Command and Scripting Interpreter - T1059",
            attack["display_name"],
        )
        self.assertEqual("T1059", attack["attributes"]["external_id"])
        self.assertEqual(
            ["https://attack.mitre.org/techniques/T1059/"],
            attack["attributes"]["meta"]["refs"],
        )
        sector = next(
            record
            for record in evidence["records"]
            if record["entity_type"] == "target_sector"
            and record["value"] == "Activists"
        )
        self.assertEqual("Galaxy.meta.targeted-sector", sector["source_field"])
        self.assertEqual(
            "APT Example",
            sector["attributes"]["parent_cluster_value"],
        )
        country = next(
            record
            for record in evidence["records"]
            if record["entity_type"] == "target_country"
        )
        self.assertEqual("AR", country["value"])

    def test_builds_misp_vulnerability_graph_evidence(self):
        evidence = build_graph_evidence(
            {
                "misp_vulnerabilities": [
                    {
                        "value": "CVE-2024-12345",
                        "source_field": "Attribute[0]",
                        "source_type": "attribute",
                        "attribute_type": "vulnerability",
                        "attribute_category": "External analysis",
                        "attribute_uuid": "attr-cve",
                        "tags": ["exploit:known"],
                    }
                ],
                "misp_galaxies": [
                    {
                        "type": "branded-vulnerability",
                        "value": "CVE-2023-9999",
                        "uuid": "cluster-cve",
                        "galaxy_type": "branded-vulnerability",
                        "galaxy_name": "Branded Vulnerability",
                        "source_field": "Galaxy",
                        "meta": {"refs": ["https://nvd.nist.gov/vuln/detail/CVE-2023-9999"]},
                    }
                ],
            },
            source_key="misp:misp",
            external_id="event-1",
            title="MISP event",
        )

        self.assertEqual(2, evidence["record_count"])
        self.assertEqual(2, evidence["counts"]["vulnerability"])
        self.assertIn(
            {
                "entity_type": "vulnerability",
                "value": "CVE-2024-12345",
                "stix_object_type": "vulnerability",
                "relationship_type": "related-to",
                "source_key": "misp:misp",
                "source_name": "misp",
                "source_field": "Attribute[0]",
                "confidence": 75,
                "attributes": {
                    "source_type": "attribute",
                    "attribute_type": "vulnerability",
                    "attribute_category": "External analysis",
                    "attribute_uuid": "attr-cve",
                    "tags": ["exploit:known"],
                },
            },
            evidence["records"],
        )
        galaxy_vulnerability = next(
            record
            for record in evidence["records"]
            if record["source_name"] == "misp-galaxy"
        )
        self.assertEqual("CVE-2023-9999", galaxy_vulnerability["value"])
        self.assertEqual("CVE-2023-9999", galaxy_vulnerability["attributes"]["external_id"])

    def test_builds_misp_event_report_note_evidence(self):
        evidence = build_graph_evidence(
            {
                "misp_event_reports": [
                    {
                        "title": "Initial analyst report",
                        "content": "The event describes exploitation activity.",
                        "uuid": "event-report-1",
                        "timestamp": "1782004900",
                        "source_field": "EventReport[0]",
                    }
                ]
            },
            source_key="misp:misp",
            external_id="event-1",
            title="MISP event",
        )

        self.assertEqual(1, evidence["record_count"])
        self.assertEqual(1, evidence["counts"]["event_report"])
        self.assertIn(
            {
                "entity_type": "event_report",
                "value": "Initial analyst report",
                "stix_object_type": "note",
                "relationship_type": "documents",
                "source_key": "misp:misp",
                "source_name": "misp",
                "source_field": "EventReport[0]",
                "confidence": 70,
                "attributes": {
                    "content": "The event describes exploitation activity.",
                    "event_report_uuid": "event-report-1",
                    "timestamp": "1782004900",
                },
            },
            evidence["records"],
        )

    def test_builds_misp_sighting_evidence(self):
        evidence = build_graph_evidence(
            {
                "misp_sightings": [
                    {
                        "value": "evil.example",
                        "sighting_id": "42",
                        "date_sighting": "1782004900",
                        "source": "SOC",
                        "organization": "Example Org",
                        "attribute_type": "domain",
                        "attribute_uuid": "attribute-1",
                        "source_field": "Attribute[0].Sighting[0]",
                    }
                ]
            },
            source_key="misp:misp",
            external_id="event-1",
            title="MISP event",
        )

        self.assertEqual(1, evidence["record_count"])
        self.assertEqual(1, evidence["counts"]["sighting"])
        self.assertIn(
            {
                "entity_type": "sighting",
                "value": "evil.example",
                "stix_object_type": "sighting",
                "relationship_type": "sighting-of",
                "source_key": "misp:misp",
                "source_name": "misp",
                "source_field": "Attribute[0].Sighting[0]",
                "confidence": 65,
                "attributes": {
                    "sighting_id": "42",
                    "date_sighting": "1782004900",
                    "source": "SOC",
                    "organization": "Example Org",
                    "attribute_type": "domain",
                    "attribute_uuid": "attribute-1",
                },
            },
            evidence["records"],
        )

    def test_builds_misp_object_reference_evidence(self):
        evidence = build_graph_evidence(
            {
                "misp_object_references": [
                    {
                        "value": "object-1 uses object-2",
                        "relationship_type": "uses",
                        "reference_uuid": "reference-1",
                        "source_uuid": "object-1",
                        "source_name": "malware",
                        "target_uuid": "object-2",
                        "target_type": "object",
                        "comment": "Malware uses this infrastructure.",
                        "source_field": "Object[0].ObjectReference[0]",
                    }
                ]
            },
            source_key="misp:misp",
            external_id="event-1",
            title="MISP event",
        )

        self.assertEqual(1, evidence["record_count"])
        self.assertEqual(1, evidence["counts"]["object_reference"])
        self.assertIn(
            {
                "entity_type": "object_reference",
                "value": "object-1 uses object-2",
                "stix_object_type": "relationship",
                "relationship_type": "uses",
                "source_key": "misp:misp",
                "source_name": "misp",
                "source_field": "Object[0].ObjectReference[0]",
                "confidence": 60,
                "attributes": {
                    "reference_uuid": "reference-1",
                    "source_uuid": "object-1",
                    "source_name": "malware",
                    "target_uuid": "object-2",
                    "target_type": "object",
                    "comment": "Malware uses this infrastructure.",
                },
            },
            evidence["records"],
        )

    def test_builds_misp_detection_rule_evidence(self):
        evidence = build_graph_evidence(
            {
                "misp_detection_rules": [
                    {
                        "value": "Suspicious PowerShell",
                        "rule_type": "sigma",
                        "pattern_type": "sigma",
                        "pattern": "title: Suspicious PowerShell",
                        "attribute_category": "Payload delivery",
                        "attribute_uuid": "attribute-rule-1",
                        "tags": ["tlp:green"],
                        "source_field": "Attribute[0]",
                    }
                ]
            },
            source_key="misp:misp",
            external_id="event-1",
            title="MISP event",
        )

        self.assertEqual(1, evidence["record_count"])
        self.assertEqual(1, evidence["counts"]["detection_rule"])
        self.assertIn(
            {
                "entity_type": "detection_rule",
                "value": "Suspicious PowerShell",
                "stix_object_type": "indicator",
                "relationship_type": "detects",
                "source_key": "misp:misp",
                "source_name": "misp",
                "source_field": "Attribute[0]",
                "confidence": 70,
                "attributes": {
                    "rule_type": "sigma",
                    "pattern_type": "sigma",
                    "pattern": "title: Suspicious PowerShell",
                    "attribute_category": "Payload delivery",
                    "attribute_uuid": "attribute-rule-1",
                    "tags": ["tlp:green"],
                },
            },
            evidence["records"],
        )


if __name__ == "__main__":
    unittest.main()
