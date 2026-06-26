import unittest

from connectors.otx.entity_extraction import (
    extract_otx_entities,
    normalize_attack_ids,
    normalize_cve_ids,
    normalize_references,
    normalize_tlp,
)


class OTXEntityExtractionTests(unittest.TestCase):
    def test_extracts_enterprise_entity_hints_from_otx_payload(self):
        entities = extract_otx_entities(
            {
                "adversary": "APT Example",
                "malware_families": [
                    "LummaC2",
                    {"display_name": "Stealc", "id": "malware-1"},
                ],
                "attack_ids": ["T1059", "Uses T1105 and T1059.001"],
                "cves": ["CVE-2024-12345", "reference to cve-2023-9999"],
                "industries": "Finance, Healthcare",
                "target_countries": ["BR", "US"],
                "author_name": "AlienVault Research",
                "author": "2",
                "id": "pulse-1",
                "created": "2026-04-01T00:00:00Z",
                "modified": "2026-04-03T00:00:00Z",
                "upvotes_count": 7,
                "downvotes_count": 1,
                "TLP": "TLP:AMBER",
                "references": [
                    "https://example.com/report",
                    {"url": "https://vendor.example/ioc", "source_name": "Vendor"},
                ],
                "indicators": [
                    {
                        "type": "domain",
                        "indicator": "one.example",
                        "first_seen": "2026-04-01T10:00:00Z",
                        "last_seen": "2026-04-02T10:00:00Z",
                    },
                    {
                        "type": "url",
                        "indicator": "https://two.example/a",
                        "first_seen": "2026-04-02T10:00:00Z",
                        "last_seen": "2026-04-05T10:00:00Z",
                    },
                    {
                        "id": "indicator-yara-1",
                        "type": "YARA",
                        "indicator": "rule SuspiciousRule { condition: true }",
                        "description": "Suspicious YARA rule",
                    },
                ],
                "tags": ["credential theft", "T1059"],
            }
        )

        self.assertEqual(["APT Example"], entities["adversaries"])
        self.assertEqual(["LummaC2", "Stealc"], entities["malware_families"])
        self.assertEqual(["T1059", "T1105", "T1059.001"], entities["attack_ids"])
        self.assertEqual(["CVE-2024-12345", "CVE-2023-9999"], entities["vulnerabilities"])
        self.assertEqual(["Finance", "Healthcare"], entities["industries"])
        self.assertEqual(["BR", "US"], entities["targeted_countries"])
        self.assertEqual(["AlienVault Research"], entities["authors"])
        self.assertFalse(
            any(
                record["entity_type"] == "source_identity"
                for record in entities["records"]
            )
        )
        self.assertEqual("pulse-1", entities["lifecycle"]["pulse_id"])
        self.assertEqual("2026-04-03T00:00:00Z", entities["lifecycle"]["modified"])
        self.assertEqual(7, entities["vote_summary"]["upvotes"])
        self.assertEqual(
            "2026-04-01T10:00:00Z",
            entities["indicator_observation_window"]["first_seen_min"],
        )
        self.assertEqual(
            "2026-04-05T10:00:00Z",
            entities["indicator_observation_window"]["last_seen_max"],
        )
        self.assertEqual(2, len(entities["observables"]))
        self.assertEqual("domain-name", entities["observables"][0]["observable_type"])
        self.assertEqual("url", entities["observables"][1]["observable_type"])
        self.assertEqual(
            ["APT Example OTX observed infrastructure pulse-1"],
            entities["infrastructures"],
        )
        self.assertEqual(1, len(entities["detection_rules"]))
        self.assertEqual("yara", entities["detection_rules"][0]["rule_type"])
        self.assertEqual(
            "rule SuspiciousRule { condition: true }",
            entities["detection_rules"][0]["pattern"],
        )
        self.assertEqual(["amber"], entities["tlp"])
        self.assertEqual(
            {"url": "https://vendor.example/ioc", "source_name": "Vendor"},
            entities["references"][1],
        )
        attack_pattern = next(
            record
            for record in entities["records"]
            if record["entity_type"] == "attack_pattern"
            and record["value"] == "T1059.001"
            and record["attributes"]["relationship_source_stix_object_type"]
            == "intrusion-set"
        )
        self.assertEqual("attack_ids", attack_pattern["source_field"])
        self.assertEqual(70, attack_pattern["confidence"])
        self.assertEqual(
            {
                "relationship_source_stix_object_type": "intrusion-set",
                "relationship_source_value": "APT Example",
                "relationship_source_field": "adversary",
            },
            attack_pattern["attributes"],
        )
        sector = next(
            record
            for record in entities["records"]
            if record["entity_type"] == "target_sector"
            and record["value"] == "Finance"
        )
        self.assertEqual(
            "APT Example",
            sector["attributes"]["relationship_source_value"],
        )
        self.assertEqual(3, entities["counts"]["attack_ids"])
        self.assertEqual(2, entities["counts"]["vulnerabilities"])
        self.assertEqual(2, entities["counts"]["observables"])
        self.assertEqual(1, entities["counts"]["infrastructures"])
        self.assertEqual(1, entities["counts"]["detection_rules"])
        self.assertIn(
            {
                "entity_type": "infrastructure",
                "value": "APT Example OTX observed infrastructure pulse-1",
                "source_field": "infrastructures",
                "confidence": 65,
                "attributes": {
                    "relationship_source_stix_object_type": "intrusion-set",
                    "relationship_source_value": "APT Example",
                    "relationship_source_field": "adversary",
                },
            },
            entities["records"],
        )
        self.assertIn(
            {
                "entity_type": "observable",
                "value": "one.example",
                "source_field": "indicators",
                "confidence": 65,
                "relationship_type": "consists-of",
                "attributes": {
                    "observable_type": "domain-name",
                    "indicator_type": "domain",
                    "indicator_id": None,
                    "hash_algorithm": None,
                    "created": None,
                    "first_seen": "2026-04-01T10:00:00Z",
                    "last_seen": "2026-04-02T10:00:00Z",
                    "relationship_source_stix_object_type": "infrastructure",
                    "relationship_source_value": (
                        "APT Example OTX observed infrastructure pulse-1"
                    ),
                    "relationship_source_field": "infrastructures",
                    "relationship_inference": (
                        "otx-single-adversary-network-observable"
                    ),
                },
            },
            entities["records"],
        )
        self.assertIn(
            {
                "entity_type": "attack_pattern",
                "value": "T1059",
                "source_field": "attack_ids",
                "confidence": 70,
                "relationship_type": "related-to",
                "attributes": {
                    "relationship_source_stix_object_type": "infrastructure",
                    "relationship_source_value": (
                        "APT Example OTX observed infrastructure pulse-1"
                    ),
                    "relationship_source_field": "infrastructures",
                    "relationship_inference": (
                        "otx-single-adversary-infrastructure-ttp"
                    ),
                },
            },
            entities["records"],
        )
        self.assertIn(
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
                    "created": None,
                    "first_seen": None,
                    "last_seen": None,
                },
            },
            entities["records"],
        )

    def test_normalizes_attack_ids_from_mixed_strings(self):
        self.assertEqual(
            ["T1059", "T1105", "T1566.001"],
            normalize_attack_ids("t1059, technique T1105, subtechnique T1566.001"),
        )

    def test_ignores_numeric_otx_author_ids_as_graph_identities(self):
        entities = extract_otx_entities({"author": "2"})

        self.assertEqual([], entities["authors"])
        self.assertFalse(
            any(
                record["entity_type"] == "source_identity"
                for record in entities["records"]
            )
        )

    def test_does_not_anchor_otx_relationships_with_multiple_adversaries(self):
        entities = extract_otx_entities(
            {
                "adversary": ["APT One", "APT Two"],
                "industries": ["Finance"],
                "attack_ids": ["T1059"],
                "indicators": [{"type": "domain", "indicator": "one.example"}],
            }
        )

        self.assertEqual([], entities["infrastructures"])
        sector = next(
            record
            for record in entities["records"]
            if record["entity_type"] == "target_sector"
        )
        attack_pattern = next(
            record
            for record in entities["records"]
            if record["entity_type"] == "attack_pattern"
        )
        self.assertNotIn("attributes", sector)
        self.assertNotIn("attributes", attack_pattern)

    def test_does_not_promote_adversary_name_as_malware_family(self):
        entities = extract_otx_entities(
            {
                "adversary": "Lazarus",
                "malware_families": ["Lazarus", "DTrack"],
            }
        )

        self.assertEqual(["DTrack"], entities["malware_families"])
        self.assertFalse(
            any(
                record["entity_type"] == "malware" and record["value"] == "Lazarus"
                for record in entities["records"]
            )
        )

    def test_extracts_explicit_otx_operational_graph_fields(self):
        entities = extract_otx_entities(
            {
                "adversary": "APT Example",
                "campaign": "Operation Example",
                "operation_name": "Operation Backup",
                "c2_channels": ["Telegram"],
                "objective": "Credential theft",
                "incident_name": "Observed phishing wave",
                "security_platform": "Microsoft Defender for Endpoint",
                "siem": "Splunk Enterprise Security",
                "targeted_system": "Windows Workstations",
            }
        )

        self.assertEqual(["Operation Example"], entities["campaigns"])
        self.assertEqual(["Operation Backup"], entities["operations"])
        self.assertEqual(["Telegram"], entities["c2_channels"])
        self.assertEqual(["Credential theft"], entities["objectives"])
        self.assertEqual(["Observed phishing wave"], entities["incidents"])
        self.assertEqual(
            ["Microsoft Defender for Endpoint"],
            entities["security_platforms"],
        )
        self.assertEqual(["Splunk Enterprise Security"], entities["siems"])
        self.assertEqual(["Windows Workstations"], entities["targeted_systems"])
        records = {
            (record["entity_type"], record["value"]): record
            for record in entities["records"]
        }
        self.assertEqual(
            "APT Example",
            records[("campaign", "Operation Example")]["attributes"][
                "relationship_source_value"
            ],
        )
        self.assertEqual(
            "operations",
            records[("campaign", "Operation Backup")]["source_field"],
        )
        self.assertEqual(
            ["c2"],
            records[("channel", "Telegram")]["attributes"]["channel_types"],
        )
        self.assertEqual(
            ["objective"],
            records[("narrative", "Credential theft")]["attributes"][
                "narrative_types"
            ],
        )
        self.assertEqual(
            ["incident"],
            records[("event", "Observed phishing wave")]["attributes"]["event_types"],
        )
        self.assertNotIn(
            "security_platform_type",
            records[("security_platform", "Microsoft Defender for Endpoint")][
                "attributes"
            ],
        )
        self.assertEqual(
            "SIEM",
            records[("security_platform", "Splunk Enterprise Security")][
                "attributes"
            ]["security_platform_type"],
        )
        self.assertEqual(
            "APT Example",
            records[("target_system", "Windows Workstations")]["attributes"][
                "relationship_source_value"
            ],
        )

    def test_ignores_ioc_like_otx_operational_graph_fields(self):
        entities = extract_otx_entities(
            {
                "c2_channels": ["c2.example.test"],
                "campaign": ["https://example.test/campaign"],
                "objective": ["T1059"],
                "security_platform": ["https://example.test/platform"],
                "targeted_system": ["CVE-2026-12345"],
            }
        )

        self.assertEqual([], entities["c2_channels"])
        self.assertEqual([], entities["campaigns"])
        self.assertEqual([], entities["objectives"])
        self.assertEqual([], entities["security_platforms"])
        self.assertEqual([], entities["targeted_systems"])
        self.assertFalse(
            any(
                record["entity_type"]
                in {
                    "campaign",
                    "channel",
                    "narrative",
                    "security_platform",
                    "target_system",
                }
                for record in entities["records"]
            )
        )

    def test_extracts_otx_asn_and_netblock_as_infrastructure_evidence(self):
        entities = extract_otx_entities(
            {
                "id": "pulse-asn-1",
                "adversary": "APT Example",
                "indicators": [
                    {
                        "id": "indicator-cidr-1",
                        "type": "CIDR",
                        "indicator": "203.0.113.0/24",
                        "first_seen": "2026-06-01T00:00:00Z",
                    },
                    {
                        "id": "indicator-asn-1",
                        "type": "ASN",
                        "indicator": "AS64512",
                        "title": "NarrowCTI Validation ASN",
                        "last_seen": "2026-06-03T00:00:00Z",
                    },
                ],
            }
        )

        self.assertEqual(
            ["APT Example OTX observed infrastructure pulse-as"],
            entities["infrastructures"],
        )
        self.assertEqual(1, entities["counts"]["autonomous_systems"])
        self.assertEqual("ipv4-addr", entities["observables"][0]["observable_type"])
        self.assertEqual("203.0.113.0/24", entities["observables"][0]["value"])
        self.assertEqual(
            "AS64512 NarrowCTI Validation ASN",
            entities["autonomous_systems"][0]["value"],
        )

        cidr_record = next(
            record
            for record in entities["records"]
            if record["entity_type"] == "observable"
            and record["value"] == "203.0.113.0/24"
        )
        self.assertEqual("consists-of", cidr_record["relationship_type"])
        self.assertEqual(
            "APT Example OTX observed infrastructure pulse-as",
            cidr_record["attributes"]["relationship_source_value"],
        )

        asn_record = next(
            record
            for record in entities["records"]
            if record["entity_type"] == "autonomous_system"
        )
        self.assertEqual("consists-of", asn_record["relationship_type"])
        self.assertEqual(64512, asn_record["attributes"]["asn"])
        self.assertEqual(
            "APT Example OTX observed infrastructure pulse-as",
            asn_record["attributes"]["relationship_source_value"],
        )

    def test_otx_asn_without_single_adversary_is_not_attributed_to_infrastructure(self):
        entities = extract_otx_entities(
            {
                "adversary": ["APT One", "APT Two"],
                "indicators": [
                    {
                        "type": "ASN",
                        "indicator": "AS64512",
                        "title": "NarrowCTI Validation ASN",
                    },
                ],
            }
        )

        self.assertEqual([], entities["infrastructures"])
        asn_record = next(
            record
            for record in entities["records"]
            if record["entity_type"] == "autonomous_system"
        )
        self.assertEqual("related-to", asn_record["relationship_type"])
        self.assertNotIn(
            "relationship_source_value",
            asn_record["attributes"],
        )

    def test_otx_asn_dedup_keeps_richer_name(self):
        entities = extract_otx_entities(
            {
                "indicators": [
                    {"type": "ASN", "indicator": "AS64512"},
                    {
                        "type": "ASN",
                        "indicator": "AS64512",
                        "title": "NarrowCTI Validation ASN",
                    },
                ],
            }
        )

        self.assertEqual(1, len(entities["autonomous_systems"]))
        self.assertEqual(
            "AS64512 NarrowCTI Validation ASN",
            entities["autonomous_systems"][0]["value"],
        )

    def test_normalizes_cve_ids_from_nested_values(self):
        self.assertEqual(
            ["CVE-2024-12345", "CVE-2023-9999"],
            normalize_cve_ids(
                [
                    {"value": "CVE-2024-12345"},
                    "seen in https://example.test/CVE-2023-9999",
                    "cve-2024-12345",
                ]
            ),
        )

    def test_normalizes_tlp_alias_fields(self):
        self.assertEqual(["green"], normalize_tlp({"tlp_marking": "tlp:green"}))

    def test_normalizes_reference_strings_and_dicts(self):
        self.assertEqual(
            [
                {"url": "https://example.com/report", "source_name": "example.com"},
                {"url": "https://vendor.example/ioc", "source_name": "Vendor"},
            ],
            normalize_references(
                [
                    "https://example.com/report",
                    {"url": "https://vendor.example/ioc", "source_name": "Vendor"},
                ]
            ),
        )


if __name__ == "__main__":
    unittest.main()
