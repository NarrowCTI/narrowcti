import json
import unittest

from exporters.stix_builder import build_curated_report_bundle, build_graph_report_bundle


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
                    event_report_candidate(),
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

        self.assertEqual(7, summary["accepted_candidate_count"])
        self.assertEqual(14, summary["bundle_object_count"])
        self.assertEqual(6, summary["graph_object_count"])
        self.assertEqual(6, summary["graph_relationship_count"])
        self.assertEqual(0, summary["skipped_candidate_count"])
        self.assertEqual(
            {
                "attack-pattern": 1,
                "domain-name": 1,
                "indicator": 1,
                "note": 1,
                "threat-actor": 1,
                "vulnerability": 1,
            },
            summary["object_counts"],
        )
        self.assertEqual({"related-to": 6}, summary["relationship_counts"])
        self.assertEqual(
            {
                "attributed-to": 1,
                "based-on": 1,
                "detects": 1,
                "documents": 1,
                "related-to": 1,
                "uses": 1,
            },
            summary["proposed_relationship_counts"],
        )
        self.assertEqual(0, summary["semantic_relationship_count"])
        self.assertEqual(6, summary["report_relationship_count"])
        self.assertEqual(1, len(objects_by_type["attack-pattern"]))
        self.assertEqual(1, len(objects_by_type["threat-actor"]))
        self.assertEqual(1, len(objects_by_type["vulnerability"]))
        self.assertEqual(1, len(objects_by_type["domain-name"]))
        self.assertEqual(1, len(objects_by_type["indicator"]))
        self.assertEqual(1, len(objects_by_type["note"]))
        self.assertEqual(6, len(objects_by_type["relationship"]))

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
        note = objects_by_type["note"][0]
        self.assertEqual("Initial analyst report", note["abstract"])
        self.assertEqual(
            "The event describes exploitation activity.",
            note["content"],
        )
        self.assertIn(
            "identity--",
            note["object_refs"][0],
        )

        reports = objects_by_type["report"]
        self.assertEqual(1, len(reports))
        self.assertEqual(6, len(reports[0]["object_refs"]))
        self.assertTrue(
            all(
                relationship["source_ref"] == reports[0]["id"]
                and relationship["relationship_type"] == "related-to"
                and relationship["x_narrowcti_relationship_mode"] == "report-context"
                for relationship in objects_by_type["relationship"]
            )
        )

    def test_builds_semantic_relationship_when_source_anchor_is_trusted(self):
        bundle, summary = build_graph_report_bundle(
            "Curated graph report",
            "graph context",
            80,
            graph_candidate_policy={
                "accepted": [
                    threat_actor_candidate(),
                    target_sector_candidate(),
                ]
            },
        )

        data = json.loads(bundle.serialize())
        objects_by_type = {}
        for item in data["objects"]:
            objects_by_type.setdefault(item["type"], []).append(item)

        actor = objects_by_type["threat-actor"][0]
        sector = next(
            item
            for item in objects_by_type["identity"]
            if item["name"] == "Finance"
        )
        target_relationship = next(
            relationship
            for relationship in objects_by_type["relationship"]
            if relationship["relationship_type"] == "targets"
        )

        self.assertEqual("class", sector["identity_class"])
        self.assertEqual(actor["id"], target_relationship["source_ref"])
        self.assertEqual(sector["id"], target_relationship["target_ref"])
        self.assertEqual(
            "semantic",
            target_relationship["x_narrowcti_relationship_mode"],
        )
        self.assertEqual(
            {
                "related-to": 1,
                "targets": 1,
            },
            summary["relationship_counts"],
        )
        self.assertEqual(
            {
                "attributed-to": 1,
                "targets": 1,
            },
            summary["proposed_relationship_counts"],
        )
        self.assertEqual(1, summary["semantic_relationship_count"])
        self.assertEqual(1, summary["report_relationship_count"])

    def test_builds_semantic_relationship_from_explicit_source_anchor(self):
        bundle, _ = build_graph_report_bundle(
            "Curated graph report",
            "graph context",
            80,
            graph_candidate_policy={
                "accepted": [
                    threat_actor_candidate(),
                    anchored_malware_candidate(),
                ]
            },
        )

        data = json.loads(bundle.serialize())
        objects_by_type = {}
        for item in data["objects"]:
            objects_by_type.setdefault(item["type"], []).append(item)

        actor = objects_by_type["threat-actor"][0]
        malware = objects_by_type["malware"][0]
        relationship = next(
            relationship
            for relationship in objects_by_type["relationship"]
            if relationship["relationship_type"] == "uses"
        )

        self.assertEqual(actor["id"], relationship["source_ref"])
        self.assertEqual(malware["id"], relationship["target_ref"])
        self.assertEqual("semantic", relationship["x_narrowcti_relationship_mode"])
        self.assertEqual(
            "threat-actor",
            relationship["x_narrowcti_relationship_source_type"],
        )
        self.assertEqual(
            "APT Example",
            relationship["x_narrowcti_relationship_source_value"],
        )
        self.assertEqual(
            "adversary",
            relationship["x_narrowcti_relationship_source_field"],
        )

    def test_builds_curated_bundle_with_indicators_and_graph_entities(self):
        bundle, indicator_count, summary = build_curated_report_bundle(
            "Curated ingest report",
            "graph context",
            80,
            indicators=[{"type": "domain", "indicator": "one.example"}],
            graph_candidate_policy={
                "accepted": [
                    threat_actor_candidate(),
                    target_sector_candidate(),
                    anchored_malware_candidate(),
                ]
            },
        )

        data = json.loads(bundle.serialize())
        objects_by_type = {}
        for item in data["objects"]:
            objects_by_type.setdefault(item["type"], []).append(item)

        sector = next(
            item
            for item in objects_by_type["identity"]
            if item["name"] == "Finance"
        )
        report = objects_by_type["report"][0]

        self.assertEqual(1, indicator_count)
        self.assertEqual(1, summary["indicator_count"])
        self.assertEqual(3, summary["graph_object_count"])
        self.assertEqual("class", sector["identity_class"])
        self.assertEqual(1, len(objects_by_type["indicator"]))
        self.assertEqual(1, len(objects_by_type["malware"]))
        self.assertEqual(1, len(objects_by_type["threat-actor"]))
        self.assertIn(sector["id"], report["object_refs"])
        self.assertIn(objects_by_type["indicator"][0]["id"], report["object_refs"])

    def test_curated_bundle_references_existing_opencti_objects(self):
        existing_attack_pattern_ref = (
            "attack-pattern--11111111-1111-4111-8111-111111111111"
        )
        bundle, _, summary = build_curated_report_bundle(
            "Curated ingest report",
            "graph context",
            80,
            graph_candidate_policy={
                "accepted": [
                    threat_actor_candidate(),
                    existing_attack_pattern_candidate(existing_attack_pattern_ref),
                ]
            },
        )

        data = json.loads(bundle.serialize())
        objects_by_type = {}
        for item in data["objects"]:
            objects_by_type.setdefault(item["type"], []).append(item)

        actor = objects_by_type["threat-actor"][0]
        report = objects_by_type["report"][0]
        relationship = next(
            item
            for item in objects_by_type["relationship"]
            if item["relationship_type"] == "uses"
        )

        self.assertNotIn("attack-pattern", objects_by_type)
        self.assertEqual(1, summary["existing_reference_count"])
        self.assertEqual(
            {"attack-pattern": 1},
            summary["existing_reference_counts"],
        )
        self.assertIn(existing_attack_pattern_ref, report["object_refs"])
        self.assertEqual(actor["id"], relationship["source_ref"])
        self.assertEqual(existing_attack_pattern_ref, relationship["target_ref"])
        self.assertEqual("semantic", relationship["x_narrowcti_relationship_mode"])

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


def target_sector_candidate():
    return {
        "fingerprint": "sector-1",
        "entity_type": "target_sector",
        "value": "Finance",
        "name": "Finance",
        "stix_object_type": "identity",
        "relationship_type": "targets",
        "source_key": "misp:misp",
        "source_name": "misp-galaxy",
        "source_field": "Galaxy.meta.targeted-sector",
        "confidence": 70,
        "relationship_confidence": 70,
        "attributes": {
            "parent_cluster_type": "threat-actor",
            "parent_cluster_value": "APT Example",
            "parent_cluster_uuid": "cluster-actor",
        },
    }


def anchored_malware_candidate():
    return {
        "fingerprint": "malware-anchored-1",
        "entity_type": "malware",
        "value": "LummaC2",
        "name": "LummaC2",
        "stix_object_type": "malware",
        "relationship_type": "uses",
        "source_key": "alienvault:otx",
        "source_name": "otx",
        "source_field": "malware_families",
        "confidence": 55,
        "relationship_confidence": 55,
        "attributes": {
            "relationship_source_stix_object_type": "threat-actor",
            "relationship_source_value": "APT Example",
            "relationship_source_field": "adversary",
        },
    }


def existing_attack_pattern_candidate(existing_ref):
    candidate = attack_pattern_candidate()
    candidate["attributes"] = {
        "relationship_source_stix_object_type": "threat-actor",
        "relationship_source_value": "APT Example",
        "relationship_source_field": "adversary",
        "opencti_existing_ref": existing_ref,
        "opencti_existing_id": "internal--1",
        "opencti_existing_entity_type": "Attack-Pattern",
        "opencti_match_type": "mitre_attack_id",
        "opencti_match_value": "T1059",
    }
    return candidate


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


def event_report_candidate():
    return {
        "fingerprint": "event-report-1",
        "entity_type": "event_report",
        "value": "Initial analyst report",
        "name": "Initial analyst report",
        "stix_object_type": "note",
        "relationship_type": "documents",
        "source_key": "misp:event",
        "source_name": "misp",
        "source_field": "EventReport[0]",
        "confidence": 70,
        "relationship_confidence": 70,
        "attributes": {
            "content": "The event describes exploitation activity.",
            "event_report_uuid": "event-report-1",
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
