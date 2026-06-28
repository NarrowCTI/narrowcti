import unittest

from core.graph_candidates import (
    apply_graph_candidate_policy,
    build_graph_candidates,
    candidate_fingerprint,
    graph_candidate_from_record,
    safe_graph_export_allowed_entity_types,
    safe_graph_export_allowed_stix_object_types,
)
from core.graph_evidence import build_graph_evidence


class GraphCandidateTests(unittest.TestCase):
    def test_safe_export_defaults_hold_provenance_metadata(self):
        entity_types = safe_graph_export_allowed_entity_types("export")
        stix_object_types = safe_graph_export_allowed_stix_object_types("export")

        self.assertIn("infrastructure", entity_types)
        self.assertIn("attack_data_component", entity_types)
        self.assertIn("autonomous_system", entity_types)
        self.assertIn("campaign", entity_types)
        self.assertIn("course_of_action", entity_types)
        self.assertIn("target_sector", entity_types)
        self.assertIn("target_organization", entity_types)
        self.assertIn("target_administrative_area", entity_types)
        self.assertIn("target_city", entity_types)
        self.assertIn("target_individual", entity_types)
        self.assertIn("target_position", entity_types)
        self.assertIn("threat_actor", entity_types)
        self.assertIn("threat_actor_individual", entity_types)
        self.assertIn("attack_pattern", entity_types)
        self.assertIn("attack_data_source", entity_types)
        self.assertNotIn("attack_tactic", entity_types)
        self.assertNotIn("attack_platform", entity_types)
        self.assertNotIn("source_identity", entity_types)
        self.assertNotIn("collector", entity_types)
        self.assertNotIn("tag", entity_types)
        self.assertNotIn("marking", entity_types)
        self.assertIn("infrastructure", stix_object_types)
        self.assertIn("autonomous-system", stix_object_types)
        self.assertIn("campaign", stix_object_types)
        self.assertIn("course-of-action", stix_object_types)
        self.assertIn("identity", stix_object_types)
        self.assertIn("x-mitre-data-source", stix_object_types)
        self.assertIn("x-mitre-data-component", stix_object_types)
        self.assertNotIn("x-mitre-tactic", stix_object_types)
        self.assertNotIn("x-narrowcti-attack-platform", stix_object_types)
        self.assertNotIn("marking-definition", stix_object_types)
        self.assertNotIn("label", stix_object_types)

    def test_safe_export_defaults_respect_operator_allowlist(self):
        self.assertEqual(
            ["collector", "source_identity"],
            safe_graph_export_allowed_entity_types(
                "export",
                ["source_identity", "collector"],
            ),
        )
        self.assertEqual(
            ["identity"],
            safe_graph_export_allowed_stix_object_types("export", ["identity"]),
        )

    def test_safe_export_defaults_are_empty_outside_export(self):
        self.assertEqual([], safe_graph_export_allowed_entity_types("audit"))
        self.assertEqual([], safe_graph_export_allowed_stix_object_types("dry-run"))

    def test_builds_graph_candidates_from_evidence_records(self):
        candidates = build_graph_candidates(
            {
                "version": "v0.7.0-dev",
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
                        "relationship_confidence": 82,
                        "attributes": {
                            "tactics": ["execution"],
                            "stix_id": "attack-pattern--1",
                        },
                    }
                ],
            }
        )

        self.assertEqual("v0.7.0-dev", candidates.version)
        self.assertEqual("alienvault:otx", candidates.source_key)
        self.assertEqual("pulse-1", candidates.external_id)
        self.assertEqual(1, candidates.candidate_count)
        self.assertEqual({"attack_pattern": 1}, candidates.counts)

        candidate = candidates.candidates[0]
        self.assertEqual("Command and Scripting Interpreter", candidate.name)
        self.assertEqual("attack-pattern", candidate.stix_object_type)
        self.assertEqual("uses", candidate.relationship_type)
        self.assertEqual(82, candidate.relationship_confidence)
        self.assertEqual(
            {
                "source_key": "alienvault:otx",
                "source_name": "mitre-attack",
                "source_field": "mitre_attack.resolved",
            },
            candidate.provenance,
        )
        self.assertEqual(["execution"], candidate.attributes["tactics"])
        self.assertEqual(
            candidate_fingerprint(
                "alienvault:otx",
                "pulse-1",
                "attack_pattern",
                "attack-pattern",
                "T1059",
                relationship_type="uses",
            ),
            candidate.fingerprint,
        )

        candidate_dict = candidate.to_dict()
        self.assertEqual("pulse-1", candidate_dict["external_id"])
        self.assertEqual("Technique pulse", candidate_dict["title"])
        self.assertEqual(
            "Command and Scripting Interpreter",
            candidate_dict["display_name"],
        )
        self.assertEqual(82, candidate_dict["relationship_confidence"])
        self.assertEqual(
            "mitre_attack.resolved",
            candidate_dict["provenance"]["source_field"],
        )

    def test_builds_mitre_reference_candidates_from_evidence(self):
        evidence = build_graph_evidence(
            {
                "mitre_attack": {
                    "available": True,
                    "resolved": [
                        {
                            "attack_id": "T1059",
                            "found": True,
                            "name": "Command and Scripting Interpreter",
                            "tactics": ["execution"],
                            "stix_id": "attack-pattern--1",
                            "url": "https://attack.mitre.org/techniques/T1059/",
                            "platforms": ["Windows"],
                            "data_sources": ["Process: Process Creation"],
                            "detection": "Monitor process execution.",
                        }
                    ],
                }
            },
            source_key="alienvault:otx",
            external_id="pulse-1",
            title="Technique pulse",
        )

        candidates = build_graph_candidates(evidence)

        self.assertEqual(7, candidates.candidate_count)
        self.assertEqual(1, candidates.counts["attack_pattern"])
        self.assertEqual(1, candidates.counts["attack_tactic"])
        self.assertEqual(1, candidates.counts["attack_platform"])
        self.assertEqual(1, candidates.counts["attack_data_component"])
        self.assertEqual(1, candidates.counts["attack_data_source"])
        self.assertEqual(1, candidates.counts["detection_guidance"])
        self.assertEqual(1, candidates.counts["external_reference"])

        attack_pattern = next(
            candidate
            for candidate in candidates.candidates
            if candidate.entity_type == "attack_pattern"
        )
        self.assertEqual(
            [
                {
                    "source_name": "mitre-attack",
                    "external_id": "T1059",
                    "url": "https://attack.mitre.org/techniques/T1059/",
                }
            ],
            attack_pattern.attributes["external_references"],
        )
        self.assertEqual(
            [{"kill_chain_name": "mitre-attack", "phase_name": "execution"}],
            attack_pattern.attributes["kill_chain_phases"],
        )

        detection = next(
            candidate
            for candidate in candidates.candidates
            if candidate.entity_type == "detection_guidance"
        )
        self.assertEqual("note", detection.stix_object_type)
        self.assertEqual("Detection guidance for T1059", detection.name)
        self.assertEqual("Monitor process execution.", detection.value)
        self.assertEqual(70, detection.relationship_confidence)
        self.assertEqual(
            "mitre_attack.resolved.detection",
            detection.provenance["source_field"],
        )

        data_component = next(
            candidate
            for candidate in candidates.candidates
            if candidate.entity_type == "attack_data_component"
        )
        self.assertEqual("x-mitre-data-component", data_component.stix_object_type)
        self.assertEqual("Process Creation", data_component.value)
        self.assertEqual("Process", data_component.attributes["data_source"])

    def test_filters_candidates_by_confidence_and_type(self):
        candidates = build_graph_candidates(
            {
                "source_key": "misp:misp",
                "records": [
                    {
                        "entity_type": "tag",
                        "value": "ransomware",
                        "stix_object_type": "label",
                        "confidence": 35,
                    },
                    {
                        "entity_type": "marking",
                        "value": "green",
                        "stix_object_type": "marking-definition",
                        "confidence": 80,
                    },
                    {
                        "entity_type": "collector",
                        "value": "misp",
                        "stix_object_type": "identity",
                        "confidence": 80,
                    },
                ],
            },
            min_confidence=50,
            excluded_stix_object_types={"marking-definition"},
        )

        self.assertEqual(1, candidates.candidate_count)
        self.assertEqual("collector", candidates.candidates[0].entity_type)

    def test_applies_graph_candidate_policy_without_dropping_candidates(self):
        candidates = build_graph_candidates(
            {
                "source_key": "alienvault:otx",
                "records": [
                    {
                        "entity_type": "threat_actor",
                        "value": "APT Example",
                        "stix_object_type": "threat-actor",
                        "relationship_type": "attributed-to",
                        "confidence": 45,
                        "relationship_confidence": 40,
                        "source_field": "adversary",
                    },
                    {
                        "entity_type": "attack_pattern",
                        "value": "T1059",
                        "stix_object_type": "attack-pattern",
                        "relationship_type": "uses",
                        "confidence": 90,
                        "relationship_confidence": 85,
                        "source_field": "mitre_attack.resolved",
                    },
                ],
            }
        )

        result = apply_graph_candidate_policy(
            candidates,
            min_entity_confidence=50,
            min_relationship_confidence=60,
            allowed_entity_types={"attack_pattern"},
            require_relationship_provenance=True,
        )

        self.assertEqual(2, result.candidate_count)
        self.assertEqual(1, result.accepted_count)
        self.assertEqual(1, result.held_count)
        self.assertEqual("attack_pattern", result.accepted[0].entity_type)
        self.assertEqual(
            {
                "entity_confidence_below_min": 1,
                "entity_type_not_allowed": 1,
                "relationship_confidence_below_min": 1,
            },
            result.held_reasons,
        )
        policy = result.to_dict()
        self.assertEqual(2, policy["candidate_count"])
        self.assertEqual("threat_actor", policy["held"][0]["candidate"]["entity_type"])

    def test_holds_relationships_that_require_opencti_validation(self):
        candidates = build_graph_candidates(
            {
                "source_key": "misp:misp",
                "records": [
                    {
                        "entity_type": "target_sector",
                        "value": "Finance",
                        "stix_object_type": "identity",
                        "relationship_type": "targets",
                        "confidence": 75,
                        "source_field": "Galaxy.meta.targeted-sector",
                        "attributes": {
                            "relationship_source_stix_object_type": "infrastructure",
                            "relationship_source_value": "MISP domain-ip c2.example",
                            "relationship_validation_state": (
                                "requires-opencti-validation"
                            ),
                        },
                    }
                ],
            }
        )

        result = apply_graph_candidate_policy(
            candidates,
            allowed_entity_types={"target_sector"},
            allowed_stix_object_types={"identity"},
        )

        self.assertEqual(1, result.candidate_count)
        self.assertEqual(0, result.accepted_count)
        self.assertEqual(1, result.held_count)
        self.assertEqual(
            {"relationship_requires_opencti_validation": 1},
            result.held_reasons,
        )

    def test_skips_malformed_records_and_clamps_confidence(self):
        candidates = build_graph_candidates(
            {
                "source_key": "alienvault:otx",
                "records": [
                    {},
                    "not a record",
                    {
                        "entity_type": "malware",
                        "value": "ExampleMalware",
                        "stix_object_type": "malware",
                        "relationship_type": "",
                        "confidence": "250",
                    },
                ],
            }
        )

        self.assertEqual(1, candidates.candidate_count)
        candidate = candidates.candidates[0]
        self.assertEqual(100, candidate.confidence)
        self.assertEqual(100, candidate.relationship_confidence)
        self.assertEqual("related-to", candidate.relationship_type)

    def test_candidate_fingerprint_distinguishes_relationship_source_anchor(self):
        actor_anchor = {
            "relationship_source_stix_object_type": "intrusion-set",
            "relationship_source_value": "APT Example",
        }
        infrastructure_anchor = {
            "relationship_source_stix_object_type": "infrastructure",
            "relationship_source_value": "APT Example OTX observed infrastructure pulse-1",
        }

        self.assertNotEqual(
            candidate_fingerprint(
                "alienvault:otx",
                "pulse-1",
                "attack_pattern",
                "attack-pattern",
                "T1059",
                relationship_type="uses",
                attributes=actor_anchor,
            ),
            candidate_fingerprint(
                "alienvault:otx",
                "pulse-1",
                "attack_pattern",
                "attack-pattern",
                "T1059",
                relationship_type="uses",
                attributes=infrastructure_anchor,
            ),
        )

    def test_candidate_preserves_explicit_provenance(self):
        candidate = graph_candidate_from_record(
            {
                "entity_type": "malware",
                "value": "ExampleMalware",
                "stix_object_type": "malware",
                "relationship_type": "uses",
                "confidence": 70,
                "relationship_confidence": 55,
                "source_key": "alienvault:otx",
                "source_name": "otx",
                "source_field": "malware_families",
                "provenance": {
                    "raw_value": "Example Malware",
                    "extractor": "otx_entities",
                },
            }
        )

        self.assertEqual(55, candidate.relationship_confidence)
        self.assertEqual("Example Malware", candidate.provenance["raw_value"])
        self.assertEqual("otx_entities", candidate.provenance["extractor"])
        self.assertEqual("alienvault:otx", candidate.provenance["source_key"])
        self.assertEqual("otx", candidate.provenance["source_name"])
        self.assertEqual("malware_families", candidate.provenance["source_field"])

    def test_record_without_required_fields_does_not_build_candidate(self):
        self.assertIsNone(
            graph_candidate_from_record(
                {
                    "entity_type": "malware",
                    "value": "",
                    "stix_object_type": "malware",
                }
            )
        )


if __name__ == "__main__":
    unittest.main()
