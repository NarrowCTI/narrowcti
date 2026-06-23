import unittest

from core.graph_candidates import apply_graph_candidate_policy, build_graph_candidates
from core.graph_export_plan import (
    build_graph_export_plan,
    normalize_graph_export_mode,
)


class GraphExportPlanTests(unittest.TestCase):
    def test_builds_audit_only_plan_from_candidate_policy(self):
        policy = self.graph_policy().to_dict()

        plan = build_graph_export_plan(policy)

        self.assertEqual("v0.7.0-dev", plan["version"])
        self.assertEqual("audit", plan["mode"])
        self.assertEqual("audit-only", plan["status"])
        self.assertFalse(plan["export_enabled"])
        self.assertEqual(2, plan["candidate_count"])
        self.assertEqual(1, plan["accepted_count"])
        self.assertEqual(1, plan["held_count"])
        self.assertEqual({"attack-pattern": 1}, plan["accepted_object_counts"])
        self.assertEqual({"uses": 1}, plan["accepted_relationship_counts"])
        self.assertEqual(0, plan["would_create_object_count"])
        self.assertEqual(0, plan["would_create_relationship_count"])
        self.assertEqual("audit_only", plan["actions"][0]["action"])
        self.assertEqual("held", plan["actions"][1]["action"])
        self.assertEqual(
            ["entity_confidence_below_min", "relationship_confidence_below_min"],
            plan["actions"][1]["reasons"],
        )

    def test_builds_dry_run_plan_with_would_create_counts(self):
        policy = self.graph_policy().to_dict()

        plan = build_graph_export_plan(policy, mode="dry_run")

        self.assertEqual("dry-run", plan["mode"])
        self.assertEqual("dry-run", plan["status"])
        self.assertEqual(1, plan["would_create_object_count"])
        self.assertEqual(1, plan["would_create_relationship_count"])
        self.assertEqual("would_create", plan["actions"][0]["action"])
        self.assertEqual("graph_export_dry_run", plan["actions"][0]["reason"])
        self.assertEqual(
            "T1059",
            plan["actions"][0]["candidate"]["value"],
        )

    def test_deduplicates_repeated_entity_and_relationship_inside_plan(self):
        policy = apply_graph_candidate_policy(
            build_graph_candidates(
                {
                    "version": "v0.7.0-dev",
                    "source_key": "alienvault:otx",
                    "external_id": "pulse-1",
                    "records": [
                        accepted_attack_pattern_record(),
                        accepted_attack_pattern_record(),
                    ],
                }
            )
        ).to_dict()

        plan = build_graph_export_plan(policy, mode="dry-run")

        self.assertEqual(2, plan["accepted_count"])
        self.assertEqual(1, plan["would_create_object_count"])
        self.assertEqual(1, plan["would_create_relationship_count"])
        self.assertEqual(1, plan["deduplicated_candidate_count"])
        self.assertEqual(1, plan["deduplicated_entity_count"])
        self.assertEqual(1, plan["deduplicated_relationship_count"])
        self.assertEqual("would_create", plan["actions"][0]["action"])
        self.assertEqual("deduplicated", plan["actions"][1]["action"])
        self.assertEqual(
            "graph_plan_duplicate_entity_and_relationship",
            plan["actions"][1]["reason"],
        )
        self.assertTrue(
            plan["actions"][1]["deduplication"]["entity_key"].startswith("entity:")
        )
        self.assertTrue(
            plan["actions"][1]["deduplication"]["relationship_key"].startswith(
                "relationship:"
            )
        )

    def test_deduplicates_entity_without_dropping_unique_relationship(self):
        first = accepted_attack_pattern_record()
        second = dict(first)
        second["relationship_type"] = "related-to"
        policy = apply_graph_candidate_policy(
            build_graph_candidates(
                {
                    "version": "v0.7.0-dev",
                    "source_key": "alienvault:otx",
                    "external_id": "pulse-1",
                    "records": [first, second],
                }
            )
        ).to_dict()

        plan = build_graph_export_plan(policy, mode="dry-run")

        self.assertEqual(1, plan["would_create_object_count"])
        self.assertEqual(2, plan["would_create_relationship_count"])
        self.assertEqual(1, plan["deduplicated_candidate_count"])
        self.assertEqual(1, plan["deduplicated_entity_count"])
        self.assertEqual(0, plan["deduplicated_relationship_count"])
        self.assertEqual("would_create", plan["actions"][1]["action"])
        self.assertTrue(plan["actions"][1]["deduplication"]["entity_duplicate"])
        self.assertFalse(
            plan["actions"][1]["deduplication"]["relationship_duplicate"]
        )

    def test_uses_known_graph_keys_for_persistent_deduplication(self):
        policy = apply_graph_candidate_policy(
            build_graph_candidates(
                {
                    "version": "v0.7.0-dev",
                    "source_key": "alienvault:otx",
                    "external_id": "pulse-1",
                    "records": [accepted_attack_pattern_record()],
                }
            )
        ).to_dict()
        probe_plan = build_graph_export_plan(policy, mode="dry-run")
        known_entity_key = probe_plan["actions"][0]["deduplication"]["entity_key"]

        plan = build_graph_export_plan(
            policy,
            mode="dry-run",
            known_entity_keys=[known_entity_key],
        )

        self.assertEqual(1, plan["deduplicated_candidate_count"])
        self.assertEqual(1, plan["deduplicated_entity_count"])
        self.assertEqual(0, plan["deduplicated_relationship_count"])
        self.assertEqual(0, plan["would_create_object_count"])
        self.assertEqual(1, plan["would_create_relationship_count"])
        self.assertEqual("would_create", plan["actions"][0]["action"])
        self.assertEqual(
            "graph_plan_duplicate_entity",
            plan["actions"][0]["reason"],
        )

    def test_export_mode_is_blocked_until_graph_export_exists(self):
        policy = self.graph_policy().to_dict()

        plan = build_graph_export_plan(policy, mode="export")

        self.assertEqual("export", plan["mode"])
        self.assertEqual("blocked", plan["status"])
        self.assertFalse(plan["export_enabled"])
        self.assertEqual("blocked", plan["actions"][0]["action"])
        self.assertEqual(
            "graph_export_not_implemented",
            plan["actions"][0]["reason"],
        )

    def test_rejects_unknown_graph_export_mode(self):
        with self.assertRaisesRegex(ValueError, "graph export mode"):
            normalize_graph_export_mode("unsafe")

    def graph_policy(self):
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
                        "relationship_confidence": 85,
                    },
                    {
                        "entity_type": "threat_actor",
                        "value": "APT Example",
                        "stix_object_type": "threat-actor",
                        "relationship_type": "attributed-to",
                        "source_key": "alienvault:otx",
                        "source_name": "otx",
                        "source_field": "adversary",
                        "confidence": 45,
                        "relationship_confidence": 40,
                    },
                ],
            }
        )
        return apply_graph_candidate_policy(
            candidates,
            min_entity_confidence=50,
            min_relationship_confidence=60,
        )


def accepted_attack_pattern_record():
    return {
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


if __name__ == "__main__":
    unittest.main()
