import json
import os
import tempfile
import unittest

from core.graph_deduplication import (
    GRAPH_ENTITIES_KEY,
    GRAPH_RELATIONSHIPS_KEY,
    GraphDeduplicationIndex,
    load_graph_state,
)


class GraphDeduplicationIndexTests(unittest.TestCase):
    def test_load_graph_state_recovers_missing_or_invalid_state(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            missing = os.path.join(tmpdir, "graph.json")
            invalid = os.path.join(tmpdir, "invalid.json")
            with open(invalid, "w", encoding="utf-8") as file_obj:
                file_obj.write("not json")

            self.assertEqual(
                {GRAPH_ENTITIES_KEY: {}, GRAPH_RELATIONSHIPS_KEY: {}},
                load_graph_state(missing),
            )
            self.assertEqual(
                {GRAPH_ENTITIES_KEY: {}, GRAPH_RELATIONSHIPS_KEY: {}},
                load_graph_state(invalid),
            )

    def test_mark_plan_persists_entity_and_relationship_keys(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            state_file = os.path.join(tmpdir, "graph.json")
            index = GraphDeduplicationIndex(state_file)

            added = index.mark_plan(
                graph_plan(),
                source_key="alienvault:otx",
                external_id="pulse-1",
                title="Technique pulse",
            )

            self.assertEqual({"entities": 1, "relationships": 1}, added)
            self.assertTrue(index.has_entity("entity:attack-pattern:t1059"))
            self.assertTrue(
                index.has_relationship("relationship:pulse-1:uses:t1059")
            )
            entity = index.entity_record("entity:attack-pattern:t1059")
            relationship = index.relationship_record("relationship:pulse-1:uses:t1059")
            self.assertEqual("T1059", entity["candidate"]["value"])
            self.assertEqual(["alienvault:otx"], entity["sources"])
            self.assertEqual("pulse-1", entity["sightings"][0]["external_id"])
            self.assertEqual("uses", relationship["candidate"]["relationship_type"])

    def test_mark_plan_is_idempotent_for_same_source_sighting(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            state_file = os.path.join(tmpdir, "graph.json")
            index = GraphDeduplicationIndex(state_file)
            first = index.mark_plan(
                graph_plan(),
                source_key="alienvault:otx",
                external_id="pulse-1",
                title="Technique pulse",
            )
            second = index.mark_plan(
                graph_plan(),
                source_key="alienvault:otx",
                external_id="pulse-1",
                title="Technique pulse",
            )

            self.assertEqual({"entities": 1, "relationships": 1}, first)
            self.assertEqual({"entities": 0, "relationships": 0}, second)
            entity = index.entity_record("entity:attack-pattern:t1059")
            self.assertEqual(1, len(entity["sightings"]))

    def test_known_keys_for_plan_reports_existing_graph_keys(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            state_file = os.path.join(tmpdir, "graph.json")
            with open(state_file, "w", encoding="utf-8") as file_obj:
                json.dump(
                    {
                        GRAPH_ENTITIES_KEY: {
                            "entity:attack-pattern:t1059": {
                                "key": "entity:attack-pattern:t1059"
                            }
                        },
                        GRAPH_RELATIONSHIPS_KEY: {},
                    },
                    file_obj,
                )

            known = GraphDeduplicationIndex(state_file).known_keys_for_plan(
                graph_plan()
            )

            self.assertEqual(["entity:attack-pattern:t1059"], known["entity_keys"])
            self.assertEqual([], known["relationship_keys"])

    def test_mark_plan_ignores_held_and_deduplicated_actions(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            state_file = os.path.join(tmpdir, "graph.json")
            added = GraphDeduplicationIndex(state_file).mark_plan(
                {
                    "actions": [
                        graph_action("held"),
                        graph_action("deduplicated"),
                    ]
                }
            )

            self.assertEqual({"entities": 0, "relationships": 0}, added)
            state = load_graph_state(state_file)
            self.assertEqual({}, state[GRAPH_ENTITIES_KEY])
            self.assertEqual({}, state[GRAPH_RELATIONSHIPS_KEY])


def graph_plan():
    return {"actions": [graph_action("would_create")]}


def graph_action(action):
    return {
        "action": action,
        "candidate": {
            "entity_type": "attack_pattern",
            "value": "T1059",
            "name": "Command and Scripting Interpreter",
            "stix_object_type": "attack-pattern",
            "relationship_type": "uses",
            "confidence": 90,
            "relationship_confidence": 85,
        },
        "deduplication": {
            "entity_key": "entity:attack-pattern:t1059",
            "relationship_key": "relationship:pulse-1:uses:t1059",
            "entity_duplicate": False,
            "relationship_duplicate": False,
        },
    }


if __name__ == "__main__":
    unittest.main()
