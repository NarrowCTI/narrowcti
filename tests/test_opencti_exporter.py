import json
import unittest

from exporters.opencti import send_bundle


class OpenCTIExporterTests(unittest.TestCase):
    def test_audit_mode_keeps_legacy_report_indicator_bundle(self):
        api_client = FakeOpenCTIClient()

        indicator_count = send_bundle(
            api_client,
            "Curated report",
            "description",
            75,
            indicators=[{"type": "domain", "indicator": "one.example"}],
            graph_candidate_policy={"accepted": [target_sector_candidate()]},
            graph_export_mode="audit",
        )

        objects = imported_objects(api_client)
        self.assertEqual(1, indicator_count)
        self.assertEqual(["identity", "indicator", "report"], object_types(objects))
        self.assertFalse(has_sector_identity(objects, "Crypto"))

    def test_export_mode_imports_curated_graph_entities(self):
        api_client = FakeOpenCTIClient()

        indicator_count = send_bundle(
            api_client,
            "Curated report",
            "description",
            75,
            indicators=[{"type": "domain", "indicator": "one.example"}],
            graph_candidate_policy={"accepted": [target_sector_candidate()]},
            graph_export_mode="export",
        )

        objects = imported_objects(api_client)
        self.assertEqual(1, indicator_count)
        self.assertTrue(has_sector_identity(objects, "Crypto"))
        self.assertIn("relationship", object_types(objects))

    def test_export_mode_references_existing_opencti_graph_objects(self):
        api_client = FakeOpenCTIClient()
        existing_attack_pattern_ref = (
            "attack-pattern--11111111-1111-4111-8111-111111111111"
        )

        send_bundle(
            api_client,
            "Curated report",
            "description",
            75,
            graph_candidate_policy={
                "accepted": [
                    threat_actor_candidate(),
                    existing_attack_pattern_candidate(existing_attack_pattern_ref),
                ]
            },
            graph_export_mode="export",
        )

        objects = imported_objects(api_client)
        report = first_object(objects, "report")
        relationship = first_relationship(objects, "uses")

        self.assertNotIn("attack-pattern", object_types(objects))
        self.assertIn(existing_attack_pattern_ref, report["object_refs"])
        self.assertEqual(existing_attack_pattern_ref, relationship["target_ref"])

    def test_repeated_report_exports_use_stable_report_id(self):
        api_client = FakeOpenCTIClient()

        for _ in range(2):
            send_bundle(
                api_client,
                "LummaC2 Stealer: A Potent Threat to Crypto Users",
                "description",
                75,
                indicators=[{"type": "domain", "indicator": "one.example"}],
                graph_export_mode="audit",
            )

        first_report = first_object(
            api_client.stix2.imports[0]["bundle"]["objects"],
            "report",
        )
        second_report = first_object(
            api_client.stix2.imports[1]["bundle"]["objects"],
            "report",
        )

        self.assertEqual(first_report["id"], second_report["id"])
        self.assertTrue(first_report["id"].startswith("report--"))


class FakeOpenCTIClient:
    def __init__(self):
        self.stix2 = FakeStix2()


class FakeStix2:
    def __init__(self):
        self.imports = []

    def import_bundle_from_json(self, bundle_json, update=True):
        self.imports.append({"bundle": json.loads(bundle_json), "update": update})


def imported_objects(api_client):
    return api_client.stix2.imports[-1]["bundle"]["objects"]


def object_types(objects):
    return sorted(item["type"] for item in objects)


def has_sector_identity(objects, name):
    return any(
        item["type"] == "identity"
        and item.get("identity_class") == "class"
        and item.get("name") == name
        for item in objects
    )


def first_object(objects, object_type):
    for item in objects:
        if item["type"] == object_type:
            return item
    raise AssertionError(f"missing object type: {object_type}")


def first_relationship(objects, relationship_type):
    for item in objects:
        if (
            item["type"] == "relationship"
            and item["relationship_type"] == relationship_type
        ):
            return item
    raise AssertionError(f"missing relationship type: {relationship_type}")


def target_sector_candidate():
    return {
        "fingerprint": "sector-crypto",
        "entity_type": "target_sector",
        "value": "Crypto",
        "name": "Crypto",
        "stix_object_type": "identity",
        "relationship_type": "targets",
        "source_key": "alienvault:otx",
        "source_name": "otx",
        "source_field": "industries",
        "confidence": 70,
        "relationship_confidence": 70,
    }


def threat_actor_candidate():
    return {
        "fingerprint": "actor-example",
        "entity_type": "threat_actor",
        "value": "APT Example",
        "name": "APT Example",
        "stix_object_type": "threat-actor",
        "relationship_type": "related-to",
        "source_key": "alienvault:otx",
        "source_name": "otx",
        "source_field": "adversary",
        "confidence": 80,
        "relationship_confidence": 75,
    }


def existing_attack_pattern_candidate(existing_ref):
    return {
        "fingerprint": "attack-pattern-t1059",
        "entity_type": "attack_pattern",
        "value": "T1059",
        "name": "Command and Scripting Interpreter",
        "stix_object_type": "attack-pattern",
        "relationship_type": "uses",
        "source_key": "alienvault:otx",
        "source_name": "otx",
        "source_field": "attack_ids",
        "confidence": 80,
        "relationship_confidence": 75,
        "attributes": {
            "relationship_source_stix_object_type": "threat-actor",
            "relationship_source_value": "APT Example",
            "relationship_source_field": "adversary",
            "opencti_existing_ref": existing_ref,
        },
    }


if __name__ == "__main__":
    unittest.main()
