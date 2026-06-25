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


if __name__ == "__main__":
    unittest.main()
