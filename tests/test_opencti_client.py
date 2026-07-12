import unittest

from gateway.opencti_client import (
    NarrowCTIOpenCTIApiClient,
    OpenCTICompatibilityError,
    sanitize_legacy_query,
    sanitize_legacy_variables,
)


class OpenCTIClientCompatibilityTests(unittest.TestCase):
    def test_sanitizes_nested_empty_pycti7_fields_without_mutating_input(self):
        variables = {
            "input": {
                "name": "NarrowCTI validation",
                "files": None,
                "nested": [{"embedded": False, "value": "kept"}],
            }
        }

        sanitized = sanitize_legacy_variables(variables)

        self.assertEqual(
            {
                "input": {
                    "name": "NarrowCTI validation",
                    "nested": [{"value": "kept"}],
                }
            },
            sanitized,
        )
        self.assertIn("files", variables["input"])
        self.assertIn("embedded", variables["input"]["nested"][0])

    def test_rejects_non_empty_unsupported_field(self):
        with self.assertRaisesRegex(OpenCTICompatibilityError, "files"):
            sanitize_legacy_variables({"input": {"files": ["evidence.txt"]}})

    def test_removes_pycti7_observable_inputs_missing_from_opencti_6_9(self):
        query = """
        mutation Observable(
          $SSHKey: SSHKeyAddInput
          $AIPrompt: AIPromptAddInput
          $IMEI: IMEIAddInput
          $upsertOperations: [EditInput!]
        ) {
          stixCyberObservableAdd(
            SSHKey: $SSHKey
            AIPrompt: $AIPrompt
            IMEI: $IMEI
            upsertOperations: $upsertOperations
          ) { id }
        }
        """

        sanitized = sanitize_legacy_query(query)

        self.assertIn("SSHKeyAddInput", sanitized)
        self.assertIn("SSHKey: $SSHKey", sanitized)
        self.assertNotIn("AIPrompt", sanitized)
        self.assertNotIn("IMEI", sanitized)
        self.assertNotIn("upsertOperations", sanitized)

    def test_rejects_non_empty_legacy_query_input_variable(self):
        with self.assertRaisesRegex(OpenCTICompatibilityError, "AIPrompt"):
            sanitize_legacy_variables({"AIPrompt": {"value": "secret prompt"}})

    def test_legacy_detection_is_limited_to_opencti_6_9(self):
        client = NarrowCTIOpenCTIApiClient.__new__(NarrowCTIOpenCTIApiClient)

        client.platform_version = "6.9.4"
        self.assertTrue(client.uses_legacy_input_schema)
        client.platform_version = "7.0.0"
        self.assertFalse(client.uses_legacy_input_schema)
        client.platform_version = "6.8.12"
        self.assertFalse(client.uses_legacy_input_schema)


if __name__ == "__main__":
    unittest.main()
