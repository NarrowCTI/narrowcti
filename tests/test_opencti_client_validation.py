import unittest

from gateway.opencti_client_validation import (
    DEFAULT_REPORT_NAME,
    build_client,
    import_validation_report,
    parse_args,
    validate_authentication,
)


class FakeStix2:
    def __init__(self):
        self.import_count = 0

    def import_bundle_from_json(self, bundle_json, update=False):
        self.import_count += 1
        return ([{"id": f"report--{self.import_count}"}], [])


class FakeApiClient:
    def __init__(self, authenticated=True, report_count=1):
        self.authenticated = authenticated
        self.report_count = report_count
        self.stix2 = FakeStix2()

    def query(self, query, variables=None):
        if " me " in query:
            return {"data": {"me": {"id": "user--1"} if self.authenticated else None}}
        if "reports(" in query:
            report_name = (variables or {}).get("search")
            return {
                "data": {
                    "reports": {
                        "edges": [
                            {"node": {"id": f"report--{index}", "name": report_name}}
                            for index in range(self.report_count)
                        ]
                    }
                }
            }
        return {"data": {}}


class OpenCTIClientValidationTests(unittest.TestCase):
    def test_requires_opencti_environment(self):
        with self.assertRaisesRegex(ValueError, "OPENCTI_URL"):
            build_client({})

    def test_defaults_to_read_only_validation(self):
        args = parse_args([])

        self.assertFalse(args.write_test)
        self.assertEqual(DEFAULT_REPORT_NAME, args.report_name)

    def test_validates_authenticated_user(self):
        self.assertTrue(validate_authentication(FakeApiClient()))
        self.assertFalse(validate_authentication(FakeApiClient(authenticated=False)))

    def test_write_validation_imports_twice_and_requires_one_report(self):
        api_client = FakeApiClient(report_count=1)

        result = import_validation_report(api_client, DEFAULT_REPORT_NAME)

        self.assertEqual([1, 1], result["imported_counts"])
        self.assertEqual(0, result["rejected_count"])
        self.assertEqual(1, result["exact_report_count"])
        self.assertEqual(2, api_client.stix2.import_count)


if __name__ == "__main__":
    unittest.main()
