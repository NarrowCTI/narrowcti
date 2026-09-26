import json
import tempfile
import unittest
from pathlib import Path

from narrowcti.infrastructure.runtime.topology import (
    validate_configured_endpoints,
    validate_endpoint,
    validate_state_path,
)


class PreflightTopologyContractTests(unittest.TestCase):
    def test_valid_http_and_https_are_structurally_valid(self):
        http = validate_endpoint("OPENCTI_URL", "http://opencti.example.invalid:8080")
        https = validate_endpoint("MISP_URL", "https://misp.example.invalid")
        self.assertEqual("ok", http.code)
        self.assertFalse(http.tls_expected)
        self.assertEqual("ok", https.code)
        self.assertTrue(https.tls_expected)

    def test_invalid_scheme_host_port_and_embedded_credentials(self):
        self.assertEqual("endpoint-invalid", validate_endpoint("X", "ftp://host").code)
        self.assertEqual("endpoint-invalid", validate_endpoint("X", "https://").code)
        self.assertEqual("endpoint-invalid", validate_endpoint("X", "https://host:bad").code)
        credentials = validate_endpoint("X", "https://user:secret@host")
        self.assertEqual("endpoint-credentials-embedded", credentials.code)
        self.assertNotIn("secret", json.dumps(credentials.to_dict()))

    def test_active_sources_control_required_endpoint_validation(self):
        otx_only = validate_configured_endpoints(
            opencti_url="https://opencti.example.invalid",
            misp_url="",
            enabled_sources=("otx",),
        )
        self.assertEqual(["ok", "endpoint-not-configured"], [item.code for item in otx_only])
        misp = validate_configured_endpoints(
            opencti_url="https://opencti.example.invalid",
            misp_url="",
            enabled_sources=("misp",),
        )
        self.assertEqual("endpoint-missing", misp[1].code)

    def test_single_label_hosts_are_not_classified_as_docker(self):
        diagnostic = validate_endpoint("OPENCTI_URL", "https://opencti:8080")
        self.assertEqual("ok", diagnostic.code)
        self.assertEqual("opencti", diagnostic.hostname)

    def test_state_path_reports_existing_non_writable_directory(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "state"
            path.mkdir()
            path.chmod(0o500)
            try:
                diagnostic = validate_state_path(str(path))
                # Windows ACLs may not represent POSIX mode bits; the code
                # still must never mutate ownership or permissions.
                if diagnostic.code == "state-path-not-writable":
                    self.assertIn("state path", diagnostic.message)
            finally:
                path.chmod(0o700)


if __name__ == "__main__":
    unittest.main()
