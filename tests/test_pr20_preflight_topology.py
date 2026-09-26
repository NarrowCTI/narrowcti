import json
import os
import tempfile
import unittest
from pathlib import Path

from gateway.preflight import build_preflight_report
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
        if hasattr(os, "geteuid") and os.geteuid() == 0:
            self.skipTest("root can bypass directory mode-bit write checks")
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
                elif os.name != "nt":
                    self.fail(f"expected non-writable state path, got {diagnostic.code}")
            finally:
                path.chmod(0o700)

    def test_state_path_file_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "state.txt"
            path.write_text("not a directory", encoding="utf-8")
            diagnostic = validate_state_path(str(path))
            self.assertEqual("state-path-not-directory", diagnostic.code)

    def test_state_path_absent_is_neutral_and_does_not_promise_creation(self):
        with tempfile.TemporaryDirectory() as directory:
            diagnostic = validate_state_path(str(Path(directory) / "new" / "state"))
            self.assertEqual("state-path-absent", diagnostic.code)
            self.assertNotIn("will be created", diagnostic.message)

    def test_gateway_preflight_rejects_otx_without_opencti_url(self):
        report = build_preflight_report(
            _settings(enabled_sources=["otx"]),
            env={"OTX_DRY_RUN": "true"},
        )
        self.assertFalse(report.ok)
        self.assertIn("endpoint-missing", {issue.code for issue in report.issues})

    def test_gateway_preflight_rejects_misp_without_misp_url(self):
        report = build_preflight_report(
            _settings(enabled_sources=["misp"]),
            env={"OPENCTI_URL": "https://opencti.example.invalid"},
        )
        self.assertFalse(report.ok)
        self.assertIn("endpoint-missing", {issue.code for issue in report.issues})

    def test_gateway_preflight_otx_only_does_not_require_misp_url(self):
        report = build_preflight_report(
            _settings(enabled_sources=["otx"]),
            env={"OPENCTI_URL": "https://opencti.example.invalid"},
        )
        endpoint_errors = {
            issue.code
            for issue in report.issues
            if issue.code in {"endpoint-missing", "endpoint-invalid", "endpoint-credentials-embedded"}
        }
        self.assertEqual(set(), endpoint_errors)

    def test_gateway_preflight_accepts_valid_misp_and_otx_endpoints(self):
        report = build_preflight_report(
            _settings(enabled_sources=["otx", "misp"]),
            env={
                "OPENCTI_URL": "https://opencti.example.invalid",
                "MISP_URL": "https://misp.example.invalid",
            },
        )
        endpoint_errors = {
            issue.code
            for issue in report.issues
            if issue.code in {"endpoint-missing", "endpoint-invalid", "endpoint-credentials-embedded"}
        }
        self.assertEqual(set(), endpoint_errors)


def _settings(**overrides):
    if __package__:
        from tests.test_gateway_preflight import make_settings
    else:
        from test_gateway_preflight import make_settings

    return make_settings(**overrides)


if __name__ == "__main__":
    unittest.main()
