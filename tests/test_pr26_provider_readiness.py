from __future__ import annotations

import tempfile
import unittest
import contextlib
import io
import json
import sys
from pathlib import Path
from unittest.mock import patch

import requests

from narrowcti.adapters.sources.bounded_http import probe_status
from narrowcti.adapters.sources.misp.explorer import MISPSourceExplorer
from narrowcti.adapters.sources.otx.explorer import OTXSourceExplorer
from narrowcti.application.provider_readiness import ProviderReadinessService
from narrowcti.infrastructure.config.web_settings import SourceExplorerSettings
from narrowcti.infrastructure.runtime.web_composition import build_source_explorer
from narrowcti.ports.source_explorer import ExplorerError, ProviderDescriptor


class _Probe:
    def __init__(self, key="misp", *, available=True, reason=None, outcome=200):
        self._descriptor = ProviderDescriptor(key, key.upper(), available, reason)
        self.outcome = outcome
        self.called = False

    def descriptor(self):
        return self._descriptor

    def probe_readiness(self):
        self.called = True
        if isinstance(self.outcome, Exception):
            raise self.outcome
        return self.outcome


class ProviderReadinessTests(unittest.TestCase):
    def test_ops_cli_emits_only_safe_readiness_projection(self):
        from narrowcti.cli import provider_readiness

        provider = _Probe(outcome=200)
        service = ProviderReadinessService((provider,))
        output = io.StringIO()
        with patch.object(sys, "argv", ["provider_readiness", "--json"]), patch(
            "narrowcti.cli.provider_readiness.load_web_settings",
            return_value=type("Settings", (), {"sources": SourceExplorerSettings()})(),
        ), patch(
            "narrowcti.cli.provider_readiness.build_source_explorer", return_value=type(
                "Explorer", (), {"check_readiness_all": lambda _self: service.check_all()}
            )(),
        ), contextlib.redirect_stdout(output):
            self.assertEqual(0, provider_readiness.main())
        rendered = output.getvalue()
        self.assertEqual("ready", json.loads(rendered)[0]["state"])
        self.assertNotIn("synthetic", rendered)
        self.assertNotIn("Authorization", rendered)

    def test_static_preflight_remains_network_free(self):
        from gateway.preflight import build_preflight_report
        from tests.test_gateway_preflight import make_settings

        with patch(
            "narrowcti.adapters.sources.bounded_http.requests.Session",
            side_effect=AssertionError("static preflight must not use the network"),
        ):
            report = build_preflight_report(
                make_settings(enabled_sources=["otx"]),
                env={
                    "OPENCTI_URL": "https://opencti.example.invalid",
                    "OTX_DRY_RUN": "true",
                },
            )
        self.assertTrue(report.ok)

    def test_fixed_taxonomy_covers_configuration_credentials_status_and_transport(self):
        cases = (
            (_Probe(available=False, reason="endpoint_not_configured"), "not_configured"),
            (_Probe(available=False, reason="credential_missing"), "credential_missing"),
            (_Probe(outcome=200), "ready"),
            (_Probe(outcome=401), "auth_rejected"),
            (_Probe(outcome=403), "auth_rejected"),
            (_Probe(outcome=429), "rate_limited"),
            (_Probe(outcome=503), "degraded"),
            (_Probe(outcome=302), "degraded"),
            (_Probe(outcome=ExplorerError("provider_tls_failed", "secret text")), "tls_failed"),
            (_Probe(outcome=ExplorerError("provider_unavailable", "secret text")), "unreachable"),
            (_Probe(outcome=ExplorerError("provider_timeout", "secret text")), "unreachable"),
            (_Probe(outcome=RuntimeError("synthetic-secret")), "degraded"),
        )
        for provider, expected in cases:
            with self.subTest(expected=expected, outcome=provider.outcome):
                result = ProviderReadinessService((provider,)).check(provider.descriptor().key)
                self.assertEqual(expected, result.state.value)
                self.assertNotIn("secret", repr(result))
                self.assertNotIn("synthetic", result.message)
                self.assertTrue(result.checked_at.endswith("Z"))
                if not provider.descriptor().available:
                    self.assertFalse(provider.called)

    def test_unknown_provider_fails_without_echoing_the_requested_key(self):
        service = ProviderReadinessService((_Probe(),))
        with self.assertRaises(KeyError):
            service.check("synthetic-secret-provider")

    def test_misp_endpoint_and_secret_file_validation_are_independent_and_fail_safe(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            missing = root / "missing.key"
            empty = root / "empty.key"
            empty.write_text("  \n", encoding="utf-8")
            folder = root / "directory.key"
            folder.mkdir()
            oversized = root / "oversized.key"
            oversized.write_text("x" * 8193, encoding="utf-8")

            for path in ("", str(missing), str(empty), str(folder), str(oversized)):
                service = build_source_explorer(SourceExplorerSettings(
                    misp_url="https://misp.example.invalid", misp_key_file=path
                ))
                result = service.check_readiness("misp")
                self.assertEqual("credential_missing", result.state.value)

            key = root / "misp.key"
            key.write_text("synthetic-misp-key\n", encoding="utf-8")
            for endpoint in ("", "not a URL"):
                service = build_source_explorer(SourceExplorerSettings(misp_url=endpoint, misp_key_file=str(key)))
                result = service.check_readiness("misp")
                self.assertEqual("not_configured", result.state.value)

    def test_otx_missing_key_file_is_credential_missing(self):
        with tempfile.TemporaryDirectory() as directory:
            service = build_source_explorer(SourceExplorerSettings(otx_key_file=str(Path(directory) / "missing")))
            self.assertEqual("credential_missing", service.check_readiness("otx").state.value)

    @patch("narrowcti.adapters.sources.bounded_http.requests.Session")
    def test_probe_is_bounded_non_redirecting_bodyless_and_tls_verified(self, session_factory):
        response = _StatusResponse(200)
        session = session_factory.return_value
        session.request.return_value = response
        status = probe_status(
            "GET", "https://misp.example/servers/getVersion", headers={"Authorization": "synthetic-key"}
        )
        self.assertEqual(200, status)
        self.assertFalse(session.trust_env)
        kwargs = session.request.call_args.kwargs
        self.assertEqual((3.0, 5.0), kwargs["timeout"])
        self.assertEqual(False, kwargs["allow_redirects"])
        self.assertTrue(kwargs["verify"])
        self.assertTrue(kwargs["stream"])
        self.assertFalse(response.iterated)
        session.close.assert_called_once_with()

    def test_transport_exception_categories_are_stable_and_safe(self):
        categories = (
            (requests.exceptions.SSLError("synthetic secret"), "provider_tls_failed"),
            (requests.exceptions.Timeout("synthetic secret"), "provider_timeout"),
            (requests.exceptions.ConnectionError("synthetic secret"), "provider_unavailable"),
        )
        for error, expected in categories:
            with self.subTest(expected=expected), patch(
                "narrowcti.adapters.sources.bounded_http.requests.Session"
            ) as factory:
                factory.return_value.request.side_effect = error
                with self.assertRaises(ExplorerError) as raised:
                    probe_status("GET", "https://provider.example/", headers={})
                self.assertEqual(expected, raised.exception.code)
                self.assertNotIn("synthetic secret", str(raised.exception))

    @patch("narrowcti.adapters.sources.misp.explorer.probe_status", return_value=403)
    def test_misp_live_probe_is_get_with_dedicated_auth_header_and_maps_rejection(self, probe):
        provider = MISPSourceExplorer("https://misp.example/api", "synthetic-misp-key")
        service = ProviderReadinessService((provider,))
        result = service.check("misp")
        self.assertEqual("auth_rejected", result.state.value)
        args, kwargs = probe.call_args
        self.assertEqual("GET", args[0])
        self.assertEqual("https://misp.example/api/servers/getVersion", args[1])
        self.assertEqual("synthetic-misp-key", kwargs["headers"]["Authorization"])
        self.assertTrue(kwargs["verify_tls"])

    @patch("narrowcti.adapters.sources.otx.explorer.probe_status", return_value=200)
    def test_otx_live_probe_uses_supported_read_only_subscriptions_route(self, probe):
        provider = OTXSourceExplorer("synthetic-otx-key")
        result = ProviderReadinessService((provider,)).check("otx")
        self.assertEqual("ready", result.state.value)
        args, kwargs = probe.call_args
        self.assertEqual("GET", args[0])
        self.assertEqual("https://otx.alienvault.com/api/v1/pulses/subscribed", args[1])
        self.assertEqual({"limit": "1"}, kwargs["params"])
        self.assertEqual("synthetic-otx-key", kwargs["headers"]["X-OTX-API-KEY"])
        self.assertTrue(kwargs["verify_tls"])


class _StatusResponse:
    def __init__(self, status):
        self.status_code = status
        self.iterated = False

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def iter_content(self, *_args):
        self.iterated = True
        return iter((b"secret body should not be read",))


if __name__ == "__main__":
    unittest.main()
