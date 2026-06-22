import os
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import ANY, patch

from gateway.connector import main
from gateway.runtime import SourceRegistry, run_gateway_loop, run_gateway_once
from gateway.settings import GatewaySettings, load_settings
from gateway.sources import build_artifact_dedup, build_source_dedup


class GatewaySettingsTests(unittest.TestCase):
    def test_load_settings_reads_gateway_controls(self):
        env = {
            "NARROWCTI_ENABLED_SOURCES": "otx, MISP",
            "NARROWCTI_DRY_RUN": "true",
            "NARROWCTI_RUN_ONCE": "yes",
            "NARROWCTI_SOURCE_INTERVAL_SECONDS": "300",
            "NARROWCTI_DEDUP_MODE": "hybrid",
            "NARROWCTI_OPENCTI_DEDUP_LOOKUP": "1",
            "NARROWCTI_DEDUP_STATE_FILE": "/state/dedup.json",
        }

        with patch.dict(os.environ, env, clear=True):
            settings = load_settings()

        self.assertEqual(["otx", "misp"], settings.enabled_sources)
        self.assertTrue(settings.dry_run)
        self.assertTrue(settings.run_once)
        self.assertEqual(300, settings.source_interval_seconds)
        self.assertEqual("hybrid", settings.dedup_mode)
        self.assertTrue(settings.opencti_dedup_lookup)
        self.assertEqual("/state/dedup.json", settings.dedup_state_file)

    def test_load_settings_uses_connector_interval_as_legacy_default(self):
        with patch.dict(os.environ, {"CONNECTOR_RUN_INTERVAL": "120"}, clear=True):
            settings = load_settings()

        self.assertEqual(["otx"], settings.enabled_sources)
        self.assertEqual(120, settings.source_interval_seconds)

    def test_settings_rejects_empty_sources(self):
        with self.assertRaises(ValueError):
            GatewaySettings(
                mode="gateway",
                enabled_sources=[],
                dry_run=False,
                run_once=False,
                source_interval_seconds=60,
                state_dir="/state",
                decision_audit_dir="/state/audit",
                dedup_mode="source",
                opencti_dedup_lookup=False,
                dedup_state_file="/state/dedup.json",
            )


    def test_build_artifact_dedup_uses_gateway_mode(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            enabled = SimpleNamespace(
                dedup_mode="hybrid",
                dedup_state_file=os.path.join(tmpdir, "dedup.json"),
            )
            disabled = SimpleNamespace(
                dedup_mode="source",
                dedup_state_file=os.path.join(tmpdir, "dedup.json"),
            )

            self.assertIsNotNone(build_artifact_dedup(enabled))
            self.assertIsNone(build_artifact_dedup(disabled))
    def test_build_source_dedup_can_enable_opencti_lookup_only(self):
        dedup = build_source_dedup(
            api_client="api",
            artifact_dedup=None,
            opencti_dedup_lookup=True,
            logger=lambda message: None,
        )

        self.assertIsNotNone(dedup)
        self.assertIsNotNone(dedup.opencti_lookup)
        self.assertIsNone(dedup.local_index)

class GatewayRuntimeTests(unittest.TestCase):
    def test_registry_normalizes_source_keys(self):
        registry = SourceRegistry().register(" OTX ", "OTX", lambda: object())

        self.assertEqual(("otx",), registry.source_keys)
        self.assertEqual("otx", registry.get("OTX").key)

    def test_run_gateway_once_executes_sources_and_aggregates_summaries(self):
        calls = []
        summary = SimpleNamespace(
            reviewed=3,
            ingested=1,
            dropped=1,
            quarantined=0,
            skipped=1,
            errors=0,
            dry_run=0,
        )
        runner = SimpleNamespace(run_once=lambda: calls.append("otx") or [summary])
        registry = SourceRegistry().register("otx", "OTX", lambda: runner)
        settings = SimpleNamespace(enabled_sources=["otx"])
        logs = []

        result = run_gateway_once(settings, registry, logs.append)

        self.assertEqual(["otx"], calls)
        self.assertEqual(1, result.succeeded)
        self.assertEqual(0, result.failed)
        self.assertEqual(3, result.total("reviewed"))
        self.assertEqual(1, result.total("ingested"))
        self.assertTrue(any("Gateway summary" in line for line in logs))

    def test_run_gateway_once_isolates_source_failure(self):
        good_summary = SimpleNamespace(reviewed=2, ingested=0, errors=0)
        good = SimpleNamespace(run_once=lambda: [good_summary])

        def failing_factory():
            raise RuntimeError("source offline")

        registry = (
            SourceRegistry()
            .register("bad", "Bad", failing_factory)
            .register("good", "Good", lambda: good)
        )
        settings = SimpleNamespace(enabled_sources=["bad", "good"])

        result = run_gateway_once(settings, registry, lambda msg: None)

        self.assertEqual(1, result.succeeded)
        self.assertEqual(1, result.failed)
        self.assertEqual("source offline", result.results[0].error)
        self.assertEqual(2, result.total("reviewed"))

    def test_run_gateway_once_reports_unknown_source(self):
        registry = SourceRegistry()
        settings = SimpleNamespace(enabled_sources=["unknown"])

        result = run_gateway_once(settings, registry, lambda msg: None)

        self.assertEqual(0, result.succeeded)
        self.assertEqual(1, result.failed)
        self.assertEqual("unknown", result.results[0].source_key)

    def test_run_gateway_loop_runs_cycle_and_sleeps(self):
        calls = []
        runner = SimpleNamespace(run_once=lambda: calls.append("run_once") or [])
        registry = SourceRegistry().register("otx", "OTX", lambda: runner)
        settings = SimpleNamespace(enabled_sources=["otx"], source_interval_seconds=15)

        def sleeper(seconds):
            calls.append(("sleep", seconds))
            raise StopIteration

        with self.assertRaises(StopIteration):
            run_gateway_loop(settings, registry, calls.append, sleeper=sleeper)

        self.assertIn("run_once", calls)
        self.assertIn("Gateway sleeping 15s", calls)
        self.assertEqual(("sleep", 15), calls[-1])


class GatewayConnectorTests(unittest.TestCase):
    def test_main_runs_once_when_configured(self):
        settings = SimpleNamespace(run_once=True)
        registry = object()

        with patch("gateway.connector.load_settings", return_value=settings), patch(
            "gateway.connector.default_source_registry", return_value=registry
        ), patch("gateway.connector.run_gateway_once") as run_once, patch(
            "gateway.connector.run_gateway_loop"
        ) as run_loop:
            main()

        run_once.assert_called_once_with(settings, registry, ANY)
        run_loop.assert_not_called()

    def test_main_enters_loop_by_default(self):
        settings = SimpleNamespace(run_once=False)
        registry = object()

        with patch("gateway.connector.load_settings", return_value=settings), patch(
            "gateway.connector.default_source_registry", return_value=registry
        ), patch("gateway.connector.run_gateway_once") as run_once, patch(
            "gateway.connector.run_gateway_loop"
        ) as run_loop:
            main()

        run_once.assert_not_called()
        run_loop.assert_called_once_with(settings, registry, ANY)


if __name__ == "__main__":
    unittest.main()
