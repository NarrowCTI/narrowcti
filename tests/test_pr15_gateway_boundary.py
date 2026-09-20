import ast
import inspect
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from narrowcti.application.provider_registry import SourceRegistry
from narrowcti.application.runtime import run_gateway_once
from narrowcti.infrastructure.runtime.gateway_composition import default_source_registry
from narrowcti.infrastructure.runtime.summary_store import write_gateway_summary


ROOT = Path(__file__).resolve().parents[1]


class GatewayBoundaryTests(unittest.TestCase):
    def test_application_modules_have_no_concrete_or_filesystem_boundary_imports(self):
        forbidden = {"connectors", "gateway", "pycti", "infrastructure"}
        for path in (ROOT / "src" / "narrowcti" / "application").rglob("*.py"):
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    names = [alias.name for alias in node.names]
                elif isinstance(node, ast.ImportFrom):
                    names = [node.module or ""]
                else:
                    continue
                for name in names:
                    self.assertNotIn(name.split(".")[0], forbidden, f"{path}: {name}")

        runtime_source = inspect.getsource(run_gateway_once)
        self.assertNotIn("open(", runtime_source)
        self.assertNotIn("os.", runtime_source)

    def test_registry_has_no_concrete_provider_imports(self):
        source = (ROOT / "src" / "narrowcti" / "application" / "provider_registry.py").read_text(encoding="utf-8")
        tree = ast.parse(source)
        imports = [
            node.module if isinstance(node, ast.ImportFrom) else node.names[0].name
            for node in ast.walk(tree)
            if isinstance(node, (ast.Import, ast.ImportFrom))
        ]
        self.assertFalse(any(name and name.split(".")[0] in {"connectors", "gateway", "pycti"} for name in imports))

    def test_canonical_settings_and_cli_do_not_import_legacy_gateway(self):
        paths = (
            ROOT / "src" / "narrowcti" / "infrastructure" / "config" / "settings.py",
            ROOT / "src" / "narrowcti" / "cli" / "gateway.py",
        )
        for path in paths:
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    names = [alias.name for alias in node.names]
                elif isinstance(node, ast.ImportFrom):
                    names = [node.module or ""]
                else:
                    continue
                self.assertFalse(
                    any(name == "gateway" or name.startswith("gateway.") for name in names),
                    f"{path}: {names}",
                )

    def test_registration_is_lazy_and_selected_source_only_is_constructed(self):
        calls = []
        registry = (
            SourceRegistry()
            .register("misp", "MISP", lambda: calls.append("misp") or SimpleNamespace(run_once=lambda: []))
            .register("otx", "OTX", lambda: calls.append("otx") or SimpleNamespace(run_once=lambda: []))
        )
        self.assertEqual([], calls)
        result = run_gateway_once(SimpleNamespace(enabled_sources=["otx"]), registry, lambda _: None)
        self.assertEqual(["otx"], calls)
        self.assertEqual(1, result.succeeded)

    def test_inactive_misp_does_not_load_credentials_when_otx_selected(self):
        settings = SimpleNamespace(
            enabled_sources=["otx"], dedup_mode="off", dedup_state_file="", opencti_dedup_lookup=False
        )
        with patch(
            "narrowcti.infrastructure.runtime.gateway_composition.build_misp_runner",
            side_effect=AssertionError("MISP must remain lazy"),
        ), patch(
            "narrowcti.infrastructure.runtime.gateway_composition.build_otx_runner",
            return_value=SimpleNamespace(run_once=lambda: []),
        ) as otx:
            registry = default_source_registry(lambda _: None, settings)
            run_gateway_once(settings, registry, lambda _: None)
        otx.assert_called_once()

    def test_inactive_otx_does_not_load_credentials_when_misp_selected(self):
        settings = SimpleNamespace(
            enabled_sources=["misp"], dedup_mode="off", dedup_state_file="", opencti_dedup_lookup=False
        )
        with patch(
            "narrowcti.infrastructure.runtime.gateway_composition.build_otx_runner",
            side_effect=AssertionError("OTX must remain lazy"),
        ), patch(
            "narrowcti.infrastructure.runtime.gateway_composition.build_misp_runner",
            return_value=SimpleNamespace(run_once=lambda: []),
        ) as misp:
            registry = default_source_registry(lambda _: None, settings)
            run_gateway_once(settings, registry, lambda _: None)
        misp.assert_called_once()

    def test_default_registry_shares_artifact_index_across_source_factories(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            settings = SimpleNamespace(
                dedup_mode="artifact",
                dedup_state_file=str(Path(tmpdir) / "dedup.json"),
                opencti_dedup_lookup=False,
            )
            registry = default_source_registry(lambda _: None, settings)
            otx_factory = registry.get("otx").factory
            misp_factory = registry.get("misp").factory
            with patch("narrowcti.infrastructure.runtime.gateway_composition.build_otx_runner") as otx, patch(
                "narrowcti.infrastructure.runtime.gateway_composition.build_misp_runner"
            ) as misp:
                otx.return_value = SimpleNamespace(run_once=lambda: [])
                misp.return_value = SimpleNamespace(run_once=lambda: [])
                otx_factory()
                misp_factory()
            self.assertIs(otx.call_args.args[1], misp.call_args.args[1])

    def test_summary_log_precedes_jsonl_sink_and_sink_failure_is_non_fatal(self):
        events = []
        runner = SimpleNamespace(run_once=lambda: [])
        registry = SourceRegistry().register("otx", "OTX", lambda: runner)
        settings = SimpleNamespace(enabled_sources=["otx"])

        def logger(message):
            events.append(("log", message))

        def sink(summary):
            events.append(("write", summary))
            raise OSError("disk full")

        summary = run_gateway_once(settings, registry, logger, summary_sink=sink)
        self.assertEqual(1, summary.succeeded)
        summary_index = next(i for i, event in enumerate(events) if "Gateway summary:" in event[1])
        write_index = next(i for i, event in enumerate(events) if event[0] == "write")
        self.assertLess(summary_index, write_index)

    def test_summary_store_write_failure_keeps_historical_log_message(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            summary_file = Path(tmpdir) / "summary-directory"
            summary_file.mkdir()
            logs = []
            write_gateway_summary(SimpleNamespace(to_dict=lambda: {}), str(summary_file), logs.append)
        self.assertEqual(1, len(logs))
        self.assertIn(f"Gateway summary write failed: {summary_file} error=", logs[0])

    def test_canonical_opencti_client_has_no_legacy_gateway_import(self):
        path = ROOT / "src" / "narrowcti" / "adapters" / "opencti" / "client.py"
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                names = [alias.name for alias in node.names]
            elif isinstance(node, ast.ImportFrom):
                names = [node.module or ""]
            else:
                continue
            self.assertFalse(any(name == "gateway" or name.startswith("gateway.") for name in names))


if __name__ == "__main__":
    unittest.main()
