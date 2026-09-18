import importlib.util
import os
import subprocess
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


LEGACY_FIRST = r'''
import sys
import connectors.misp.feed_adapter as legacy_connectors
import core.feed_contract as legacy_core
import exporters.stix_builder as legacy_exporters
import gateway.settings as legacy_gateway
import narrowcti.connectors.misp.feed_adapter as canonical_connectors
import narrowcti.core.feed_contract as canonical_core
import narrowcti.exporters.stix_builder as canonical_exporters
import narrowcti.gateway.settings as canonical_gateway
assert sys.modules["connectors.misp.feed_adapter"] is sys.modules["narrowcti.connectors.misp.feed_adapter"]
assert sys.modules["core.feed_contract"] is sys.modules["narrowcti.core.feed_contract"]
assert sys.modules["exporters.stix_builder"] is sys.modules["narrowcti.exporters.stix_builder"]
assert sys.modules["gateway.settings"] is sys.modules["narrowcti.gateway.settings"]
assert legacy_connectors is canonical_connectors
assert legacy_core is canonical_core
assert legacy_exporters is canonical_exporters
assert legacy_gateway is canonical_gateway
'''


CANONICAL_FIRST = r'''
import sys
import narrowcti.connectors.misp.feed_adapter as canonical_connectors
import narrowcti.core.feed_contract as canonical_core
import narrowcti.exporters.stix_builder as canonical_exporters
import narrowcti.gateway.settings as canonical_gateway
import connectors.misp.feed_adapter as legacy_connectors
import core.feed_contract as legacy_core
import exporters.stix_builder as legacy_exporters
import gateway.settings as legacy_gateway
assert sys.modules["connectors.misp.feed_adapter"] is sys.modules["narrowcti.connectors.misp.feed_adapter"]
assert sys.modules["core.feed_contract"] is sys.modules["narrowcti.core.feed_contract"]
assert sys.modules["exporters.stix_builder"] is sys.modules["narrowcti.exporters.stix_builder"]
assert sys.modules["gateway.settings"] is sys.modules["narrowcti.gateway.settings"]
assert canonical_connectors is legacy_connectors
assert canonical_core is legacy_core
assert canonical_exporters is legacy_exporters
assert canonical_gateway is legacy_gateway
'''


class PackageCompatibilityTests(unittest.TestCase):
    def _run_source_import_order(self, code):
        env = os.environ.copy()
        source_path = os.pathsep.join((str(ROOT / "src"), str(ROOT)))
        env["PYTHONPATH"] = source_path
        subprocess.run(
            [sys.executable, "-c", code],
            cwd=ROOT,
            env=env,
            check=True,
            capture_output=True,
            text=True,
        )

    def test_submodule_identity_legacy_import_first(self):
        self._run_source_import_order(LEGACY_FIRST)

    def test_submodule_identity_canonical_import_first(self):
        self._run_source_import_order(CANONICAL_FIRST)

    def test_facades_and_aliases_are_exhaustive(self):
        spec = importlib.util.spec_from_file_location(
            "compat_contract", ROOT / "src" / "narrowcti" / "compat.py"
        )
        compat = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(compat)

        # Derive the expected contract from the current legacy source tree. This
        # is test-only filesystem inspection; runtime aliases stay static.
        legacy_modules = {
            ".".join(path.relative_to(ROOT).with_suffix("").parts)
            for family in ("connectors", "core", "exporters", "gateway")
            for path in (ROOT / family).rglob("*.py")
            if path.name != "__init__.py"
        }
        expected_canonical = {f"narrowcti.{module}" for module in legacy_modules}
        facades = {
            ".".join(path.relative_to(ROOT / "src").with_suffix("").parts)
            for family in ("connectors", "core", "exporters", "gateway")
            for path in (ROOT / "src" / "narrowcti" / family).rglob("*.py")
            if path.name != "__init__.py"
        }
        aliases = set(compat.LEGACY_MODULE_ALIASES)
        self.assertSetEqual(expected_canonical, facades, "Legacy modules and facades differ")
        self.assertSetEqual(expected_canonical, aliases, "Legacy modules and aliases differ")
        self.assertDictEqual(
            {
                canonical: canonical.removeprefix("narrowcti.")
                for canonical in expected_canonical
            },
            compat.LEGACY_MODULE_ALIASES,
            "An alias points to a legacy module different from its canonical key",
        )

    def test_source_mode_package_import_is_independent_of_distribution_metadata(self):
        env = os.environ.copy()
        env["PYTHONPATH"] = os.pathsep.join((str(ROOT / "src"), str(ROOT)))
        # A preceding wheel build can leave discoverable .egg-info in ROOT.
        # Force the missing-distribution condition independently of build artifacts.
        code = """
from importlib.metadata import PackageNotFoundError
from unittest.mock import patch

with patch("importlib.metadata.version", side_effect=PackageNotFoundError("narrowcti")):
    import narrowcti
    print(narrowcti.__version__)
"""
        result = subprocess.run(
            [sys.executable, "-S", "-c", code],
            cwd=ROOT,
            env=env,
            check=True,
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.stdout.strip(), "0+unknown")

    def test_otx_connector_preserves_historical_script_contract(self):
        connector = (ROOT / "connectors" / "otx" / "connector.py").read_text(encoding="utf-8")
        dockerfile = (ROOT / "connectors" / "otx" / "Dockerfile").read_text(encoding="utf-8")

        self.assertIn("from otx_client import OTXClient", connector)
        self.assertIn("from processor import OTXProcessor", connector)
        self.assertIn('CMD ["python", "connector.py"]', dockerfile)
        self.assertNotIn("sys.path", connector)

    def test_otx_package_imports_are_not_current_contract(self):
        env = os.environ.copy()
        env["PYTHONPATH"] = os.pathsep.join((str(ROOT / "src"), str(ROOT)))
        for module_name in ("connectors.otx.connector", "narrowcti.connectors.otx.connector"):
            result = subprocess.run(
                [sys.executable, "-c", f"import {module_name}"],
                cwd=ROOT,
                env=env,
                capture_output=True,
                text=True,
            )
            self.assertNotEqual(result.returncode, 0, module_name)
            self.assertIn("No module named 'otx_client'", result.stderr)


if __name__ == "__main__":
    unittest.main()
