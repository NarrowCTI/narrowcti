import ast
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class CapabilityBoundaryTests(unittest.TestCase):
    def _imports(self, path):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        imports = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imports.extend(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imports.append(node.module)
        return imports

    def _assert_no_io_imports(self, path):
        imports = self._imports(path)
        forbidden_roots = {
            "os",
            "pathlib",
            "socket",
            "requests",
            "http",
            "httpx",
            "urllib",
            "urllib3",
            "aiohttp",
            "importlib.metadata",
        }
        violations = [
            name
            for name in imports
            if name in forbidden_roots
            or any(name.startswith(f"{root}.") for root in forbidden_roots)
        ]
        self.assertFalse(violations, f"forbidden I/O/discovery imports in {path}: {violations}")

    def test_application_capabilities_is_pure(self):
        path = ROOT / "src/narrowcti/application/capabilities.py"
        imports = self._imports(path)
        self.assertFalse(
            [name for name in imports if name == "gateway" or name.startswith("narrowcti.adapters")],
            imports,
        )
        self._assert_no_io_imports(path)

    def test_entitlement_port_does_not_depend_on_adapters_or_gateway(self):
        imports = self._imports(ROOT / "src/narrowcti/ports/entitlements.py")
        self.assertFalse(
            [name for name in imports if name == "gateway" or name.startswith("narrowcti.adapters")],
            imports,
        )

    def test_community_adapter_has_no_external_io_or_license_discovery(self):
        self._assert_no_io_imports(
            ROOT / "src/narrowcti/adapters/entitlements/community.py"
        )


if __name__ == "__main__":
    unittest.main()
