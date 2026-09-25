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

    def test_application_capabilities_is_pure(self):
        imports = self._imports(ROOT / "src/narrowcti/application/capabilities.py")
        forbidden = ("gateway", "narrowcti.adapters", "requests", "http", "filesystem")
        self.assertFalse(
            [name for name in imports if name == "gateway" or name.startswith("narrowcti.adapters")],
            imports,
        )
        self.assertFalse([name for name in imports if name in forbidden], imports)

    def test_entitlement_port_does_not_depend_on_adapters_or_gateway(self):
        imports = self._imports(ROOT / "src/narrowcti/ports/entitlements.py")
        self.assertFalse(
            [name for name in imports if name == "gateway" or name.startswith("narrowcti.adapters")],
            imports,
        )

    def test_community_adapter_has_no_external_io_or_license_discovery(self):
        imports = self._imports(ROOT / "src/narrowcti/adapters/entitlements/community.py")
        forbidden_prefixes = ("requests", "http", "urllib", "socket", "importlib.metadata")
        self.assertFalse(
            [name for name in imports if name.startswith(forbidden_prefixes)],
            imports,
        )


if __name__ == "__main__":
    unittest.main()
