import ast
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PACKAGE_ROOTS = (
    ROOT / "src" / "narrowcti" / "domain" / "detection",
    ROOT / "src" / "narrowcti" / "domain" / "validation",
)
FORBIDDEN_PREFIXES = (
    "gateway",
    "core",
    "connectors",
    "exporters",
    "adapters",
    "ports",
    "infrastructure",
    "api",
    "requests",
    "httpx",
    "aiohttp",
    "urllib",
    "socket",
    "pycti",
    "stix2",
    "sigma",
    "fastapi",
    "commercial",
    "private",
    "pathlib",
    "os",
    "shutil",
    "subprocess",
)


def _absolute_imports(tree):
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            yield from (alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            yield node.module


class DetectionFoundationBoundaryTests(unittest.TestCase):
    def test_domain_detection_and_validation_have_no_runtime_boundary_imports(self):
        for package_root in PACKAGE_ROOTS:
            for path in package_root.rglob("*.py"):
                tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
                for imported in _absolute_imports(tree):
                    root = imported.split(".", 1)[0]
                    self.assertNotIn(
                        root,
                        FORBIDDEN_PREFIXES,
                        f"{path} imports forbidden runtime boundary: {imported}",
                    )

    def test_domain_imports_are_stdlib_or_sibling_domain_modules(self):
        allowed_external = {"__future__", "collections", "dataclasses", "typing", "re"}
        for package_root in PACKAGE_ROOTS:
            for path in package_root.rglob("*.py"):
                tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
                for imported in _absolute_imports(tree):
                    root = imported.split(".", 1)[0]
                    self.assertIn(
                        root,
                        allowed_external | {"narrowcti"},
                        f"unexpected non-domain import in {path}: {imported}",
                    )
                    if imported.startswith("narrowcti."):
                        self.assertTrue(
                            imported.startswith("narrowcti.domain.detection")
                            or imported.startswith("narrowcti.domain.validation"),
                            f"cross-domain import outside detection/validation: {imported}",
                        )

    def test_contract_modules_import_without_provider_packages(self):
        import narrowcti.domain.detection.artifacts  # noqa: F401
        import narrowcti.domain.detection.requirements  # noqa: F401
        import narrowcti.domain.detection.telemetry  # noqa: F401
        import narrowcti.domain.validation.contracts  # noqa: F401
        import narrowcti.domain.validation.evidence  # noqa: F401


if __name__ == "__main__":
    unittest.main()
