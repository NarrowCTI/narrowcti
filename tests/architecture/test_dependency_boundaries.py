from __future__ import annotations

import ast
import json
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SRC = ROOT / "src/narrowcti"
LAYER_ROOTS = {
    "domain": SRC / "domain",
    "ports": SRC / "ports",
    "application": SRC / "application",
    "adapters": SRC / "adapters",
    "infrastructure": SRC / "infrastructure",
    "api": SRC / "api",
    "cli": SRC / "cli",
}
LEGACY = ("core", "connectors", "gateway", "exporters")
PURE_LAYERS = {"domain", "ports", "application"}
FORBIDDEN_PROVIDER_OR_IO = {
    "pycti",
    "stix2",
    "sigma",
    "fastapi",
    "uvicorn",
    "pydantic",
    "requests",
    "httpx",
    "httpx2",
    "aiohttp",
    "pymisp",
    "OTXv2",
    "socket",
    "urllib",
    "pathlib",
    "os",
    "shutil",
    "subprocess",
}

BOUNDARY_ALLOWLIST = json.loads(
    (ROOT / "docs/development/architecture-boundary-allowlist.json").read_text(encoding="utf-8")
)["exceptions"]
EXCEPTIONS = {
    (entry["source"].removeprefix("src/narrowcti/"), entry["module"])
    for entry in BOUNDARY_ALLOWLIST
}


def _module_for_path(path: Path) -> str:
    relative = path.relative_to(SRC).with_suffix("")
    return "narrowcti." + ".".join(relative.parts)


def _resolve_import(node: ast.ImportFrom, module: str) -> str:
    if node.level == 0:
        return node.module or ""
    package = module.split(".")[:-1]
    if node.level > len(package) + 1:
        return node.module or ""
    base = package[: len(package) - node.level + 1]
    if node.module:
        base.extend(node.module.split("."))
    return ".".join(base)


def _imports(path: Path) -> list[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    module = _module_for_path(path)
    values: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            values.extend(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            values.append(_resolve_import(node, module))
    return values


def _dynamic_imports(path: Path) -> list[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    values: list[str] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or not node.args:
            continue
        function = node.func
        is_import_module = (
            isinstance(function, ast.Attribute)
            and function.attr == "import_module"
            and isinstance(function.value, ast.Name)
            and function.value.id == "importlib"
        )
        is_builtin_import = isinstance(function, ast.Name) and function.id == "__import__"
        if is_import_module or is_builtin_import:
            argument = node.args[0]
            values.append(argument.value if isinstance(argument, ast.Constant) and isinstance(argument.value, str) else "<dynamic>")
    return values


def _matches(value: str, prefix: str) -> bool:
    return value == prefix or value.startswith(prefix + ".")


class DependencyBoundaryTests(unittest.TestCase):
    def test_canonical_boundaries_have_only_documented_legacy_exceptions(self):
        violations: list[str] = []
        for layer, directory in LAYER_ROOTS.items():
            if not directory.exists():
                continue
            for path in directory.rglob("*.py"):
                source = path.relative_to(SRC).as_posix()
                for imported in _imports(path):
                    if not imported:
                        continue
                    if any(_matches(imported, prefix) for prefix in LEGACY):
                        allowed = any(
                            source == expected_source and _matches(imported, expected_import)
                            for expected_source, expected_import in EXCEPTIONS
                        )
                        if not allowed:
                            violations.append(f"{source} imports legacy {imported}")
                    if layer == "domain" and imported.startswith("narrowcti."):
                        forbidden = ("ports", "application", "adapters", "infrastructure", "api", "cli")
                        if imported.split(".")[1:2] and imported.split(".")[1] in forbidden:
                            violations.append(f"{source} imports outward {imported}")
                    if layer == "ports" and imported.startswith("narrowcti."):
                        forbidden = ("application", "adapters", "infrastructure", "api", "cli")
                        if imported.split(".")[1:2] and imported.split(".")[1] in forbidden:
                            violations.append(f"{source} imports outward {imported}")
                    if layer == "application" and imported.startswith("narrowcti."):
                        forbidden = ("adapters", "infrastructure", "api", "cli")
                        if imported.split(".")[1:2] and imported.split(".")[1] in forbidden:
                            violations.append(f"{source} imports outward {imported}")
                    if layer == "adapters" and imported.startswith("narrowcti."):
                        if imported.split(".")[1:2] and imported.split(".")[1] in {"infrastructure", "api", "cli"}:
                            violations.append(f"{source} imports outward {imported}")
                    if layer == "api" and imported.startswith("narrowcti."):
                        if imported.split(".")[1:2] and imported.split(".")[1] == "cli":
                            violations.append(f"{source} imports outward {imported}")
        self.assertEqual([], violations, "\n".join(violations))

    def test_pure_layers_do_not_import_provider_sdks_or_io(self):
        violations: list[str] = []
        for layer in PURE_LAYERS:
            directory = LAYER_ROOTS[layer]
            if not directory.exists():
                continue
            for path in directory.rglob("*.py"):
                source = path.relative_to(SRC).as_posix()
                for imported in _imports(path):
                    root = imported.split(".", 1)[0]
                    if root in FORBIDDEN_PROVIDER_OR_IO:
                        violations.append(f"{source} imports forbidden provider/IO module {imported}")
        self.assertEqual([], violations, "\n".join(violations))

    def test_pure_layers_do_not_use_dynamic_imports(self):
        violations: list[str] = []
        for layer in PURE_LAYERS:
            directory = LAYER_ROOTS[layer]
            if not directory.exists():
                continue
            for path in directory.rglob("*.py"):
                source = path.relative_to(SRC).as_posix()
                for imported in _dynamic_imports(path):
                    violations.append(f"{source} uses dynamic import {imported}")
        self.assertEqual([], violations, "\n".join(violations))

    def test_boundary_rules_are_not_implemented_as_wildcard_allowlists(self):
        self.assertTrue(BOUNDARY_ALLOWLIST)
        required = {"source", "module", "reason", "owner", "removal_target"}
        for entry in BOUNDARY_ALLOWLIST:
            self.assertEqual(required, set(entry))
            self.assertNotIn("*", entry["source"] + entry["module"])


if __name__ == "__main__":
    unittest.main()
