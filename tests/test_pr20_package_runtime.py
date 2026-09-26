import ast
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class PackageRuntimeContractTests(unittest.TestCase):
    def test_runtime_helper_uses_distribution_file_inventory(self):
        source = (ROOT / "scripts" / "validate_runtime_package.py").read_text(encoding="utf-8")
        tree = ast.parse(source)
        self.assertIn('distribution("narrowcti")', source)
        self.assertIn("PYTHONPYCACHEPREFIX", source)
        self.assertNotIn("os.walk", source)
        self.assertNotIn("site-packages", source)
        self.assertIsInstance(tree, ast.Module)

    def test_ci_runs_installed_package_from_external_directory(self):
        workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
        self.assertIn("python -m pip install .", workflow)
        self.assertIn("mktemp -d", workflow)
        self.assertIn("${GITHUB_WORKSPACE}/tests", workflow)
        self.assertNotIn("PYTHONPATH: src:.", workflow)
        self.assertNotIn("python -m py_compile \\", workflow)

    def test_gateway_image_is_installed_package_runtime(self):
        dockerfile = (ROOT / "Dockerfile.gateway").read_text(encoding="utf-8")
        self.assertIn("AS builder", dockerfile)
        self.assertIn("/opt/narrowcti-venv", dockerfile)
        self.assertIn("USER narrowcti:narrowcti", dockerfile)
        self.assertIn("PYTHONDONTWRITEBYTECODE=1", dockerfile)
        self.assertNotIn("PYTHONPATH=", dockerfile)
        self.assertNotIn("COPY core /app/core", dockerfile)
        self.assertNotIn("COPY src /app/src", dockerfile)

    def test_release_validator_has_no_manual_module_arrays(self):
        script = (ROOT / "scripts" / "validate-release-runtime.ps1").read_text(encoding="utf-8")
        self.assertNotIn("$CoreModules", script)
        self.assertNotIn("$GatewayModules", script)
        self.assertIn("validate_runtime_package.py", script)


if __name__ == "__main__":
    unittest.main()
