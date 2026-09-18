import tomllib
import unittest
from pathlib import Path

from packaging.version import Version


ROOT = Path(__file__).resolve().parents[1]


class ProjectMetadataTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
        cls.dependencies = set(cls.project["project"]["dependencies"])

    def test_project_metadata_uses_version_file_and_certified_runtime(self):
        self.assertEqual(self.project["project"]["dynamic"], ["version"])
        self.assertEqual(self.project["tool"]["setuptools"]["dynamic"]["version"]["file"], "VERSION")
        self.assertEqual(self.project["project"]["requires-python"], ">=3.11")
        self.assertEqual(
            Version((ROOT / "VERSION").read_text(encoding="utf-8").strip()),
            Version("1.1.1"),
        )

    def test_package_discovery_is_explicitly_allowlisted(self):
        package_find = self.project["tool"]["setuptools"]["packages"]["find"]
        self.assertEqual(package_find["where"], ["src", "."])
        self.assertEqual(
            package_find["include"],
            ["narrowcti*", "connectors*", "core*", "exporters*", "gateway*"],
        )
        self.assertEqual(
            package_find["exclude"],
            ["tests*", "docs*", "scripts*", "deployment*", "state*"],
        )
        self.assertTrue(package_find["namespaces"])

    def test_runtime_dependencies_are_explicit_and_legacy_projection_matches(self):
        self.assertNotIn("setuptools==82.0.1", self.dependencies)
        legacy = set()
        for line in (ROOT / "connectors" / "otx" / "requirements.txt").read_text(
            encoding="utf-8"
        ).splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if line.startswith("setuptools=="):
                continue
            self.assertRegex(line, r"^[A-Za-z0-9_.-]+==[^\s]+$")
            legacy.add(line)
        self.assertEqual(self.dependencies, legacy)

    def test_legacy_projection_is_not_used_as_dynamic_project_source(self):
        pyproject_text = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
        self.assertNotRegex(pyproject_text, r"requirements\.txt")


if __name__ == "__main__":
    unittest.main()
