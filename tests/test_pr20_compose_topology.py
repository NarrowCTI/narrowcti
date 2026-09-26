import os
import shutil
import subprocess
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
BASE = ROOT / "deployment" / "docker-compose.narrowcti-gateway.yml"
SHARED = ROOT / "deployment" / "docker-compose.narrowcti-shared-network.yml"


class ComposeTopologyContractTests(unittest.TestCase):
    def test_base_is_not_bound_to_external_opencti_network(self):
        source = BASE.read_text(encoding="utf-8")
        self.assertNotIn("PYTHONPATH", source)
        self.assertNotIn("external: true", source)
        self.assertNotIn("NARROWCTI_DOCKER_NETWORK", source)

    def test_shared_override_preserves_default_and_external_networks(self):
        source = SHARED.read_text(encoding="utf-8")
        self.assertIn("[default, opencti]", source)
        self.assertIn("external: true", source)
        self.assertIn("NARROWCTI_DOCKER_NETWORK", source)
        self.assertNotIn("elasticsearch", source.lower())
        self.assertNotIn("rabbitmq", source.lower())
        self.assertNotIn("postgres", source.lower())
        self.assertNotIn("redis", source.lower())

    def test_compose_config_renders_both_modes_when_docker_is_available(self):
        if shutil.which("docker") is None:
            self.skipTest("Docker is not available")
        for command in (
            ["docker", "compose", "-f", str(BASE), "config"],
            ["docker", "compose", "-f", str(BASE), "-f", str(SHARED), "config"],
        ):
            result = subprocess.run(
                command,
                cwd=ROOT,
                env={**os.environ, "NARROWCTI_DOCKER_NETWORK": "threat-net"},
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(0, result.returncode, result.stderr)


if __name__ == "__main__":
    unittest.main()
