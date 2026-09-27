import os
import shutil
import subprocess
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
BASE = ROOT / "deployment" / "docker-compose.narrowcti-gateway.yml"
SHARED = ROOT / "deployment" / "docker-compose.narrowcti-shared-network.yml"


class ComposeTopologyContractTests(unittest.TestCase):
    def test_canonical_web_role_is_scoped_and_authenticated(self):
        source = BASE.read_text(encoding="utf-8")
        web = source.split("  narrowcti-web:", 1)[1].split("  narrowcti-preflight:", 1)[0]
        self.assertIn("NARROWCTI_WEB_ENV_FILE", web)
        self.assertIn("NARROWCTI_RUNTIME_DB: /app/state/runtime.db", web)
        self.assertIn("NARROWCTI_REVIEW_API_CREDENTIALS_FILE: /run/secrets/narrowcti-review-api-credentials.json", web)
        self.assertIn("/run/secrets/narrowcti-review-api-credentials.json:ro", web)
        self.assertIn('"127.0.0.1:${NARROWCTI_WEB_PUBLISHED_PORT:-8081}:8081"', web)
        self.assertIn("read_only: true", web)
        self.assertIn("cap_drop:", web)
        self.assertIn("- ALL", web)
        self.assertIn("no-new-privileges:true", web)
        self.assertNotIn("NARROWCTI_GATEWAY_ENV_FILE", web)

    def test_web_env_example_contains_no_ingestion_credentials(self):
        source = (ROOT / "deployment" / "web.env.example").read_text(encoding="utf-8")
        for secret in ("OTX_API_KEY", "MISP_KEY", "MISP_URL", "OPENCTI_TOKEN"):
            self.assertNotIn(secret, source)

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
