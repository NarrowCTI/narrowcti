import os
import shutil
import subprocess
import tempfile
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
        self.assertIn("NARROWCTI_AUTH_DB: /app/auth/auth.db", web)
        self.assertIn("narrowcti-auth:/app/auth", web)
        self.assertIn("NARROWCTI_REVIEW_API_CREDENTIALS_FILE: /run/secrets/narrowcti-review-api-credentials.json", web)
        self.assertIn("/run/secrets/narrowcti-review-api-credentials.json:ro", web)
        self.assertIn('"127.0.0.1:${NARROWCTI_WEB_PUBLISHED_PORT:-8081}:8081"', web)
        self.assertIn("read_only: true", web)
        self.assertIn("cap_drop:", web)
        self.assertIn("- ALL", web)
        self.assertIn("no-new-privileges:true", web)
        self.assertNotIn("NARROWCTI_GATEWAY_ENV_FILE", web)

    def test_auth_volume_is_not_mounted_into_worker_and_has_one_shot_provisioning_role(self):
        source = BASE.read_text(encoding="utf-8")
        worker = source.split("  narrowcti-gateway:", 1)[1].split("  narrowcti-web:", 1)[0]
        self.assertNotIn("narrowcti-auth", worker)
        helper = source.split("  narrowcti-operator-auth:", 1)[1].split("  narrowcti-gateway-report:", 1)[0]
        self.assertIn("/app/auth/auth.db", helper)
        self.assertIn("narrowcti-auth:/app/auth", helper)
        self.assertIn("narrowcti-operator-auth", source)

    def test_web_env_example_contains_no_ingestion_credentials(self):
        source = (ROOT / "deployment" / "web.env.example").read_text(encoding="utf-8")
        configured_names = {
            line.split("=", 1)[0]
            for line in source.splitlines()
            if line and not line.startswith("#") and "=" in line
        }
        forbidden = {"OTX_API_KEY", "MISP_KEY", "MISP_URL", "OPENCTI_TOKEN"}
        self.assertTrue(forbidden.isdisjoint(configured_names))

    def test_provider_readiness_ops_uses_web_configuration_not_gateway_credentials(self):
        source = BASE.read_text(encoding="utf-8")
        service = source.split("  narrowcti-provider-readiness:", 1)[1].split("  narrowcti-operator-auth:", 1)[0]
        self.assertIn("NARROWCTI_WEB_ENV_FILE", service)
        self.assertIn("narrowcti.cli.provider_readiness", service)
        self.assertNotIn("NARROWCTI_GATEWAY_ENV_FILE", service)

    def test_provider_overlays_are_read_only_for_web_and_ops_readiness(self):
        for filename, target in (
            ("docker-compose.narrowcti-web-misp.yml", "/run/secrets/narrowcti-web-misp-key"),
            ("docker-compose.narrowcti-web-otx.yml", "/run/secrets/narrowcti-web-otx-key"),
        ):
            source = (ROOT / "deployment" / filename).read_text(encoding="utf-8")
            with self.subTest(filename=filename):
                self.assertEqual(2, source.count(target))
                self.assertEqual(2, source.count("read_only: true"))
                self.assertIn("narrowcti-web:", source)
                self.assertIn("narrowcti-provider-readiness:", source)

    def test_build_context_excludes_all_env_named_files(self):
        source = (ROOT / ".dockerignore").read_text(encoding="utf-8").splitlines()
        self.assertIn("*.env", source)
        self.assertIn(".env", source)
        self.assertIn(".env.*", source)

    def test_web_env_example_keeps_real_export_opt_in(self):
        from narrowcti.api.review.app import load_review_api_settings

        source = (ROOT / "deployment" / "web.env.example").read_text(encoding="utf-8")
        values = dict(
            line.split("=", 1)
            for line in source.splitlines()
            if line and not line.startswith("#") and "=" in line
        )
        self.assertEqual("false", values["NARROWCTI_REVIEW_API_ALLOW_EXPORT"])
        self.assertFalse(load_review_api_settings(values).allow_export)

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

    def test_compose_config_matrix_with_synthetic_provider_secret_files(self):
        if shutil.which("docker") is None:
            self.skipTest("Docker is not available")
        misp = ROOT / "deployment" / "docker-compose.narrowcti-web-misp.yml"
        otx = ROOT / "deployment" / "docker-compose.narrowcti-web-otx.yml"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            misp_key = root / "misp.key"
            otx_key = root / "otx.key"
            misp_key.write_text("synthetic-misp-read-only-key", encoding="utf-8")
            otx_key.write_text("synthetic-otx-key", encoding="utf-8")
            cases = (
                ("base", ["-f", str(BASE)]),
                ("shared", ["-f", str(BASE), "-f", str(SHARED)]),
                ("misp", ["-f", str(BASE), "-f", str(misp)]),
                ("otx", ["-f", str(BASE), "-f", str(otx)]),
                ("both", ["-f", str(BASE), "-f", str(misp), "-f", str(otx)]),
                ("shared+binaries", ["-f", str(BASE), "-f", str(SHARED), "-f", str(misp), "-f", str(otx)]),
            )
            env = {
                **os.environ,
                "NARROWCTI_DOCKER_NETWORK": "threat-net",
                "NARROWCTI_WEB_MISP_KEY_SOURCE": str(misp_key),
                "NARROWCTI_WEB_OTX_KEY_SOURCE": str(otx_key),
            }
            for label, layers in cases:
                with self.subTest(layers=label):
                    result = subprocess.run(
                        ["docker", "compose", *layers, "--profile", "web", "--profile", "ops", "config"],
                        cwd=ROOT / "deployment",
                        env=env,
                        capture_output=True,
                        text=True,
                        check=False,
                    )
                    self.assertEqual(0, result.returncode, result.stderr)
                    self.assertNotIn("synthetic-misp-read-only-key", result.stdout)
                    self.assertNotIn("synthetic-otx-key", result.stdout)


if __name__ == "__main__":
    unittest.main()
