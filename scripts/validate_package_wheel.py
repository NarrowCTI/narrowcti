"""Build and exercise a real NarrowCTI wheel outside the source checkout."""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import venv
import zipfile
from pathlib import Path

from packaging.version import Version


ROOT = Path(__file__).resolve().parents[1]
ALLOWED_PREFIXES = (
    "narrowcti/",
    "connectors/",
    "core/",
    "exporters/",
    "gateway/",
)
FORBIDDEN_PREFIXES = (
    "src/",
    "src.narrowcti/",
    "tests/",
    "docs/",
    "scripts/",
    "deployment/",
    "state/",
)


def run(*args: str, cwd: Path, env: dict[str, str] | None = None) -> None:
    subprocess.run(args, cwd=cwd, env=env, check=True)


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="narrowcti-wheel-") as temp_dir:
        temp = Path(temp_dir)
        wheel_dir = temp / "wheel"
        wheel_dir.mkdir()
        pip_env = os.environ.copy()
        pip_env["PIP_CACHE_DIR"] = str(temp / "pip-cache")
        run(
            sys.executable,
            "-m",
            "pip",
            "wheel",
            "--no-deps",
            "--wheel-dir",
            str(wheel_dir),
            str(ROOT),
            cwd=ROOT,
            env=pip_env,
        )

        wheels = sorted(wheel_dir.glob("narrowcti-*.whl"))
        if len(wheels) != 1:
            raise AssertionError(f"expected one NarrowCTI wheel, found {wheels}")
        wheel = wheels[0]
        with zipfile.ZipFile(wheel) as archive:
            names = [name for name in archive.namelist() if not name.endswith("/")]
        missing = [prefix for prefix in ALLOWED_PREFIXES if not any(name.startswith(prefix) for name in names)]
        if missing:
            raise AssertionError(f"wheel is missing allowlisted runtime packages: {missing}")
        forbidden = [name for name in names if name.startswith(FORBIDDEN_PREFIXES)]
        if forbidden:
            raise AssertionError(f"wheel contains forbidden paths: {forbidden}")

        venv_dir = temp / "venv"
        venv.EnvBuilder(with_pip=True, clear=True).create(venv_dir)
        python = venv_dir / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
        run(
            str(python),
            "-m",
            "pip",
            "install",
            "--disable-pip-version-check",
            str(wheel),
            cwd=temp,
            env=pip_env,
        )

        source_version = Version((ROOT / "VERSION").read_text(encoding="utf-8").strip())
        version_result = subprocess.run(
            [str(python), "-c", "import importlib.metadata; print(importlib.metadata.version('narrowcti'))"],
            cwd=temp,
            check=True,
            capture_output=True,
            text=True,
        )
        installed_version = Version(version_result.stdout.strip())
        if installed_version != source_version:
            raise AssertionError(f"version mismatch: {installed_version} != {source_version}")

        child_env = os.environ.copy()
        child_env.pop("PYTHONPATH", None)
        compatibility_checks = (
            """
import sys
import connectors.misp.feed_adapter as legacy_connectors
import core.feed_contract as legacy_core
import exporters.stix_builder as legacy_exporters
import gateway.settings as legacy_gateway
import narrowcti.connectors.misp.feed_adapter as canonical_connectors
import narrowcti.core.feed_contract as canonical_core
import narrowcti.exporters.stix_builder as canonical_exporters
import narrowcti.gateway.settings as canonical_gateway
import narrowcti.domain.intelligence.feed_contract as domain_feed
assert sys.modules["connectors.misp.feed_adapter"] is sys.modules["narrowcti.connectors.misp.feed_adapter"]
assert sys.modules["core.feed_contract"] is sys.modules["narrowcti.core.feed_contract"]
assert sys.modules["exporters.stix_builder"] is sys.modules["narrowcti.exporters.stix_builder"]
assert sys.modules["gateway.settings"] is sys.modules["narrowcti.gateway.settings"]
assert legacy_connectors is canonical_connectors
assert legacy_core is canonical_core
assert legacy_core.FeedSource is domain_feed.FeedSource
assert legacy_core.FeedCandidate is domain_feed.FeedCandidate
assert legacy_core.slugify is domain_feed.slugify
assert legacy_exporters is canonical_exporters
assert legacy_gateway is canonical_gateway
print("installed-compatibility-legacy-first-ok")
""",
            """
import sys
import narrowcti.connectors.misp.feed_adapter as canonical_connectors
import narrowcti.core.feed_contract as canonical_core
import narrowcti.exporters.stix_builder as canonical_exporters
import narrowcti.gateway.settings as canonical_gateway
import narrowcti.domain.intelligence.feed_contract as domain_feed
import connectors.misp.feed_adapter as legacy_connectors
import core.feed_contract as legacy_core
import exporters.stix_builder as legacy_exporters
import gateway.settings as legacy_gateway
assert sys.modules["core.feed_contract"] is sys.modules["narrowcti.core.feed_contract"]
assert sys.modules["connectors.misp.feed_adapter"] is sys.modules["narrowcti.connectors.misp.feed_adapter"]
assert sys.modules["exporters.stix_builder"] is sys.modules["narrowcti.exporters.stix_builder"]
assert sys.modules["gateway.settings"] is sys.modules["narrowcti.gateway.settings"]
assert canonical_connectors is legacy_connectors
assert canonical_core is legacy_core
assert legacy_core.FeedSource is domain_feed.FeedSource
assert legacy_core.FeedCandidate is domain_feed.FeedCandidate
assert legacy_core.slugify is domain_feed.slugify
assert canonical_exporters is legacy_exporters
assert canonical_gateway is legacy_gateway
print("installed-compatibility-canonical-first-ok")
""",
        )
        for import_code in compatibility_checks:
            run(str(python), "-c", import_code, cwd=temp, env=child_env)
        print(f"wheel-validation-ok version={installed_version} wheel={wheel.name}")


if __name__ == "__main__":
    main()
