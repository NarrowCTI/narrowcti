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
ALLOWED_PREFIXES = ("narrowcti/", "connectors/", "core/", "exporters/", "gateway/")
REMOVED_PREFIXES = (
    "narrowcti/core/",
    "narrowcti/connectors/",
    "narrowcti/exporters/",
    "narrowcti/gateway/",
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
SOURCE_PACKAGE_ROOTS = (
    ("src/narrowcti", "narrowcti"),
    ("connectors", "connectors"),
    ("core", "core"),
    ("exporters", "exporters"),
    ("gateway", "gateway"),
)


def expected_runtime_modules(root: Path = ROOT) -> set[str]:
    """Derive every runtime Python file that the wheel must contain."""

    expected: set[str] = set()
    for source_root_name, archive_root in SOURCE_PACKAGE_ROOTS:
        source_root = root / Path(source_root_name)
        if not source_root.exists():
            continue
        for path in source_root.rglob("*.py"):
            relative = path.relative_to(source_root)
            archive_name = (Path(archive_root) / relative).as_posix()
            if archive_name == "narrowcti/compat.py" or archive_name.startswith(REMOVED_PREFIXES):
                continue
            expected.add(archive_name)
    return expected


def wheel_runtime_modules(names: list[str] | set[str]) -> set[str]:
    return {
        name
        for name in names
        if name.endswith(".py") and name.startswith(ALLOWED_PREFIXES)
    }


def assert_runtime_inventory(names: list[str] | set[str], root: Path = ROOT) -> None:
    expected = expected_runtime_modules(root)
    actual = wheel_runtime_modules(names)
    missing = sorted(expected - actual)
    unexpected = sorted(actual - expected)
    if missing or unexpected:
        raise AssertionError(
            "wheel runtime inventory differs from source inventory: "
            f"missing={missing}, unexpected={unexpected}"
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
        run(sys.executable, "-m", "pip", "wheel", "--no-deps", "--wheel-dir", str(wheel_dir), str(ROOT), cwd=ROOT, env=pip_env)

        wheels = sorted(wheel_dir.glob("narrowcti-*.whl"))
        if len(wheels) != 1:
            raise AssertionError(f"expected one NarrowCTI wheel, found {wheels}")
        wheel = wheels[0]
        with zipfile.ZipFile(wheel) as archive:
            names = [name for name in archive.namelist() if not name.endswith("/")]
        missing = [prefix for prefix in ALLOWED_PREFIXES if not any(name.startswith(prefix) for name in names)]
        if missing:
            raise AssertionError(f"wheel is missing allowlisted runtime packages: {missing}")
        assert_runtime_inventory(names)
        forbidden = [name for name in names if name.startswith(FORBIDDEN_PREFIXES)]
        if forbidden:
            raise AssertionError(f"wheel contains forbidden paths: {forbidden}")
        removed = [name for name in names if name.startswith(REMOVED_PREFIXES)]
        if removed:
            raise AssertionError(f"wheel contains removed nested compatibility packages: {removed}")

        venv_dir = temp / "venv"
        venv.EnvBuilder(with_pip=True, clear=True).create(venv_dir)
        python = venv_dir / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
        run(str(python), "-m", "pip", "install", "--disable-pip-version-check", str(wheel), cwd=temp, env=pip_env)

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
        checks = """
import importlib
from pathlib import Path

import core.feed_contract as legacy_feed
import core.scoring as legacy_scoring
import core.quarantine as legacy_quarantine
import connectors.misp.feed_adapter as legacy_misp
import exporters.stix_builder as legacy_stix
import gateway.connector as legacy_gateway
from narrowcti.domain.intelligence import feed_contract, scoring
from narrowcti.domain.review import quarantine
from narrowcti.adapters.stix import serializer

assert legacy_feed.FeedSource is feed_contract.FeedSource
assert legacy_feed.FeedCandidate is feed_contract.FeedCandidate
assert legacy_feed.slugify is feed_contract.slugify
assert legacy_scoring.calculate_score is scoring.calculate_score
assert legacy_quarantine.QuarantineRecord is quarantine.QuarantineRecord
assert legacy_quarantine.QuarantineRepository is importlib.import_module(
    "narrowcti.adapters.persistence.local.quarantine_repository"
).QuarantineRepository
assert legacy_misp.MISPFeedAdapter is not None
assert legacy_stix.build_report_bundle is serializer.build_report_bundle
assert legacy_gateway.main is not None
for removed in (
    "narrowcti.core.feed_contract",
    "narrowcti.connectors.misp.feed_adapter",
    "narrowcti.exporters.stix_builder",
    "narrowcti.gateway.connector",
):
    try:
        importlib.import_module(removed)
    except ModuleNotFoundError:
        pass
    else:
        raise AssertionError(f"removed nested facade remains importable: {removed}")
print("installed-compatibility-cutover-ok")
"""
        run(str(python), "-c", checks, cwd=temp, env=child_env)
        print(f"wheel-validation-ok version={installed_version} wheel={wheel.name}")


if __name__ == "__main__":
    main()
