"""Build and exercise a real NarrowCTI wheel outside the source checkout."""

from __future__ import annotations

import os
import hashlib
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


def assert_brand_asset_projection(archive: zipfile.ZipFile, root: Path = ROOT) -> None:
    """Require every canonical brand asset in the wheel with byte-identical content."""

    brand_source = root / "docs" / "assets" / "brand"
    source_files = {
        path.relative_to(brand_source).as_posix(): path.read_bytes()
        for path in brand_source.rglob("*")
        if path.is_file()
    }
    archive_prefix = "narrowcti/api/web/static/brand/"
    wheel_files = {
        name.removeprefix(archive_prefix): name
        for name in archive.namelist()
        if name.startswith(archive_prefix) and not name.endswith("/")
    }
    missing = sorted(set(source_files) - set(wheel_files))
    unexpected = sorted(set(wheel_files) - set(source_files))
    if missing or unexpected:
        raise AssertionError(
            "wheel brand asset inventory differs from canonical assets: "
            f"missing={missing}, unexpected={unexpected}"
        )
    for relative, source_bytes in source_files.items():
        wheel_bytes = archive.read(wheel_files[relative])
        source_hash = hashlib.sha256(source_bytes).hexdigest()
        wheel_hash = hashlib.sha256(wheel_bytes).hexdigest()
        if wheel_hash != source_hash:
            raise AssertionError(f"brand asset hash mismatch for {relative}")


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
            assert_brand_asset_projection(archive)
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
from importlib.resources import files
from pathlib import Path

import core.feed_contract as legacy_feed
import core.scoring as legacy_scoring
import core.quarantine as legacy_quarantine
import connectors.misp.feed_adapter as legacy_misp
import exporters.stix_builder as legacy_stix
import gateway.connector as legacy_gateway
import gateway.review_api as legacy_review_api
import gateway.preflight as legacy_preflight
from narrowcti.application.runtime_roles import OPS, WEB, WORKER
from narrowcti.cli import web as web_role
from narrowcti.cli import worker as worker_role
from narrowcti.domain.intelligence import feed_contract, scoring
from narrowcti.domain.review import quarantine
from narrowcti.adapters.stix import serializer
from narrowcti.api.web import app as web_app
from narrowcti.infrastructure.config.web_settings import WebSettings
from narrowcti.adapters.persistence.local.operator_store import LocalOperatorStore
from narrowcti.application.identity.passwords import PasswordService
from narrowcti.cli import auth as auth_cli
from narrowcti.domain.security.identity import LocalOperatorPrincipal

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
assert legacy_review_api.main is not None
assert legacy_preflight.build_preflight_report is not None
assert {OPS, WEB, WORKER} == {"ops", "web", "worker"}
assert callable(web_role.main)
assert callable(worker_role.main)
assert callable(auth_cli.main)
assert LocalOperatorStore is not None
assert PasswordService is not None
assert LocalOperatorPrincipal is not None
web_package = files("narrowcti.api.web")
for resource in (
    "templates/base.html",
    "templates/login.html",
    "templates/account.html",
    "templates/evidence.html",
    "templates/community_sources.html",
    "templates/decisions.html",
    "templates/operational_evidence.html",
    "templates/validation.html",
    "templates/system_health.html",
    "templates/system_providers.html",
    "templates/system_capabilities.html",
    "templates/error.html",
    "templates/sources.html",
    "templates/search_results.html",
    "templates/source_detail.html",
    "templates/review.html",
    "templates/review_result.html",
    "templates/home.html",
    "templates/job_status.html",
    "templates/job_status_fragment.html",
    "templates/reports.html",
    "static/app.css",
    "static/htmx.min.js",
    "static/brand/logo/narrowcti-logo-horizontal-dark.svg",
    "static/brand/symbol/narrowcti-symbol-gradient.svg",
    "static/brand/favicon/narrowcti-favicon.ico",
):
    assert web_package.joinpath(*resource.split("/")).is_file(), resource
assert callable(web_app.create_web_app)
assert WebSettings().cookie_secure is True
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
