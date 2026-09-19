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
REQUIRED_MODULES = (
    "narrowcti/ports/storage.py",
    "narrowcti/ports/graph.py",
    "narrowcti/adapters/persistence/local/atomic_io.py",
    "narrowcti/adapters/persistence/local/state_repository.py",
    "narrowcti/adapters/persistence/local/artifact_index.py",
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
        missing_modules = [module for module in REQUIRED_MODULES if module not in names]
        if missing_modules:
            raise AssertionError(f"wheel is missing PR-06 modules: {missing_modules}")
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
import tempfile
from pathlib import Path
import connectors.misp.feed_adapter as legacy_connectors
import core.atomic_io as legacy_atomic
import core.feed_contract as legacy_core
import core.scoring as legacy_scoring
import core.contextual_scoring as legacy_contextual
import core.tlp as legacy_tlp
import core.policy as legacy_policy
import core.deduplication as legacy_dedup
import core.indicator_policy as legacy_indicator_policy
import core.state_repository as legacy_state
import core.graph_deduplication as legacy_graph
import exporters.stix_builder as legacy_exporters
import gateway.settings as legacy_gateway
import narrowcti.connectors.misp.feed_adapter as canonical_connectors
import narrowcti.core.feed_contract as canonical_core
import narrowcti.exporters.stix_builder as canonical_exporters
import narrowcti.gateway.settings as canonical_gateway
import narrowcti.domain.intelligence.feed_contract as domain_feed
import narrowcti.domain.intelligence.scoring as domain_scoring
import narrowcti.domain.intelligence.contextual_scoring as domain_contextual
import narrowcti.domain.intelligence.tlp as domain_tlp
import narrowcti.domain.intelligence.policy as domain_policy
import narrowcti.domain.intelligence.indicator_types as domain_indicator_types
import narrowcti.domain.intelligence.indicator_policy as domain_indicator_policy
import narrowcti.ports.storage as canonical_storage
import narrowcti.ports.graph as canonical_graph
import narrowcti.adapters.persistence.local.atomic_io as canonical_atomic
import narrowcti.adapters.persistence.local.state_repository as canonical_state
import narrowcti.adapters.persistence.local.artifact_index as canonical_artifacts
assert sys.modules["connectors.misp.feed_adapter"] is sys.modules["narrowcti.connectors.misp.feed_adapter"]
assert sys.modules["core.feed_contract"] is sys.modules["narrowcti.core.feed_contract"]
assert sys.modules["exporters.stix_builder"] is sys.modules["narrowcti.exporters.stix_builder"]
assert sys.modules["gateway.settings"] is sys.modules["narrowcti.gateway.settings"]
assert legacy_connectors is canonical_connectors
assert legacy_core is canonical_core
assert legacy_core.FeedSource is domain_feed.FeedSource
assert legacy_core.FeedCandidate is domain_feed.FeedCandidate
assert legacy_core.slugify is domain_feed.slugify
assert legacy_scoring.calculate_score is domain_scoring.calculate_score
assert legacy_contextual.build_contextual_score_evidence is domain_contextual.build_contextual_score_evidence
assert legacy_tlp.normalize_tlp is domain_tlp.normalize_tlp
assert legacy_policy.should_ingest is domain_policy.should_ingest
assert legacy_dedup.normalize_indicator_type is domain_indicator_types.normalize_indicator_type
assert legacy_indicator_policy.filter_indicators_by_type is domain_indicator_policy.filter_indicators_by_type
assert legacy_exporters is canonical_exporters
assert legacy_gateway is canonical_gateway
assert legacy_atomic.write_json_atomic is canonical_atomic.write_json_atomic
assert legacy_state.ProcessedItemStateRepository is canonical_state.ProcessedItemStateRepository
assert legacy_state.PulseStateRepository is canonical_state.PulseStateRepository
assert legacy_state.MISPEventStateRepository is canonical_state.MISPEventStateRepository
assert legacy_dedup.ArtifactDeduplicationIndex is canonical_artifacts.ArtifactDeduplicationIndex
with tempfile.TemporaryDirectory() as tmpdir:
    graph_index = legacy_graph.GraphDeduplicationIndex(str(Path(tmpdir) / "graph.json"))
    assert isinstance(graph_index, canonical_graph.GraphIndex)
print("installed-compatibility-legacy-first-ok")
""",
            """
import sys
import tempfile
from pathlib import Path
import narrowcti.connectors.misp.feed_adapter as canonical_connectors
import narrowcti.adapters.persistence.local.atomic_io as canonical_atomic
import narrowcti.adapters.persistence.local.state_repository as canonical_state
import narrowcti.adapters.persistence.local.artifact_index as canonical_artifacts
import narrowcti.ports.storage as canonical_storage
import narrowcti.ports.graph as canonical_graph
import narrowcti.core.feed_contract as canonical_core
import narrowcti.exporters.stix_builder as canonical_exporters
import narrowcti.gateway.settings as canonical_gateway
import narrowcti.domain.intelligence.feed_contract as domain_feed
import narrowcti.domain.intelligence.scoring as domain_scoring
import narrowcti.domain.intelligence.contextual_scoring as domain_contextual
import narrowcti.domain.intelligence.tlp as domain_tlp
import narrowcti.domain.intelligence.policy as domain_policy
import narrowcti.domain.intelligence.indicator_types as domain_indicator_types
import narrowcti.domain.intelligence.indicator_policy as domain_indicator_policy
import connectors.misp.feed_adapter as legacy_connectors
import core.feed_contract as legacy_core
import core.scoring as legacy_scoring
import core.contextual_scoring as legacy_contextual
import core.tlp as legacy_tlp
import core.policy as legacy_policy
import core.deduplication as legacy_dedup
import core.indicator_policy as legacy_indicator_policy
import core.atomic_io as legacy_atomic
import core.state_repository as legacy_state
import core.graph_deduplication as legacy_graph
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
assert legacy_scoring.calculate_score is domain_scoring.calculate_score
assert legacy_contextual.build_contextual_score_evidence is domain_contextual.build_contextual_score_evidence
assert legacy_tlp.normalize_tlp is domain_tlp.normalize_tlp
assert legacy_policy.should_ingest is domain_policy.should_ingest
assert legacy_dedup.normalize_indicator_type is domain_indicator_types.normalize_indicator_type
assert legacy_indicator_policy.filter_indicators_by_type is domain_indicator_policy.filter_indicators_by_type
assert canonical_exporters is legacy_exporters
assert canonical_gateway is legacy_gateway
assert legacy_atomic.write_json_atomic is canonical_atomic.write_json_atomic
assert legacy_state.ProcessedItemStateRepository is canonical_state.ProcessedItemStateRepository
assert legacy_state.PulseStateRepository is canonical_state.PulseStateRepository
assert legacy_state.MISPEventStateRepository is canonical_state.MISPEventStateRepository
assert legacy_dedup.ArtifactDeduplicationIndex is canonical_artifacts.ArtifactDeduplicationIndex
with tempfile.TemporaryDirectory() as tmpdir:
    graph_index = legacy_graph.GraphDeduplicationIndex(str(Path(tmpdir) / "graph.json"))
    assert isinstance(graph_index, canonical_graph.GraphIndex)
print("installed-compatibility-canonical-first-ok")
""",
        )
        for import_code in compatibility_checks:
            run(str(python), "-c", import_code, cwd=temp, env=child_env)
        print(f"wheel-validation-ok version={installed_version} wheel={wheel.name}")


if __name__ == "__main__":
    main()
