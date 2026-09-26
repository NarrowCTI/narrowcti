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
    "narrowcti/ports/graph_index.py",
    "narrowcti/adapters/persistence/local/atomic_io.py",
    "narrowcti/adapters/persistence/local/state_repository.py",
    "narrowcti/adapters/persistence/local/artifact_index.py",
    "narrowcti/domain/review/__init__.py",
    "narrowcti/domain/review/quarantine.py",
    "narrowcti/domain/detection/__init__.py",
    "narrowcti/domain/detection/_normalization.py",
    "narrowcti/domain/detection/requirements.py",
    "narrowcti/domain/detection/telemetry.py",
    "narrowcti/domain/detection/artifacts.py",
    "narrowcti/domain/detection/lifecycle.py",
    "narrowcti/domain/validation/__init__.py",
    "narrowcti/domain/validation/contracts.py",
    "narrowcti/domain/validation/evidence.py",
    "narrowcti/ports/quarantine.py",
    "narrowcti/ports/entitlements.py",
    "narrowcti/adapters/persistence/local/quarantine_repository.py",
    "narrowcti/application/__init__.py",
    "narrowcti/application/capabilities.py",
    "narrowcti/application/preflight.py",
    "narrowcti/application/reporting/__init__.py",
    "narrowcti/application/reporting/operational.py",
    "narrowcti/application/reporting/correlation.py",
    "narrowcti/application/reporting/decisions.py",
    "narrowcti/application/reporting/curation.py",
    "narrowcti/application/assurance/__init__.py",
    "narrowcti/application/assurance/opencti_relationship_audit.py",
    "narrowcti/application/assurance/operational_validation.py",
    "narrowcti/application/validation/__init__.py",
    "narrowcti/application/validation/opencti_client.py",
    "narrowcti/application/support/__init__.py",
    "narrowcti/application/support/diagnostics.py",
    "narrowcti/application/ingestion/__init__.py",
    "narrowcti/application/ingestion/pipeline.py",
    "narrowcti/application/ingestion/outcomes.py",
    "narrowcti/application/ingestion/contracts.py",
    "narrowcti/application/review/__init__.py",
    "narrowcti/application/review/service.py",
    "narrowcti/application/review/export.py",
    "narrowcti/api/__init__.py",
    "narrowcti/api/review/__init__.py",
    "narrowcti/api/review/app.py",
    "narrowcti/api/review/auth.py",
    "narrowcti/adapters/sources/__init__.py",
    "narrowcti/adapters/sources/misp/__init__.py",
    "narrowcti/adapters/sources/misp/context.py",
    "narrowcti/adapters/sources/misp/entities.py",
    "narrowcti/adapters/sources/misp/infrastructure.py",
    "narrowcti/adapters/sources/misp/detection_rules.py",
    "narrowcti/adapters/sources/misp/_common.py",
    "narrowcti/domain/graph/__init__.py",
    "narrowcti/domain/graph/deduplication.py",
    "narrowcti/domain/graph/evidence/__init__.py",
    "narrowcti/domain/graph/evidence/aggregate.py",
    "narrowcti/domain/graph/evidence/common.py",
    "narrowcti/domain/graph/evidence/misp_contracts.py",
    "narrowcti/domain/graph/evidence/otx.py",
    "narrowcti/domain/graph/evidence/mitre.py",
    "narrowcti/domain/graph/evidence/misp_metadata.py",
    "narrowcti/domain/graph/evidence/misp_galaxy.py",
    "narrowcti/domain/graph/evidence/misp_operational.py",
    "narrowcti/domain/graph/evidence/misp_detection.py",
    "narrowcti/domain/graph/evidence/misp_relationships.py",
    "narrowcti/adapters/opencti/__init__.py",
    "narrowcti/adapters/opencti/graph_lookup.py",
    "narrowcti/adapters/opencti/deduplication.py",
    "narrowcti/adapters/opencti/graph_serializer.py",
    "narrowcti/adapters/opencti/exporter.py",
    "narrowcti/adapters/opencti/stix_profile.py",
    "narrowcti/adapters/stix/__init__.py",
    "narrowcti/adapters/stix/patterns.py",
    "narrowcti/adapters/stix/identifiers.py",
    "narrowcti/adapters/stix/serializer.py",
    "narrowcti/application/compiler/__init__.py",
    "narrowcti/application/compiler/contracts.py",
    "narrowcti/application/compiler/graph.py",
    "narrowcti/application/provider_registry.py",
    "narrowcti/application/runtime.py",
    "narrowcti/infrastructure/__init__.py",
    "narrowcti/infrastructure/config/__init__.py",
    "narrowcti/infrastructure/config/settings.py",
    "narrowcti/infrastructure/capabilities.py",
    "narrowcti/infrastructure/runtime/__init__.py",
    "narrowcti/infrastructure/runtime/gateway_composition.py",
    "narrowcti/infrastructure/runtime/summary_store.py",
    "narrowcti/adapters/opencti/client.py",
    "narrowcti/adapters/entitlements/__init__.py",
    "narrowcti/adapters/entitlements/community.py",
    "narrowcti/cli/__init__.py",
    "narrowcti/cli/gateway.py",
    "narrowcti/cli/quarantine.py",
    "narrowcti/adapters/persistence/local/review_audit.py",
    "narrowcti/adapters/persistence/local/decision_audit_reader.py",
    "narrowcti/adapters/persistence/local/support_bundle.py",
    "narrowcti/adapters/opencti/relationship_audit.py",
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
            raise AssertionError(f"wheel is missing required persistence/quarantine modules: {missing_modules}")
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
import core.graph_evidence as legacy_graph_evidence
import core.quarantine as legacy_quarantine
import exporters.stix_builder as legacy_exporters
import gateway.settings as legacy_gateway
import gateway.runtime as legacy_gateway_runtime
import gateway.sources as legacy_gateway_sources
import gateway.connector as legacy_gateway_connector
import gateway.opencti_client as legacy_opencti_client
import narrowcti.connectors.misp.feed_adapter as canonical_connectors
import narrowcti.core.feed_contract as canonical_core
import narrowcti.exporters.stix_builder as canonical_exporters
import narrowcti.gateway.settings as canonical_gateway
import narrowcti.gateway.runtime as canonical_gateway_runtime
import narrowcti.gateway.sources as canonical_gateway_sources
import narrowcti.gateway.connector as canonical_gateway_connector
import narrowcti.gateway.opencti_client as canonical_opencti_client
import narrowcti.application.provider_registry as canonical_provider_registry
import narrowcti.application.runtime as canonical_runtime
import narrowcti.infrastructure.config.settings as canonical_settings
import narrowcti.infrastructure.runtime.gateway_composition as canonical_composition
import narrowcti.cli.gateway as canonical_cli_gateway
import narrowcti.adapters.opencti.client as canonical_opencti_client_adapter
import narrowcti.domain.intelligence.feed_contract as domain_feed
import narrowcti.domain.intelligence.scoring as domain_scoring
import narrowcti.domain.intelligence.contextual_scoring as domain_contextual
import narrowcti.domain.intelligence.tlp as domain_tlp
import narrowcti.domain.intelligence.policy as domain_policy
import narrowcti.domain.intelligence.indicator_types as domain_indicator_types
import narrowcti.domain.intelligence.indicator_policy as domain_indicator_policy
import narrowcti.ports.storage as canonical_storage
import narrowcti.ports.graph as canonical_graph
import narrowcti.ports.graph_index as canonical_graph_index
import narrowcti.adapters.persistence.local.atomic_io as canonical_atomic
import narrowcti.adapters.persistence.local.state_repository as canonical_state
import narrowcti.adapters.persistence.local.artifact_index as canonical_artifacts
import narrowcti.adapters.persistence.local.quarantine_repository as canonical_quarantine_repository
import narrowcti.ports.quarantine as canonical_quarantine_port
import narrowcti.core.quarantine as canonical_quarantine
import narrowcti.domain.review.quarantine as domain_quarantine
import narrowcti.domain.graph.evidence as domain_graph_evidence
import narrowcti.domain.graph.deduplication as domain_graph_deduplication
import narrowcti.adapters.opencti.graph_lookup as canonical_opencti_graph
import narrowcti.adapters.opencti.deduplication as canonical_opencti_dedup
import narrowcti.adapters.opencti.graph_serializer as canonical_graph_serializer
import narrowcti.adapters.opencti.exporter as canonical_opencti_exporter
import narrowcti.adapters.opencti.stix_profile as canonical_opencti_profile
import narrowcti.adapters.stix as canonical_stix
import narrowcti.adapters.stix.patterns as canonical_stix_patterns
import narrowcti.adapters.stix.identifiers as canonical_stix_identifiers
import narrowcti.adapters.stix.serializer as canonical_stix_serializer
import narrowcti.application.compiler as canonical_compiler
import narrowcti.application.compiler.contracts as compiler_contracts
import narrowcti.application.compiler.graph as compiler_graph
import core.opencti_graph_lookup as legacy_opencti_graph
import core.opencti_deduplication as legacy_opencti_dedup
import narrowcti.application as application
import narrowcti.application.preflight as canonical_preflight
import narrowcti.application.reporting.operational as canonical_reporting_operational
import narrowcti.application.reporting.correlation as canonical_reporting_correlation
import narrowcti.application.reporting.decisions as canonical_reporting_decisions
import narrowcti.application.reporting.curation as canonical_reporting_curation
import narrowcti.application.assurance.opencti_relationship_audit as canonical_relationship_assurance
import narrowcti.application.assurance.operational_validation as canonical_operational_assurance
import narrowcti.application.validation.opencti_client as canonical_validation
import narrowcti.application.support.diagnostics as canonical_support
import narrowcti.adapters.opencti.relationship_audit as canonical_relationship_adapter
import narrowcti.adapters.persistence.local.decision_audit_reader as canonical_decision_reader
import narrowcti.adapters.persistence.local.support_bundle as canonical_support_bundle
import narrowcti.application.ingestion as ingestion
import narrowcti.application.ingestion.pipeline as ingestion_pipeline
import narrowcti.application.ingestion.outcomes as ingestion_outcomes
import narrowcti.application.ingestion.contracts as ingestion_contracts
import narrowcti.adapters.sources as canonical_sources
import narrowcti.adapters.sources.misp as canonical_misp
import narrowcti.adapters.sources.misp.context as canonical_misp_context
import narrowcti.adapters.sources.misp.entities as canonical_misp_entities
import narrowcti.adapters.sources.misp.infrastructure as canonical_misp_infrastructure
import narrowcti.adapters.sources.misp.detection_rules as canonical_misp_detection_rules
import connectors.misp.processor as legacy_misp_processor
import narrowcti.application.review.service as canonical_review_service
import narrowcti.application.review.export as canonical_review_export
import narrowcti.api.review.app as canonical_review_api
import narrowcti.api.review.auth as canonical_review_auth
import narrowcti.cli.quarantine as canonical_review_cli
import narrowcti.adapters.persistence.local.review_audit as canonical_review_audit
import gateway.review as legacy_review
import gateway.quarantine_export as legacy_review_export
import gateway.review_api as legacy_review_api
import gateway.review_auth as legacy_review_auth
import gateway.quarantine as legacy_review_cli
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
assert legacy_gateway_runtime.SUMMARY_FIELDS == canonical_runtime.SUMMARY_FIELDS
assert legacy_gateway_sources.default_source_registry is canonical_composition.default_source_registry
assert legacy_gateway_connector.main is not canonical_cli_gateway.main
assert legacy_opencti_client.NarrowCTIOpenCTIApiClient is canonical_opencti_client_adapter.NarrowCTIOpenCTIApiClient
assert legacy_opencti_client.OpenCTICompatibilityError is canonical_opencti_client_adapter.OpenCTICompatibilityError
assert legacy_opencti_client.sanitize_legacy_variables is canonical_opencti_client_adapter.sanitize_legacy_variables
assert legacy_opencti_client.sanitize_legacy_query is canonical_opencti_client_adapter.sanitize_legacy_query
assert legacy_opencti_client.build_opencti_client is canonical_opencti_client_adapter.build_opencti_client
assert canonical_provider_registry.SourceRegistry is legacy_gateway_runtime.SourceRegistry
assert canonical_settings.GatewaySettings is legacy_gateway.GatewaySettings
assert legacy_atomic.write_json_atomic is canonical_atomic.write_json_atomic
assert legacy_state.ProcessedItemStateRepository is canonical_state.ProcessedItemStateRepository
assert legacy_state.PulseStateRepository is canonical_state.PulseStateRepository
assert legacy_state.MISPEventStateRepository is canonical_state.MISPEventStateRepository
assert legacy_dedup.ArtifactDeduplicationIndex is canonical_artifacts.ArtifactDeduplicationIndex
assert sys.modules["core.quarantine"] is sys.modules["narrowcti.core.quarantine"]
assert legacy_quarantine.QuarantineRecord is domain_quarantine.QuarantineRecord
assert legacy_quarantine.QuarantineRepository is canonical_quarantine_repository.QuarantineRepository
assert legacy_quarantine.QuarantineRepository is canonical_quarantine.QuarantineRepository
assert isinstance(legacy_quarantine.QuarantineRepository("unused"), canonical_quarantine_port.QuarantineStore)
assert application is not None
assert canonical_preflight.PreflightReport is not None
assert canonical_reporting_operational.GatewayOperationalReport is not None
assert canonical_reporting_correlation.ArtifactCorrelationReport is not None
assert canonical_reporting_decisions.DecisionAuditReport is not None
assert canonical_reporting_curation.CurationReport is not None
assert canonical_relationship_assurance.summarize_relationships is not None
assert canonical_operational_assurance.OperationalValidationReport is not None
assert canonical_validation.import_validation_report is not None
assert canonical_support.SupportDiagnosticSnapshot is not None
assert canonical_relationship_adapter.build_relationship_audit is not None
assert canonical_decision_reader.read_decision_records is not None
assert canonical_support_bundle.write_support_bundle is not None
assert ingestion.run_candidate is ingestion_pipeline.run_candidate
assert ingestion.IngestionOutcome is ingestion_outcomes.IngestionOutcome
assert ingestion_contracts.IngestionOperations is not None
assert canonical_sources is not None
assert canonical_misp is not None
assert canonical_misp_context.extract_misp_context is not None
assert canonical_misp_entities.extract_misp_galaxies is not None
assert canonical_misp_infrastructure.extract_misp_infrastructure is not None
assert canonical_misp_detection_rules.extract_misp_detection_rules is not None
assert legacy_misp_processor.sigma_rule_opencti_compatibility is canonical_misp_detection_rules.sigma_rule_opencti_compatibility
assert legacy_review.ReviewSummary is canonical_review_service.ReviewSummary
assert legacy_review_export.QuarantineExportResult is canonical_review_export.QuarantineExportResult
assert legacy_review_api.ReviewApiSettings is canonical_review_api.ReviewApiSettings
assert legacy_review_auth.ReviewPrincipal is canonical_review_auth.ReviewPrincipal
assert legacy_review_auth.ReviewCredentialStore is canonical_review_auth.ReviewCredentialStore
assert legacy_review_cli.main is canonical_review_cli.main
assert canonical_review_audit.read_audit_events is not None
assert canonical_review_service.AnalystReviewService is not legacy_review.AnalystReviewService
assert canonical_review_export.QuarantineExporter is not legacy_review_export.QuarantineExporter
assert legacy_graph_evidence.build_graph_evidence is domain_graph_evidence.build_graph_evidence
assert legacy_graph_evidence.clamp_confidence is domain_graph_evidence.clamp_confidence
assert legacy_graph_evidence.GRAPH_EVIDENCE_VERSION == domain_graph_evidence.GRAPH_EVIDENCE_VERSION
assert domain_graph_evidence.GRAPH_EVIDENCE_VERSION == "v1.0.0"
with tempfile.TemporaryDirectory() as tmpdir:
    graph_index = legacy_graph.GraphDeduplicationIndex(str(Path(tmpdir) / "graph.json"))
assert isinstance(graph_index, canonical_graph.GraphIndex)
assert canonical_graph.GraphIndex is canonical_graph_index.GraphIndex
assert legacy_graph.plan_actions is domain_graph_deduplication.plan_actions
assert legacy_opencti_graph.OpenCTIGraphLookup is canonical_opencti_graph.OpenCTIGraphLookup
assert legacy_opencti_graph.CompositeGraphLookup is canonical_opencti_graph.CompositeGraphLookup
assert legacy_opencti_dedup.OpenCTIArtifactLookup is canonical_opencti_dedup.OpenCTIArtifactLookup
assert legacy_opencti_dedup.CompositeArtifactDeduplication is canonical_opencti_dedup.CompositeArtifactDeduplication
assert legacy_exporters.indicator_pattern is canonical_stix_patterns.indicator_pattern
assert legacy_exporters.deterministic_graph_object_id is canonical_stix_identifiers.deterministic_graph_object_id
assert legacy_exporters.deterministic_identity_id is canonical_stix_identifiers.deterministic_identity_id
assert legacy_exporters.deterministic_report_id is canonical_stix_identifiers.deterministic_report_id
assert legacy_exporters.build_report_bundle is canonical_stix_serializer.build_report_bundle
assert legacy_exporters.build_graph_report_bundle is canonical_graph_serializer.build_graph_report_bundle
assert legacy_exporters.build_curated_report_bundle is canonical_graph_serializer.build_curated_report_bundle
assert canonical_opencti_exporter.send_bundle is __import__("exporters.opencti", fromlist=["send_bundle"]).send_bundle
assert canonical_compiler.compile_graph_semantics is compiler_graph.compile_graph_semantics
assert compiler_contracts.CompilationResult is canonical_compiler.CompilationResult
assert canonical_opencti_profile.OPENCTI_EXTENSION_DEFINITION_ID.startswith("extension-definition--")
assert isinstance(canonical_opencti_graph.OpenCTIGraphLookup(object()), canonical_graph.GraphProvider)
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
import narrowcti.adapters.persistence.local.quarantine_repository as canonical_quarantine_repository
import narrowcti.ports.storage as canonical_storage
import narrowcti.ports.graph as canonical_graph
import narrowcti.ports.graph_index as canonical_graph_index
import narrowcti.ports.quarantine as canonical_quarantine_port
import narrowcti.core.feed_contract as canonical_core
import narrowcti.core.quarantine as canonical_quarantine
import narrowcti.exporters.stix_builder as canonical_exporters
import narrowcti.gateway.settings as canonical_gateway
import narrowcti.gateway.runtime as canonical_gateway_runtime
import narrowcti.gateway.sources as canonical_gateway_sources
import narrowcti.gateway.connector as canonical_gateway_connector
import narrowcti.gateway.opencti_client as canonical_opencti_client
import narrowcti.application.provider_registry as canonical_provider_registry
import narrowcti.application.runtime as canonical_runtime
import narrowcti.infrastructure.config.settings as canonical_settings
import narrowcti.infrastructure.runtime.gateway_composition as canonical_composition
import narrowcti.cli.gateway as canonical_cli_gateway
import narrowcti.adapters.opencti.client as canonical_opencti_client_adapter
import narrowcti.domain.intelligence.feed_contract as domain_feed
import narrowcti.domain.intelligence.scoring as domain_scoring
import narrowcti.domain.intelligence.contextual_scoring as domain_contextual
import narrowcti.domain.intelligence.tlp as domain_tlp
import narrowcti.domain.intelligence.policy as domain_policy
import narrowcti.domain.intelligence.indicator_types as domain_indicator_types
import narrowcti.domain.intelligence.indicator_policy as domain_indicator_policy
import narrowcti.domain.review.quarantine as domain_quarantine
import narrowcti.domain.graph.deduplication as domain_graph_deduplication
import narrowcti.adapters.opencti.graph_lookup as canonical_opencti_graph
import narrowcti.adapters.opencti.deduplication as canonical_opencti_dedup
import narrowcti.adapters.opencti.graph_serializer as canonical_graph_serializer
import narrowcti.adapters.opencti.exporter as canonical_opencti_exporter
import narrowcti.adapters.opencti.stix_profile as canonical_opencti_profile
import narrowcti.adapters.stix as canonical_stix
import narrowcti.adapters.stix.patterns as canonical_stix_patterns
import narrowcti.adapters.stix.identifiers as canonical_stix_identifiers
import narrowcti.adapters.stix.serializer as canonical_stix_serializer
import narrowcti.application.compiler as canonical_compiler
import narrowcti.application.compiler.contracts as compiler_contracts
import narrowcti.application.compiler.graph as compiler_graph
import narrowcti.application as application
import narrowcti.application.preflight as canonical_preflight
import narrowcti.application.reporting.operational as canonical_reporting_operational
import narrowcti.application.reporting.correlation as canonical_reporting_correlation
import narrowcti.application.reporting.decisions as canonical_reporting_decisions
import narrowcti.application.reporting.curation as canonical_reporting_curation
import narrowcti.application.assurance.opencti_relationship_audit as canonical_relationship_assurance
import narrowcti.application.assurance.operational_validation as canonical_operational_assurance
import narrowcti.application.validation.opencti_client as canonical_validation
import narrowcti.application.support.diagnostics as canonical_support
import narrowcti.adapters.opencti.relationship_audit as canonical_relationship_adapter
import narrowcti.adapters.persistence.local.decision_audit_reader as canonical_decision_reader
import narrowcti.adapters.persistence.local.support_bundle as canonical_support_bundle
import narrowcti.application.ingestion as ingestion
import narrowcti.application.ingestion.pipeline as ingestion_pipeline
import narrowcti.application.ingestion.outcomes as ingestion_outcomes
import narrowcti.application.ingestion.contracts as ingestion_contracts
import narrowcti.adapters.sources as canonical_sources
import narrowcti.adapters.sources.misp as canonical_misp
import narrowcti.adapters.sources.misp.context as canonical_misp_context
import narrowcti.adapters.sources.misp.entities as canonical_misp_entities
import narrowcti.adapters.sources.misp.infrastructure as canonical_misp_infrastructure
import narrowcti.adapters.sources.misp.detection_rules as canonical_misp_detection_rules
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
import core.graph_evidence as legacy_graph_evidence
import core.opencti_graph_lookup as legacy_opencti_graph
import core.opencti_deduplication as legacy_opencti_dedup
import core.quarantine as legacy_quarantine
import exporters.stix_builder as legacy_exporters
import gateway.settings as legacy_gateway
import gateway.runtime as legacy_gateway_runtime
import gateway.sources as legacy_gateway_sources
import gateway.connector as legacy_gateway_connector
import gateway.opencti_client as legacy_opencti_client
import narrowcti.domain.graph.evidence as domain_graph_evidence
import connectors.misp.processor as legacy_misp_processor
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
assert canonical_gateway_runtime.SUMMARY_FIELDS == canonical_runtime.SUMMARY_FIELDS
assert canonical_gateway_sources.default_source_registry is canonical_composition.default_source_registry
assert canonical_gateway_connector.main is not canonical_cli_gateway.main
assert canonical_opencti_client.NarrowCTIOpenCTIApiClient is canonical_opencti_client_adapter.NarrowCTIOpenCTIApiClient
assert canonical_opencti_client.OpenCTICompatibilityError is canonical_opencti_client_adapter.OpenCTICompatibilityError
assert canonical_opencti_client.sanitize_legacy_variables is canonical_opencti_client_adapter.sanitize_legacy_variables
assert canonical_opencti_client.sanitize_legacy_query is canonical_opencti_client_adapter.sanitize_legacy_query
assert canonical_opencti_client.build_opencti_client is canonical_opencti_client_adapter.build_opencti_client
assert canonical_provider_registry.SourceRegistry is canonical_gateway_runtime.SourceRegistry
assert canonical_settings.GatewaySettings is canonical_gateway.GatewaySettings
assert legacy_graph_evidence.build_graph_evidence is domain_graph_evidence.build_graph_evidence
assert legacy_graph_evidence.clamp_confidence is domain_graph_evidence.clamp_confidence
assert legacy_graph_evidence.GRAPH_EVIDENCE_VERSION == domain_graph_evidence.GRAPH_EVIDENCE_VERSION
assert domain_graph_evidence.GRAPH_EVIDENCE_VERSION == "v1.0.0"
assert legacy_atomic.write_json_atomic is canonical_atomic.write_json_atomic
assert legacy_state.ProcessedItemStateRepository is canonical_state.ProcessedItemStateRepository
assert legacy_state.PulseStateRepository is canonical_state.PulseStateRepository
assert legacy_state.MISPEventStateRepository is canonical_state.MISPEventStateRepository
assert legacy_dedup.ArtifactDeduplicationIndex is canonical_artifacts.ArtifactDeduplicationIndex
assert sys.modules["core.quarantine"] is sys.modules["narrowcti.core.quarantine"]
assert legacy_quarantine.QuarantineRecord is domain_quarantine.QuarantineRecord
assert legacy_quarantine.QuarantineRepository is canonical_quarantine_repository.QuarantineRepository
assert legacy_quarantine.QuarantineRepository is canonical_quarantine.QuarantineRepository
assert isinstance(legacy_quarantine.QuarantineRepository("unused"), canonical_quarantine_port.QuarantineStore)
assert application is not None
assert canonical_preflight.PreflightReport is not None
assert canonical_reporting_operational.GatewayOperationalReport is not None
assert canonical_reporting_correlation.ArtifactCorrelationReport is not None
assert canonical_reporting_decisions.DecisionAuditReport is not None
assert canonical_reporting_curation.CurationReport is not None
assert canonical_relationship_assurance.summarize_relationships is not None
assert canonical_operational_assurance.OperationalValidationReport is not None
assert canonical_validation.import_validation_report is not None
assert canonical_support.SupportDiagnosticSnapshot is not None
assert canonical_relationship_adapter.build_relationship_audit is not None
assert canonical_decision_reader.read_decision_records is not None
assert canonical_support_bundle.write_support_bundle is not None
assert ingestion.run_candidate is ingestion_pipeline.run_candidate
assert ingestion.IngestionOutcome is ingestion_outcomes.IngestionOutcome
assert ingestion_contracts.IngestionOperations is not None
assert canonical_sources is not None
assert canonical_misp is not None
assert canonical_misp_context.extract_misp_context is not None
assert canonical_misp_entities.extract_misp_galaxies is not None
assert canonical_misp_infrastructure.extract_misp_infrastructure is not None
assert canonical_misp_detection_rules.extract_misp_detection_rules is not None
assert legacy_misp_processor.sigma_rule_opencti_compatibility is canonical_misp_detection_rules.sigma_rule_opencti_compatibility
with tempfile.TemporaryDirectory() as tmpdir:
    graph_index = legacy_graph.GraphDeduplicationIndex(str(Path(tmpdir) / "graph.json"))
assert isinstance(graph_index, canonical_graph.GraphIndex)
assert canonical_graph.GraphIndex is canonical_graph_index.GraphIndex
assert legacy_graph.plan_actions is domain_graph_deduplication.plan_actions
assert legacy_opencti_graph.OpenCTIGraphLookup is canonical_opencti_graph.OpenCTIGraphLookup
assert legacy_opencti_graph.CompositeGraphLookup is canonical_opencti_graph.CompositeGraphLookup
assert legacy_opencti_dedup.OpenCTIArtifactLookup is canonical_opencti_dedup.OpenCTIArtifactLookup
assert legacy_opencti_dedup.CompositeArtifactDeduplication is canonical_opencti_dedup.CompositeArtifactDeduplication
assert legacy_exporters.indicator_pattern is canonical_stix_patterns.indicator_pattern
assert legacy_exporters.deterministic_graph_object_id is canonical_stix_identifiers.deterministic_graph_object_id
assert legacy_exporters.deterministic_identity_id is canonical_stix_identifiers.deterministic_identity_id
assert legacy_exporters.deterministic_report_id is canonical_stix_identifiers.deterministic_report_id
assert legacy_exporters.build_report_bundle is canonical_stix_serializer.build_report_bundle
assert legacy_exporters.build_graph_report_bundle is canonical_graph_serializer.build_graph_report_bundle
assert legacy_exporters.build_curated_report_bundle is canonical_graph_serializer.build_curated_report_bundle
assert canonical_opencti_exporter.send_bundle is __import__("exporters.opencti", fromlist=["send_bundle"]).send_bundle
assert canonical_compiler.compile_graph_semantics is compiler_graph.compile_graph_semantics
assert compiler_contracts.CompilationResult is canonical_compiler.CompilationResult
assert canonical_opencti_profile.OPENCTI_EXTENSION_DEFINITION_ID.startswith("extension-definition--")
assert isinstance(canonical_opencti_graph.OpenCTIGraphLookup(object()), canonical_graph.GraphProvider)
print("installed-compatibility-canonical-first-ok")
""",
            """
import sys
from narrowcti.application.capabilities import CapabilityRegistry, CapabilityResolution
from narrowcti.ports.entitlements import EntitlementProvider
from narrowcti.adapters.entitlements.community import CommunityEntitlements
from narrowcti.infrastructure.capabilities import COMMUNITY_IMPLEMENTED_CAPABILITIES
import gateway.feature_gates as legacy_feature_gates
import narrowcti.gateway.feature_gates as canonical_feature_gates
assert sys.modules["gateway.feature_gates"] is sys.modules["narrowcti.gateway.feature_gates"]
assert legacy_feature_gates.FeatureGateState is canonical_feature_gates.FeatureGateState
assert legacy_feature_gates.build_feature_gate_state is canonical_feature_gates.build_feature_gate_state
resolution = CapabilityRegistry.default().resolve(
    implemented=COMMUNITY_IMPLEMENTED_CAPABILITIES,
    entitled=CommunityEntitlements().granted_capabilities(),
)
assert resolution.enabled
assert isinstance(resolution, CapabilityResolution)
assert isinstance(CommunityEntitlements(), EntitlementProvider)
print("installed-capability-contract-ok")
""",
            """
import sys
import narrowcti.gateway.feature_gates as canonical_feature_gates
import narrowcti.application.capabilities as capabilities
import narrowcti.ports.entitlements as entitlements
import narrowcti.adapters.entitlements.community as community
import gateway.feature_gates as legacy_feature_gates
import gateway.preflight as legacy_preflight
assert sys.modules["gateway.feature_gates"] is sys.modules["narrowcti.gateway.feature_gates"]
assert canonical_feature_gates.FeatureGateState is legacy_feature_gates.FeatureGateState
assert capabilities.CapabilityRegistry.default().capabilities
assert entitlements.EntitlementProvider is not None
assert community.CommunityEntitlements().granted_capabilities()
assert legacy_preflight.build_preflight_report is not None
print("installed-capability-contract-canonical-first-ok")
""",
            """
from narrowcti.domain.detection import (
    DetectionArtifact,
    DetectionBehavior,
    DetectionRequirement,
    DetectionScope,
    TelemetryContract,
)
from narrowcti.domain.validation import ValidationContract, ValidationEvidence

scope = DetectionScope("community", "wheel")
behavior = DetectionBehavior("t1059.001", "PowerShell")
requirement = DetectionRequirement("DR-wheel", scope, behavior)
telemetry = TelemetryContract(
    "TC-wheel", scope, "manual", "process_creation", "1",
    {"process.name": "available"},
)
artifact = DetectionArtifact(
    "DET-wheel", requirement.id, "sigma", content="title: wheel",
    version="1.0",
)
contract = ValidationContract(
    "VC-wheel", requirement.id, behavior, artifact_id=artifact.id,
    evidence_required=("execution",),
)
evidence = ValidationEvidence(
    "VE-wheel", contract.id, artifact.id, artifact.version,
    telemetry.id, telemetry.version, "unknown", "manual",
)
assert DetectionRequirement.from_dict(requirement.to_dict()) == requirement
assert TelemetryContract.from_dict(telemetry.to_dict()) == telemetry
assert DetectionArtifact.from_dict(artifact.to_dict()) == artifact
assert ValidationContract.from_dict(contract.to_dict()) == contract
assert ValidationEvidence.from_dict(evidence.to_dict()) == evidence
print("installed-detection-foundation-contract-ok")
""",
        )
        for import_code in compatibility_checks:
            run(str(python), "-c", import_code, cwd=temp, env=child_env)
        print(f"wheel-validation-ok version={installed_version} wheel={wheel.name}")


if __name__ == "__main__":
    main()
