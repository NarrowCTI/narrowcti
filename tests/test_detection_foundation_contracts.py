import json
import unittest
from dataclasses import FrozenInstanceError, fields
from pathlib import Path

from narrowcti.domain.detection import (
    DETECTION_LIFECYCLE_STATES,
    DetectionArtifact,
    DetectionBehavior,
    DetectionRequirement,
    DetectionScope,
    TelemetryContract,
    TelemetryField,
    ThreatContext,
    can_transition,
    transition_lifecycle,
)
from narrowcti.domain.validation import ValidationContract, ValidationEvidence


ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "tests" / "fixtures" / "detection_foundation_contracts.json"


class DetectionFoundationContractTests(unittest.TestCase):
    def setUp(self):
        self.scope = DetectionScope("community", "prod")
        self.behavior = DetectionBehavior("t1059.001", "PowerShell procedure")
        self.requirement = DetectionRequirement(
            id="DR-1",
            scope=self.scope,
            behavior=self.behavior,
            source_refs=("source:1", "source:1", "decision:1"),
            threat_context=ThreatContext(actor="actor", campaign="campaign"),
            priority="high",
            confidence=80,
            provenance=("source:1",),
            telemetry_requirements=("process_creation", "process_creation"),
        )

    def test_detection_requirement_normalizes_without_random_identity(self):
        self.assertEqual("DR-1", self.requirement.id)
        self.assertEqual(("source:1", "decision:1"), self.requirement.source_refs)
        self.assertEqual(("process_creation",), self.requirement.telemetry_requirements)
        self.assertEqual("T1059.001", self.requirement.behavior.attack_id)
        self.assertEqual(1, self.requirement.version)

    def test_detection_requirement_rejects_invalid_identity_version_and_confidence(self):
        with self.assertRaises(ValueError):
            DetectionRequirement("", self.scope, self.behavior)
        with self.assertRaises(ValueError):
            DetectionRequirement("DR-1", self.scope, self.behavior, version=0)
        with self.assertRaises(ValueError):
            DetectionRequirement("DR-1", self.scope, self.behavior, confidence=101)

    def test_frozen_contract_and_caller_collections_are_isolated(self):
        refs = ["source:1"]
        fields = {"process.name": "available"}
        requirement = DetectionRequirement(
            "DR-2", self.scope, self.behavior, source_refs=refs
        )
        telemetry = TelemetryContract(
            "TC-1", self.scope, "manual", "process_creation", "1", fields
        )
        refs.append("source:2")
        fields["user.name"] = "missing"
        self.assertEqual(("source:1",), requirement.source_refs)
        self.assertEqual((TelemetryField("process.name", "available"),), telemetry.required_fields)
        with self.assertRaises(FrozenInstanceError):
            requirement.id = "DR-3"

    def test_lifecycle_only_allows_adjacent_transitions(self):
        self.assertEqual(tuple(DETECTION_LIFECYCLE_STATES), (
            "proposed", "reviewed", "designed", "compiled",
            "telemetry-verified", "deployed", "tested", "validated",
            "degraded", "retired",
        ))
        self.assertTrue(can_transition("proposed", "reviewed"))
        self.assertFalse(can_transition("proposed", "designed"))
        self.assertFalse(can_transition("validated", "retired"))
        self.assertFalse(can_transition("retired", "retired"))
        self.assertEqual("reviewed", transition_lifecycle("proposed", "reviewed"))
        with self.assertRaises(ValueError):
            transition_lifecycle("proposed", "proposed")
        with self.assertRaises(ValueError):
            transition_lifecycle("retired", "proposed")

    def test_telemetry_readiness_is_derived(self):
        ready = TelemetryContract(
            "TC-ready", self.scope, "manual", "process_creation", "1",
            {"process.name": "available"},
        )
        incomplete = TelemetryContract(
            "TC-incomplete", self.scope, "manual", "process_creation", "1",
            {"process.name": "available", "user.name": "missing"},
        )
        unknown = TelemetryContract(
            "TC-unknown", self.scope, "manual", "process_creation", "1",
            {"process.name": "unknown"},
        )
        empty = TelemetryContract("TC-empty", self.scope, "manual", "process_creation", "1")
        self.assertEqual("ready", ready.readiness)
        self.assertEqual("incomplete", incomplete.readiness)
        self.assertEqual("unknown", unknown.readiness)
        self.assertEqual("unknown", empty.readiness)
        with self.assertRaises(ValueError):
            TelemetryContract.from_dict({**ready.to_dict(), "readiness": "incomplete"})

    def test_telemetry_schema_version_is_independent_from_object_version(self):
        contract = TelemetryContract(
            "TC-2", self.scope, "sentinelone", "process_creation", "ECS-8.11",
            version=2,
        )
        self.assertEqual("ECS-8.11", contract.schema_version)
        self.assertEqual(2, contract.version)

    def test_detection_artifact_supports_inline_and_referenced_content(self):
        artifact = DetectionArtifact(
            "DET-1", "DR-1", "Sigma", source_ref="git:abc", content="title: test",
            content_ref="git:abc:path.yml", backend="splunk", version="2026.09",
            content_sha256="A" * 64,
        )
        self.assertEqual("sigma", artifact.format)
        self.assertEqual("a" * 64, artifact.content_sha256)
        with self.assertRaises(ValueError):
            DetectionArtifact("DET-2", "DR-1", "sigma")
        with self.assertRaises(ValueError):
            DetectionArtifact("DET-3", "DR-1", "sigma", content="x", content_sha256="bad")

    def test_validation_contract_has_explicit_requirement_and_optional_artifact(self):
        contract = ValidationContract(
            "VC-1", "DR-1", self.behavior, evidence_required=("execution", "execution")
        )
        self.assertEqual("DR-1", contract.requirement_id)
        self.assertIsNone(contract.artifact_id)
        self.assertEqual(("execution",), contract.evidence_required)
        with self.assertRaises(ValueError):
            ValidationContract("VC-2", "DR-1", self.behavior, evidence_required=())

    def test_validation_evidence_traces_exact_artifact_and_telemetry_versions(self):
        evidence = ValidationEvidence(
            "VE-1", "VC-1", "DET-1", "2026.09", "TC-1", 2,
            "passed", "manual", telemetry_observed=True,
            telemetry_refs=("telemetry:1",), detection_observed=True,
            alert_refs=("alert:1",), latency_ms=0,
        )
        self.assertEqual("DET-1", evidence.detection_artifact_id)
        self.assertEqual(2, evidence.telemetry_contract_version)
        self.assertEqual("passed", evidence.status)
        with self.assertRaises(ValueError):
            ValidationEvidence("VE-2", "VC-1", "DET-1", "1", "TC-1", 1, "bad", "manual")
        with self.assertRaises(ValueError):
            ValidationEvidence("VE-3", "VC-1", "DET-1", "1", "TC-1", 1, "passed", "manual", latency_ms=-1)

    def test_validation_evidence_exposes_only_normalized_observations(self):
        field_names = {field.name for field in fields(ValidationEvidence)}
        self.assertIn("telemetry_observed", field_names)
        self.assertIn("telemetry_refs", field_names)
        self.assertIn("detection_observed", field_names)
        self.assertIn("alert_refs", field_names)
        self.assertNotIn("raw_siem_event", field_names)
        self.assertNotIn("raw_provider_response", field_names)

    def test_round_trip_and_golden_serialization(self):
        fixture = json.loads(FIXTURE.read_text(encoding="utf-8"))
        requirement = DetectionRequirement.from_dict(fixture["detection_requirement"])
        telemetry = TelemetryContract.from_dict(fixture["telemetry_contract"])
        artifact = DetectionArtifact.from_dict(fixture["detection_artifact"])
        contract = ValidationContract.from_dict(fixture["validation_contract"])
        evidence = ValidationEvidence.from_dict(fixture["validation_evidence"])
        actual = {
            "detection_requirement": requirement.to_dict(),
            "telemetry_contract": telemetry.to_dict(),
            "detection_artifact": artifact.to_dict(),
            "validation_contract": contract.to_dict(),
            "validation_evidence": evidence.to_dict(),
        }
        self.assertEqual(fixture, actual)
        self.assertEqual(requirement, DetectionRequirement.from_dict(requirement.to_dict()))
        self.assertEqual(telemetry, TelemetryContract.from_dict(telemetry.to_dict()))
        self.assertEqual(artifact, DetectionArtifact.from_dict(artifact.to_dict()))
        self.assertEqual(contract, ValidationContract.from_dict(contract.to_dict()))
        self.assertEqual(evidence, ValidationEvidence.from_dict(evidence.to_dict()))
        self.assertEqual(
            json.dumps(actual, sort_keys=True),
            json.dumps(json.loads(json.dumps(actual, sort_keys=True)), sort_keys=True),
        )


if __name__ == "__main__":
    unittest.main()
