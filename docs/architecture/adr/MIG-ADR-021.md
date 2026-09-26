# MIG-ADR-021 — Detection foundation domain contracts

Status: accepted for W6 / PR-19

## Context

The Community baseline contains detection-rule extraction and operational
validation, but it does not yet expose stable domain contracts for detection
intent, telemetry declarations, detection artifacts or normalized validation
evidence. MISP, OTX, Sigma, OpenCTI and operational assurance must remain
outside those contracts.

The Architecture Product Engineering Blueprint v0.5 identifies
`DetectionRequirement` as the primary detection-engineering unit. The
Architecture Migration Plan v0.5 scopes W6 / PR-19 to five public Community
contracts: `DetectionRequirement`, `TelemetryContract`, `DetectionArtifact`,
`ValidationContract` and `ValidationEvidence`.

## Decision

PR-19 introduces pure, immutable, provider-neutral domain contracts under
`narrowcti.domain.detection` and `narrowcti.domain.validation`.

`DetectionRequirement` represents why a behavior matters. Sigma, YARA,
Suricata, Snort, PCRE and vendor-native queries are represented only as
`DetectionArtifact` formats and never become requirements.

`TelemetryContract` is a manually declared environment/schema/field contract.
Field availability is represented by `available`, `missing` or `unknown`, and
readiness is derived as `ready`, `incomplete` or `unknown`. Provider discovery,
parser mapping and freshness semantics are deferred because their vocabulary
is not stable enough for this wave.

`ValidationContract` uses explicit `requirement_id` and optional
`artifact_id` references. Its `provider_preference` is singular optional
metadata, while `expected.telemetry` and `expected.detection` are booleans.
`TelemetryContract` owns telemetry capability and field detail; the concrete
observed references belong to `ValidationEvidence`. `ValidationEvidence`
records the exact artifact and version plus the exact telemetry contract and
version used for a normalized result. Its status vocabulary is independent of
`OperationalValidationReport`.

The detection lifecycle vocabulary is explicit and the domain accepts only
adjacent transitions:

`proposed → reviewed → designed → compiled → telemetry-verified → deployed →
tested → validated → degraded → retired`.

No same-state transition, skip, rollback, automatic retirement, authorization,
reviewer state, audit persistence or timestamps are implemented here.

The Blueprint has an inconsistency in the meaning of `TelemetryContract.blocks`:
one example refers to `DET-*`, while Appendix B refers to `DR-*`. PR-19 keeps
`blocks` as normalized opaque references and does not silently assign an ID
type.

All contracts support deterministic `to_dict()` / `from_dict()` round-trips,
use no runtime dependency beyond the standard library, and do not import
providers, SDKs, parsers, network, filesystem or commercial modules.

DetectionPlan, ValidationProvider, TelemetryProvider, automatic telemetry
discovery, compilation, native deployment, OpenAEV/CALDERA/Atomic
orchestration, continuous validation, D3FEND automation, persistence, API and
UI remain deferred.

## Alternatives considered

- Treat Sigma as the primary domain object. Rejected because the Blueprint
  defines the requirement, not a rule format, as the primary unit.
- Reuse `OperationalValidationReport` for detection evidence. Rejected because
  its status vocabulary and assurance scope are already public and different.
- Store mutable dictionaries directly in frozen records. Rejected because
  `frozen=True` alone does not prevent caller mutation.
- Add provider ports or discovery in PR-19. Rejected because W6 defines public
  contracts only and no current caller requires orchestration.
- Include `DetectionPlan` now. Rejected because the Migration Plan does not
  assign it to PR-19 and no planning consumer exists in the baseline.

## Consequences

- Community and future private extensions share stable, serializable domain
  contracts without sharing provider implementations.
- Normalized evidence can refer to an exact artifact and telemetry contract
  without embedding raw SIEM, EDR or BAS payloads.
- Lifecycle, confidence, version and readiness semantics become testable
  contracts before application orchestration exists.
- Future changes to freshness, parser mapping, discovery, planning and
  provider execution require their own ADRs or additive schema revisions.
- Existing gateway, processors, graph, STIX, OpenCTI, quarantine and
  operational-validation behavior remain unchanged.

## Dependencies

- Current W6 baseline and contract characterization
- MIG-ADR-001
- MIG-ADR-002
- MIG-ADR-014

## Related ADRs

- MIG-ADR-007
- MIG-ADR-009
- MIG-ADR-012
- MIG-ADR-013
- MIG-ADR-018
- MIG-ADR-019

## Validation and rollout

The implementation is validated by frozen-record, normalization, lifecycle,
readiness, traceability, serialization-golden and AST boundary tests. The
wheel validator must import all new modules outside the source checkout and
exercise a round-trip. The full existing suite and all repository quality and
security gates remain required.

## Target Wave

W6 / PR-19 — Detection Foundation Domain Contracts.
