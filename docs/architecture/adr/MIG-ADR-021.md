# MIG-ADR-021 — Detection foundation domain contracts

Status: accepted and implemented in Community

## Context

Detection-rule extraction and operational validation need stable domain
contracts for detection intent, telemetry declarations, detection artifacts
and normalized validation evidence. These concepts have different meanings
and must not be collapsed into source-provider or operational-report models.

## Decision

The provider-neutral contracts are immutable and live under
`narrowcti.domain.detection` and `narrowcti.domain.validation`.

- `DetectionRequirement` represents why a behavior matters. Sigma, YARA,
  Suricata, Snort, PCRE and vendor-native queries are artifact formats, not
  requirements.
- `TelemetryContract` declares an environment, schema and fields. Field
  availability is `available`, `missing` or `unknown`; readiness is derived
  as `ready`, `incomplete` or `unknown`.
- `ValidationContract` references a `requirement_id` and optional
  `artifact_id`. `provider_preference` is singular optional metadata, and
  `expected.telemetry` and `expected.detection` are booleans.
- `ValidationEvidence` records the exact artifact and version, and the exact
  telemetry contract and version used for a normalized result. Its status
  vocabulary is independent of `OperationalValidationReport`.

The detection lifecycle accepts only adjacent transitions:

`proposed → reviewed → designed → compiled → telemetry-verified → deployed → tested → validated → degraded → retired`.

There is no same-state transition, skipped transition, rollback, automatic
retirement, authorization state, reviewer state, audit persistence or
timestamp in this domain contract. `TelemetryContract.blocks` remains a list
of normalized opaque references; the contract does not infer an identifier
type from a reference string.

All contracts support deterministic `to_dict()` / `from_dict()` round-trips,
use only the Python standard library and do not import providers, SDKs,
parsers, network or filesystem code.

## Rationale

- A detection requirement describes the behavior of interest; rule formats
  describe artifacts that implement detections.
- Telemetry declarations and observed validation evidence have distinct
  ownership and lifecycle semantics.
- Reusing `OperationalValidationReport` would conflate its operational
  assurance scope and status vocabulary with normalized detection evidence.
- Immutable, serializable records make the public contract deterministic and
  prevent caller mutation of nested state.

## Consequences

- Community consumers can exchange normalized detection and validation
  contracts without coupling the domain to a provider or raw tool payload.
- Evidence can refer to exact artifact and telemetry-contract versions without
  embedding raw SIEM, EDR or BAS responses.
- Changes to these meanings require an explicit compatible contract revision.

## Related decisions

- MIG-ADR-002 — source tree and package boundary
- MIG-ADR-009 — STIX/compiler and OpenCTI export boundary
- MIG-ADR-012 — operational evidence boundary
- MIG-ADR-014 — compatibility and rollout policy
- MIG-ADR-018 — gateway provider registry boundary
- MIG-ADR-019 — capability registry and entitlement provider boundary
