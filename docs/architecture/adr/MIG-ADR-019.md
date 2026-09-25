# MIG-ADR-019 — Capability registry and entitlement provider boundary

Status: accepted for W6 / PR-18

## Context

The Community runtime currently exposes feature-gate names from
`gateway.feature_gates`, but that inventory conflates capability knowledge,
implementation presence, entitlement, operator requests, and enabled state.
Community 2.0 needs a capability-first boundary without introducing
commercial licensing, network calls, or edition checks into the public runtime.

## Proposed Decision

PR-18 introduces a canonical `CapabilityRegistry`, an immutable capability
resolution, and the minimal `EntitlementProvider` port. Capability names and
aliases are resolved deterministically, while implementation presence is an
explicit Community manifest and entitlements are supplied by the local,
offline `CommunityEntitlements` provider.

The states remain distinct: known, implemented, entitled, requested, enabled,
disabled, and unknown. Enabled is exactly the intersection of implemented and
entitled. Requests never grant entitlements.

Community entitlement resolution does not use network access, license files,
secrets, private packages, dynamic plugin discovery, or edition checks.
Security controls remain product invariants, not capabilities or commercial
entitlements.

The legacy `FeatureGateState`, `AVAILABLE_CAPABILITIES`, normalization helpers,
and `build_feature_gate_state` remain import-compatible projections. Legacy
reporting names resolve to canonical `reporting.*` names. The historical
`mssp.multi_environment` name resolves to `environment.multi`, but is not
implemented, entitled, or enabled in Community. `deployment.templates`
remains a legacy Community capability for compatibility and is explicitly not
a commercial grant.

Future Community names `ui.basic`, `source.explorer`, and `ingestion.run_once`
are known target names only; they are not implemented or granted by PR-18.
`source.search` and `ingestion.preview` are not canonical names in this wave.

No Web UI, Source Explorer implementation, licensing implementation, API
route, scheduler, processor cutover, graph/STIX/OpenCTI change, or deployment
topology change is part of this decision.

## Alternatives

- Keep the current feature-gate tuple as the authority. Rejected because it
  cannot distinguish implementation, entitlement, and request state.
- Let `NARROWCTI_CAPABILITIES` grant features. Rejected because configuration
  must remain declarative and must not escalate Community privileges.
- Add a network-backed license client. Rejected because Community remains
  deterministic and offline.
- Use dynamic package/plugin discovery for implementation presence. Rejected
  because it would make enablement non-deterministic and blur the boundary.

## Consequences

- Consumers gain a stable capability-first contract.
- Existing feature-gate imports and DTO shape remain compatible.
- The false Community enablement of `mssp.multi_environment` is corrected.
- Future commercial providers can implement the public port without changing
  the Community provider.
- The legacy tuple remains a compatibility projection rather than the full
  canonical namespace.

## Dependencies

- Current feature-gate and preflight characterization
- MIG-ADR-002
- MIG-ADR-014

## Related ADRs

- MIG-ADR-013
- MIG-ADR-018
- MIG-ADR-010

## Target Wave

W6 / PR-18 — CapabilityRegistry + CommunityEntitlements.
