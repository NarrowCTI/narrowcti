# MIG-ADR-019 — Capability registry and entitlement provider boundary

Status: accepted and implemented in Community

## Context

The legacy feature-gate inventory combined capability knowledge,
implementation presence, entitlement, operator requests and enabled state.
Community needs a deterministic boundary that distinguishes those states
without network access or capability escalation through configuration.

## Decision

Community uses a canonical `CapabilityRegistry`, immutable capability
resolution and the `EntitlementProvider` contract. Capability names and
supported aliases resolve deterministically; implementation presence comes
from the explicit Community manifest, and entitlements come from the local,
offline `CommunityEntitlements` provider.

The states remain distinct: known, implemented, entitled, requested, enabled,
disabled and unknown. A capability is enabled only when implemented and
entitled. A request does not grant an entitlement. Community resolution does
not use network access, license files, secrets or dynamic package discovery.
Security controls are product invariants, not capabilities.

Legacy `FeatureGateState`, `AVAILABLE_CAPABILITIES`, normalization helpers and
`build_feature_gate_state` remain import-compatible projections. Existing
legacy aliases and reporting names retain their supported normalization
behavior; a legacy name does not by itself make a capability implemented,
entitled or enabled.

## Rationale

- Retaining the feature-gate tuple as authority would continue to conflate
  implementation, entitlement and request state.
- Allowing configuration to grant capabilities would turn declarative
  settings into a privilege escalation path.
- A local provider keeps Community capability resolution deterministic and
  usable without an external service.

## Consequences

- Consumers have a stable capability-resolution contract and explicit
  Community implementation/entitlement state.
- Existing feature-gate imports and DTO shape remain compatible.
- Legacy feature-gate data remains a compatibility projection rather than the
  canonical capability inventory.

## Related decisions

- MIG-ADR-002 — source tree and package boundary
- MIG-ADR-014 — compatibility and rollout policy
- MIG-ADR-018 — gateway provider registry boundary
