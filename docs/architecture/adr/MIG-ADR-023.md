# MIG-ADR-023 — Documentation architecture, boundaries, and brand integration

**Status:** accepted for W7 / PR-21

## Context

PR-21 establishes the current documentation taxonomy, makes the architecture
overview authoritative, records the remaining source-tree boundary exceptions,
and integrates the approved NarrowCTI identity assets. Historical snapshots and
release evidence must remain byte-identical while their locations become
discoverable through a machine-readable migration ledger.

## Decision

- Current documentation is organized into six categories: `architecture/`,
  `product/`, `validation/`, `community/`, `development/`, and `releases/`.
  Operational product assets live separately under `docs/assets/`.
- `docs/architecture/overview.md` is the sole current architecture overview;
  `docs/architecture.md` remains a compatibility stub.
- Historical files move without content rewrites and are verified by SHA-256.
- Documentation links are checked locally, case-sensitively, with fenced and
  inline code masked. External URL availability is outside this gate.
- The dependency direction follows explicit inward edges rather than a linear
  chain: application depends on ports and domain; ports depend on domain;
  adapters depend on application contracts, ports and domain; infrastructure
  depends on application, ports and adapters; and API/CLI are delivery and
  composition surfaces. Transitional imports are permitted only through the
  exact allowlist documented in the overview and boundary tests.
- Deployment documentation describes interoperable endpoints and the A-H
  topology matrix; it does not require direct access to backend databases or
  message stores.
- Approved brand assets are product assets under `docs/assets/brand/`, with the
  brand guide at `docs/product/brand-guidelines.md`. The permanent identity is
  `NarrowCTI`; `2.0` is only a release qualifier.
- Legal and INPI material remains external to this repository.

## Dependencies

- MIG-ADR-001
- MIG-ADR-014
- MIG-ADR-022

## Related ADRs

- MIG-ADR-012
- MIG-ADR-020
- MIG-ADR-021

## Consequences

The migration ledger and link checker become maintained development tooling.
Legacy paths and assets remain available where compatibility or historical
traceability requires them. Boundary tests document the small set of known
transitional imports without widening the dependency direction.

## Scope and non-goals

This ADR is limited to W7 / PR-21. It does not define the web/UI architecture,
source adapter ports, provider behavior, packaging changes, or removal of the
documented compatibility exceptions.
