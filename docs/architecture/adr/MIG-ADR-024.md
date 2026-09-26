# MIG-ADR-024 — Community 2.0 compatibility cutover

**Status:** accepted for W7 / PR-22

## Context

The Community 2.0 migration introduced a second compatibility layer under
`src/narrowcti/{core,connectors,exporters,gateway}`. Each nested module only
aliases a top-level legacy module through `narrowcti.compat`. The published
Community v1.1.1 source tree did not contain these nested facades, while the
top-level roots remain supported compatibility surfaces.

The duplicate layer increases wheel size, creates misleading package paths,
and requires artificial module-identity tests without providing a distinct
runtime capability.

## Decision

- Remove the 60 nested compatibility facades and `narrowcti.compat` in W7 / PR-22.
- Preserve the top-level `core/`, `connectors/`, `exporters/` and `gateway/`
  packages, their public symbols, current entrypoints, and operational behavior.
- Keep canonical implementation in `src/narrowcti/{domain,ports,application,adapters,infrastructure,api,cli}`.
- Replace nested facade identity tests with tests of legacy symbols against
  their canonical owners where that ownership is already established.
- Add a deterministic, read-only migration checker. It reports deprecated
  legacy imports and removed nested facade paths without rewriting source.
- Keep the architecture boundary allowlist unchanged unless a dependency is
  demonstrably removed by this bounded cleanup.
- Historical documentation and immutable release evidence remain unchanged.

The removed nested compatibility facades were not part of the published
Community v1.1.1 source tree.

## Alternatives

- Retain both compatibility layers, preserving duplication and ambiguous
  package ownership.
- Remove the top-level roots, which would break the supported 1.x surface.
- Add a generic import hook, increasing runtime complexity and hiding package
  ownership.

## Consequences

The wheel and source tree expose one canonical package namespace plus the
supported top-level compatibility roots. Existing `gateway.*`, `core.*`,
`connectors.*` and `exporters.*` consumers remain valid. Tests, CI smoke checks
and wheel validators must stop treating nested facades as a contract.

## Dependencies

- MIG-ADR-002
- MIG-ADR-014
- MIG-ADR-022
- MIG-ADR-023

## Related ADRs

- MIG-ADR-006
- MIG-ADR-008
- MIG-ADR-009
- MIG-ADR-015
- MIG-ADR-021

## Risks and rollback

The principal risks are stale imports in tests or packaging metadata and
accidental removal of a top-level entrypoint. Validation therefore builds and
installs a wheel outside the checkout, runs the full unittest suite, checks the
current architecture allowlist, and performs container smoke validation. A
rollback is a normal revert of the PR; no data migration is required.

## Scope and non-goals

This decision is limited to the W7 / PR-22 compatibility cutover. It does not
move residual `core` implementations, source processors, OpenCTI/STIX logic,
quarantine, configuration, state, graph behavior, runtime roles, UI, scheduler,
or commercial capabilities. It does not remove the top-level compatibility
roots or define a future date for their removal.
