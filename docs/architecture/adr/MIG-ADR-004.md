# MIG-ADR-004 — Source adapter ports

- Status: proposed
- Context: MISP and OTX adapters currently expose source-specific runtime seams and normalized candidates.
- Proposed Decision: Define source adapter ports around the existing feed contract and preserve source provenance at the boundary.
- Alternatives: Create a common adapter immediately; let each connector expose an unrelated API.
- Consequences: Future adapters can be substituted in tests while source-specific parsing remains isolated.
- Dependencies: Existing feed-contract tests; ADR-002 and ADR-005.
- Target Wave: W1 architecture foundation; implementation deferred.

The W0 branch does not introduce ports or compatibility shims.
