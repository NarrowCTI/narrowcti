# MIG-ADR-008 — OpenCTI canonical lookup

- Status: proposed
- Context: `core.opencti_graph_lookup` resolves canonical entities and exact relationships before graph export.
- Proposed Decision: Preserve read-only lookup precedence, fail-open auditing and exact relationship deduplication as migration contracts.
- Alternatives: Create entities without lookup; deduplicate by name only; fail closed on lookup outage.
- Consequences: Existing OpenCTI graphs remain reusable and outages remain visible without silently blocking ingestion.
- Dependencies: OpenCTI lookup tests and golden contract; ADR-007 and ADR-009.
- Target Wave: W1 architecture foundation; implementation deferred.

The W0 characterization invokes existing lookup tests but adds no lookup behavior.
