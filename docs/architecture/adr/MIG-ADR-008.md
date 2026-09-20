# MIG-ADR-008 — OpenCTI graph provider boundary

- Status: accepted for W4 / PR-13
- Context: OpenCTI-backed canonical entity and relationship lookup, artifact deduplication, and graph-plan lookup are currently implemented in `core` and consumed by processors, exporters, and graph planning. The migration needs a provider boundary without changing lookup precedence, matching, error, cache, or mutation semantics.
- Proposed Decision: Introduce the smallest consumer-derived graph provider boundary. The plan-level seam remains `known_keys_for_plan(plan)` and the existing `GraphIndex` contract; OpenCTI lookup and artifact deduplication move behind canonical adapter owners while `GraphDeduplicationIndex` remains the transitional concrete local implementation in `core`. Pure graph deduplication helpers may be owned by the domain, but filesystem/JSON/atomic-write behavior remains outside it.
- Alternatives: Invent a generic entity/relationship port unused by current consumers; move the concrete graph index into an OpenCTI adapter; rewrite STIX/export and gateway runtime in this wave.
- Consequences: Domain and ports remain independent of OpenCTI, legacy `core.*` imports continue to resolve the same public objects, and OpenCTI outages retain the existing observable fail-open lookup behavior. Runtime/client capability negotiation and STIX compilation remain in later waves.
- Dependencies: current OpenCTI lookup/dedup characterization; MIG-ADR-002; MIG-ADR-014; MIG-ADR-015.
- Related ADRs: MIG-ADR-006; MIG-ADR-007; MIG-ADR-009.
- Target Wave: W4 / PR-13.

The implementation is intentionally limited to the graph lookup/dedup/provider boundary. PR-14 owns the STIX IR/compiler and OpenCTI adapter rewrite; PR-15 owns gateway runtime/provider registry and client capability migration.
