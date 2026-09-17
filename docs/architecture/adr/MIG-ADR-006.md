# MIG-ADR-006 — Graph evidence contract

- Status: proposed
- Context: `core.graph_evidence` produces source-backed evidence records with temporal and provenance attributes.
- Proposed Decision: Treat the characterized GraphEvidence shape and version as a compatibility contract for migration.
- Alternatives: Recompute evidence during export; change the evidence shape while moving modules.
- Consequences: Evidence semantics remain comparable across waves and report generation remains explainable.
- Dependencies: GraphEvidence golden fixture; ADR-005 and ADR-009.
- Target Wave: W1 architecture foundation; implementation deferred.

No evidence field or relationship behavior is changed here.
