# MIG-ADR-006 — Graph evidence contract

- Status: proposed
- Context: `core.graph_evidence` produces source-backed evidence records with temporal and provenance attributes.
- Proposed Decision: Treat the characterized GraphEvidence shape and version as a compatibility contract for migration.
- Alternatives: Recompute evidence during export; change the evidence shape while moving modules.
- Consequences: Evidence semantics remain comparable across waves and report generation remains explainable.
- Dependencies: GraphEvidence golden fixture and ADR-009. ADR-005 is a
  related domain-primitives decision, not a dependency of the graph evidence
  contract; this direction avoids a documentation dependency cycle.
- Target Wave: W1 architecture foundation; implementation deferred.

No evidence field or relationship behavior is changed here.
