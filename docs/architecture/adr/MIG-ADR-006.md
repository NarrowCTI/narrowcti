# MIG-ADR-006 — Graph evidence boundary

- Status: accepted
- Context: `core.graph_evidence` currently owns the GraphEvidence contract, fourteen
  source-backed evidence families, temporal/provenance attributes, confidence
  normalization, and the final aggregation order. The module is consumed by the
  MISP and OTX processors and by graph-candidate construction.
- Proposed Decision: For W4 / PR-12, make
  `narrowcti.domain.graph.evidence` the canonical owner of GraphEvidence. Keep a
  single stable aggregator and split implementation by evidence family without
  changing the public output contract, version, record ordering, aliases,
  confidence behavior, provenance, or timeline semantics. Retain
  `core.graph_evidence` as a compatibility wrapper that reexports the historical
  symbols without duplicating implementation.
- Alternatives: Leave the 2,500-line module intact; recompute evidence during
  export; or change the evidence shape while moving modules. These alternatives
  either preserve the current coupling or risk semantic drift.
- Consequences: Evidence semantics remain comparable across waves, report
  generation remains explainable, and the domain graph package can be tested
  independently of source processors. Graph candidates, promotion policy,
  graph providers/deduplication, STIX, OpenCTI, and exporters remain outside this
  decision.
- Dependencies: Existing GraphEvidence characterization and golden-output
  contract; established legacy compatibility and rollout constraints.
- Related ADRs: MIG-ADR-002, MIG-ADR-005, MIG-ADR-007, MIG-ADR-009.
- Target Wave: W4 / PR-12.

No evidence field, relationship behavior, or source extraction behavior is
changed by this ADR.
