# MIG-ADR-007 — Candidate and promotion policy

- Status: proposed
- Context: Graph candidates are policy-filtered before audit, dry-run or export planning.
- Proposed Decision: Keep candidate acceptance, hold reasons and export planning as separate observable stages.
- Alternatives: Promote directly from source parsing; combine policy and exporter decisions.
- Consequences: Operators retain a reviewable explanation for every accepted or held candidate.
- Dependencies: GraphCandidate and GraphExportPlan fixtures; ADR-006 and ADR-011.
- Target Wave: W1 architecture foundation; implementation deferred.

W0 only records the existing separation.
