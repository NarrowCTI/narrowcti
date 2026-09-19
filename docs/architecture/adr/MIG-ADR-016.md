# MIG-ADR-016 — Ingestion application orchestration boundary

- Status: accepted for W2 / PR-08
- Context: MISP and OTX processors currently combine candidate-level decision
  ordering with source-specific normalization, enrichment, persistence and
  export side effects. The migration needs a small application seam that can
  preserve the ordering without duplicating source behavior or taking
  ownership of query/run execution.
- Proposed Decision: Introduce `src/narrowcti/application/ingestion` as the
  owner of candidate-level orchestration only. The flow is linear and
  deterministic: prechecks, TLP, contextual scoring, policy, indicator
  filtering, artifact deduplication, then dry-run or export. The seam exposes
  only the outcomes `ingest`, `drop`, `quarantine`, `skip`, `error` and
  `dry_run`. It is not a generic stage engine, registry, middleware chain,
  plugin system or DAG. Source normalization and enrichment remain outside the
  application package, and query/run aggregation, summaries, search limits
  and sleep semantics remain source-specific.
- Side-effect Ordering: A normal successful export preserves
  `export → artifact mark → source checkpoint → DecisionRecord → graph
  exported-plan mark` when graph metadata is returned. Graph replay remains an
  `ingest` outcome and is represented by source-provided candidate/export
  dependencies; it is not a MISP-specific branch in the application seam. The
  application package does not move `mark_event`, `mark_pulse`,
  `DecisionAuditLog`, quarantine creation, `GraphDeduplicationIndex` or the
  OpenCTI exporter.
- Alternatives: Keep duplicated orchestration in both processors; introduce a
  generic pipeline framework; move source adapters and persistence into the
  application layer before their dedicated cutovers.
- Consequences: Candidate-level ordering can be characterized independently
  and adopted incrementally. Existing MISP and OTX runtime behavior remains
  unchanged in PR-08, while PR-10 and PR-11 own runtime adoption after the
  source-specific decomposition work.
- Dependencies: Current MISP/OTX pipeline characterization, MIG-ADR-005 and
  MIG-ADR-014.
- Related ADRs: MIG-ADR-004, MIG-ADR-010, MIG-ADR-011 and MIG-ADR-015.
- Target Wave: W2 / PR-08.
