# MIG-ADR-017 — MISP source extraction boundary

- Status: accepted for W3 / PR-09
- Context: The MISP processor currently combines source-specific context
  extraction with candidate decision ordering, graph planning, persistence and
  export runtime. PR-09 needs to separate the MISP extraction responsibilities
  without changing the operational processor or introducing a generic source
  adapter port.
- Proposed Decision: Make `src/narrowcti/adapters/sources/misp` the canonical
  owner of MISP source-specific extraction. The package is limited to the
  `_common`, `entities`, `infrastructure`, `detection_rules` and `context`
  modules. Feed normalization remains owned by
  `connectors.misp.feed_adapter`; runtime ownership remains in
  `connectors.misp.processor`. `decision_metadata` resolves
  `candidate.event` versus `candidate_ref.raw` and `source.tags` versus
  `candidate_ref.tags` before calling `extract_misp_context(source, tags=...)`.
  No application.ingestion cutover, graph/STIX/OpenCTI move or generic source
  port is introduced. Existing MISP metadata keys, provenance, ordering,
  deduplication, Sigma compatibility reasons and failure behavior require exact
  output parity.
- Alternatives: Keep all extraction in `MISPProcessor`; introduce a generic
  source provider abstraction before source-specific characterization; move
  extraction into `application.ingestion`.
- Consequences: MISP extraction can be tested and packaged independently while
  the processor retains all runtime ordering and side effects. The explicit
  compatibility surface is declared in `connectors.misp.processor.__all__` and
  currently contains `MISPProcessor`, `decision_metadata`,
  `graph_candidate_policy_from_settings` and
  `sigma_rule_opencti_compatibility`; this declaration does not claim that
  other module attributes are technically inaccessible.
- Dependencies: Current MISP extraction characterization, MIG-ADR-005,
  MIG-ADR-014 and MIG-ADR-016.
- Related ADRs: MIG-ADR-004 and MIG-ADR-006.
- Target Wave: W3 / PR-09.
