# Product and Architecture Validation - v0.5.0

## Verdict

NarrowCTI is still aligned with the requested product direction: an
OpenCTI-native CTI gateway that curates, scores, deduplicates, audits and governs
intelligence before it reaches the OpenCTI graph.

The project is not drifting into a simple OTX custom connector or a loose bundle
of feed scripts. The v0.2 through v0.4 evolution has preserved the gateway
foundation, and v0.5 is the right point to make the gateway runtime explicit.

## Evidence By Version

v0.2 established a modular OTX foundation:

- Source settings, API client, processor, runtime loop, state and export were
  separated.
- The original OTX implementation became a testable adapter foundation instead
  of a one-file connector.

v0.3 established the product foundation:

- The project identity moved from OTX-specific naming to NarrowCTI Gateway.
- A shared feed contract was introduced for future sources.
- Decision audit records and operational summaries became part of the product
  behavior.
- Documentation positioned NarrowCTI as a pre-ingestion intelligence decision
  layer for OpenCTI.

v0.4 validated the multi-feed gateway direction:

- MISP became the second real source foundation.
- OTX and MISP reuse shared feed contracts, policy, scoring, decision audit,
  state patterns and OpenCTI export paths.
- MISP source provenance, collector context, dry-run mode, run-once execution and
  guardrails were added for controlled curation.
- Bounded operational validation showed the runtime can exercise MISP without
  destabilizing OpenCTI, MISP, Caddy or Elasticsearch.

v0.5 should make the runtime shape match the product shape:

- Add a unified gateway entrypoint.
- Add source registry and enabled-source orchestration.
- Keep OTX and MISP source isolation inside the gateway runtime.
- Keep source-specific standalone commands for debugging and bounded backfill.

## Product Value Assessment

The product thesis remains strong for CTI and hunting teams because NarrowCTI is
not trying to replace OpenCTI, MISP or feed providers. It sits in the ingestion
path and solves a practical operational gap: deciding what intelligence deserves
to enter the graph and why.

The strongest value signals already present are:

- Explainable ingest, drop, quarantine, skip, error and dry-run outcomes.
- Source-specific normalization with shared policy behavior.
- Persistent deduplication, source-scoped state and local artifact sighting records.
- Graph hygiene through layered deduplication before OpenCTI export.
- Decision audit evidence for analyst and operator review.
- Safe handling of high-volume MISP events through metadata-first guardrails.
- Provenance preservation for collector and original source context.
- STIX export into OpenCTI after curation rather than raw forwarding.
- Enterprise direction for actor, arsenal, ATT&CK, victimology, quarantine
  release and graph enrichment filters.

This is the right product posture for a professional gateway aimed at CTI,
threat hunting, SOC and platform teams.

## Documentation Coverage

The core product vision is documented, but v0.5 should keep making it more
explicit:

- `docs/product-foundation-v0.3.md` explains the product thesis and market
  position.
- `docs/multi-feed-expansion-v0.4.md` explains why MISP validates the gateway
  model.
- `docs/misp-validation-v0.4.md` records operational evidence and guardrails.
- `docs/gateway-runtime-v0.5.md` describes the unified gateway runtime target.
- `docs/enterprise-intelligence-gateway-v0.5.md` defines the enterprise filter,
  quarantine-release and graph-enrichment target.
- This document records the v0.5 continuity check against the product vision.

## v0.5 Quality Bar

v0.5 should not be considered successful only because one process can call two
sources. It should be considered successful when the product behavior feels like
a gateway:

- One runtime can orchestrate enabled sources.
- Source failure does not prevent other enabled sources from running.
- State, audit and guardrails remain source-scoped.
- Duplicate artifacts are skipped, correlated or enriched before they can pollute
  the OpenCTI graph.
- Operators can see per-source and aggregate outcomes.
- Dry-run mode remains trustworthy and non-exporting.
- Tests prove registry, orchestration, failure isolation and summaries.
- Documentation explains how the gateway improves CTI and hunting workflows.
- Enterprise backlog separates safe v0.5 documentation from future quarantine,
  entity extraction, ATT&CK resolver and graph enrichment implementation.

## Known Gaps To Preserve As Roadmap Items

- Scoring is still basic and must mature into source-specific weighting.
- The unified gateway entrypoint and source registry exist; they still need
  broader operational validation and richer value reporting.
- Aggregate run, decision-reason and artifact-correlation reports exist as
  local operator evidence for v0.5.
- OpenCTI-side deduplication lookup and initial local cross-source artifact
  correlation records are implemented. Analyst-facing enrichment, confidence
  uplift and reporting from those records remain roadmap items.
- There is no quarantine release workflow yet; today quarantine is recorded as
  a decision outcome, not a managed review queue.
- There is no administrative UI for policy tuning.
- Metrics are still operational summaries, not full customer-facing value
  reporting.
- MITRE mapping, Sigma generation and threat-to-detection workflows remain later
  product layers.
