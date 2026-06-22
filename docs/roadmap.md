# NarrowCTI Roadmap

## Branching And Release Model

NarrowCTI uses this flow:

```text
work branch -> dev -> main -> version tag
```

`dev` is the integration branch. `main` is the stable branch. Official versions
are marked with tags.

## v0.2.0 - Modular OTX Foundation

Status: released.

Purpose:

- Establish a modular OTX connector foundation.
- Split settings, OTX API access, processing, policy, state and STIX export.
- Validate the connector through Docker build, syntax checks and unit tests.
- Provide safe environment configuration examples.

## v0.3.0 - Product Foundation

Status: released.

Purpose:

- Define product positioning and commercial direction.
- Add initial proprietary licensing foundation.
- Track third-party dependency notices.
- Introduce a shared feed contract for multi-feed development.
- Add an OTX feed adapter as the reference contract implementation.
- Add structured decision audit records for operational review.
- Add per-query operational summaries for reviewed and handled candidates.
- Rename runtime identity from OTX-specific naming to NarrowCTI Gateway.
- Keep OTX as the reference adapter while preparing for additional feeds.

Expected outcomes:

- The project reads as NarrowCTI Gateway, not an OTX custom connector.
- Licensing and distribution boundaries are explicit.
- Future feed adapters have a stable contract to follow.
- The OTX feed can be normalized through the shared feed contract.
- Ingest, drop, quarantine and skip outcomes can be audited.
- Query execution can report reviewed, ingested, dropped, quarantined, skipped
  and failed candidates.

## v0.4.0 - Multi-Feed Expansion

Status: released.

Purpose:

- Add a second real feed, with MISP as the likely candidate.
- Prove that NarrowCTI Gateway is a reusable multi-feed intelligence gateway.
- Reuse the shared feed contract instead of duplicating OTX-specific logic.

Expected outcomes:

- At least two feeds use the same decision foundation.
- MISP payload and official connector behavior are validated against real local data.
- Feed-specific scoring inputs are normalized.
- MISP runtime foundation uses shared state, policy, audit and export paths.
- Local MISP dry-run validation proves search, enrichment, policy and audit
  without OpenCTI export.
- Bounded operational validation keeps OpenCTI, MISP, Caddy and Elasticsearch
  healthy after opt-in MISP runs.
- OpenCTI export remains consistent across sources.

## v0.5.0 - Gateway Runtime And Decision Engine

Status: released.

Purpose:

- Add the first unified NarrowCTI Gateway runtime.
- Orchestrate enabled sources through a source registry.
- Preserve source-level state, audit evidence, safety limits and failure
  isolation inside the unified runtime.
- Improve scoring beyond the current basic model.
- Protect OpenCTI graph hygiene through layered deduplication.
- Add source-specific weighting, policy reasons and decision evidence.
- Improve quarantine behavior, summaries and operator reporting.
- Document curation parameters so operators know which filters, thresholds and
  guardrails can be configured.
- Formalize enterprise curation domains for actor, arsenal, MITRE ATT&CK,
  victimology, quarantine release and graph enrichment.

Expected outcomes:

- One gateway container can run enabled sources such as OTX and MISP.
- Source-specific OTX and MISP runtimes remain available for debugging,
  validation and bounded backfill.
- MISP remains opt-in and guarded until repeated local validations prove stable
  queue, Elasticsearch and OpenCTI behavior.
- Every ingestion decision is explainable.
- Analysts can understand why intelligence was dropped, quarantined or ingested.
- The gateway can prioritize intelligence based on source, age, confidence,
  indicator type and operational relevance.
- Duplicate artifacts are treated as skips, known items or cross-source
  correlations instead of duplicate OpenCTI graph objects.
- Gateway design details are documented in `docs/gateway-runtime-v0.5.md`.
- Curation configuration is documented in
  `docs/configuration-reference-v0.5.md`.
- Product and architecture continuity are validated in
  `docs/product-architecture-validation-v0.5.md`.
- Enterprise gateway direction is documented in
  `docs/enterprise-intelligence-gateway-v0.5.md`.

## v0.6.0 - Quarantine And Enrichment Foundation

Purpose:

- Add operational metrics and clearer runtime reporting.
- Improve health checks.
- Produce value metrics such as reviewed, ingested, dropped and quarantined
  intelligence by source.
- Add a quarantine repository, CLI release workflow and release audit records.
- Start OTX enriched entity extraction for adversary, malware families,
  ATT&CK ids, industries, countries, TLP and references.
- Add a local MITRE ATT&CK cache and technique/tactic resolver.

Expected outcomes:

- Operators can tune the gateway safely.
- Customers can see measurable feed-noise reduction.
- Runtime behavior is easier to support.
- Quarantined intelligence can be reviewed, released, rejected or replayed
  without losing auditability.
- OTX and MITRE data begin to populate actor, arsenal, TTP and victimology
  context instead of only indicators and reports.

## v0.7.0 - Graph Enrichment And Enterprise Filters

Purpose:

- Export richer STIX objects and relationships for actors, intrusion sets,
  malware, tools, infrastructure, vulnerabilities, ATT&CK techniques,
  campaigns, sectors and locations.
- Add enterprise policy variables for actor, arsenal, ATT&CK, sector,
  geography, artifact criticality and graph state.
- Add confidence and provenance controls for relationships inferred from source
  fields.
- Expand graph hygiene from indicator deduplication into relationship and entity
  quality controls.

Expected outcomes:

- OpenCTI receives more useful context across Threats, Arsenal, Techniques,
  Entities, Locations, Observations and Analyses.
- Analysts can filter intake by monitored actors, sectors, tactics, malware
  families and infrastructure classes.
- Relationship evidence is auditable before it becomes graph knowledge.

## v0.8.0 - Analyst Review And Product Operations

Purpose:

- Add analyst review API/UI for quarantine, release and policy tuning.
- Prepare the reporting model for analyst-facing CTI curation reports.
- Provide a cleaner installation and upgrade path.
- Add deployment templates.
- Harden configuration defaults.
- Document customer installation procedures.
- Add technical license enforcement and feature gates by feed, environment or
  capability.

Expected outcomes:

- The product can be deployed repeatably outside the lab.
- Upgrade steps are clear.
- Customer onboarding becomes predictable.
- Product use can be controlled without requiring internet access.
- Support teams can identify customer and entitlement state.

## v1.0.0 - Commercial-Ready Release

Purpose:

- Ship a stable, documented and installable product.
- Finalize commercial license and support terms.
- Ship the enterprise curation engine with quarantine release, graph enrichment,
  explainable policy and measurable graph-quality outcomes.
- Provide enterprise CTI reporting that explains what was ingested, what was
  filtered, how policy was applied, which sources contributed, and how graph
  quality improved.
- Provide validated deployment guidance.
- Maintain a clear changelog and upgrade path.
- Carry the v1.0 market position: NarrowCTI as an OpenCTI-native CTI
  curation gateway.

Expected outcomes:

- NarrowCTI is ready for controlled commercial delivery.
- Product, engineering, licensing and operations are aligned.
- Operators and CTI teams can produce an enterprise-grade report from gateway
  evidence, decision audit, quarantine/release history and graph hygiene
  metrics.
- Release messaging is aligned with `docs/market-positioning-v1.0.md`.
