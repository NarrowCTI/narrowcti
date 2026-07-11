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

- Define product positioning and open source direction.
- Add Apache-2.0 licensing foundation.
- Track third-party dependency notices.
- Introduce a shared feed contract for multi-feed development.
- Add an OTX feed adapter as the reference contract implementation.
- Add structured decision audit records for operational review.
- Add per-query operational summaries for reviewed and handled candidates.
- Rename runtime identity from OTX-specific naming to NarrowCTI Gateway.
- Keep OTX as the reference adapter while preparing for additional feeds.

Expected outcomes:

- The project reads as NarrowCTI Gateway, not an OTX custom connector.
- Open source distribution boundaries are explicit.
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
  `docs/configuration-reference-v0.6.md`, extending the base v0.5 reference.
- Product and architecture continuity are validated in
  `docs/product-architecture-validation-v0.5.md`.
- Enterprise gateway direction is documented in
  `docs/enterprise-intelligence-gateway-v0.5.md`.

## v0.6.0 - Quarantine And Enrichment Foundation

Status: released.

Release notes:

- `docs/release-v0.6.0.md`

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

Status: closed as the graph enrichment and enterprise-filter foundation.

Detailed design:

- `docs/architecture-v0.7.md`
- `docs/graph-enrichment-v0.7.md`
- `docs/mitre-curation-architecture-v0.7.md`
- `docs/contextual-scoring-reference-v0.7.md`
- `docs/source-ingestion-modes-v0.7.md`
- `docs/operational-validation-v0.7.md`

Development notes:

- `docs/release-v0.7.0.md`

Purpose:

- Export richer STIX objects and relationships for actors, intrusion sets,
  malware, tools, infrastructure, vulnerabilities, ATT&CK techniques,
  campaigns, sectors and locations.
- Add enterprise policy variables for actor, arsenal, ATT&CK, sector,
  geography, artifact criticality and graph state.
- Add confidence and provenance controls for relationships inferred from source
  fields.
- Add contextual scoring design based on graph evidence for threat, arsenal,
  sector, geography, TTP and author relevance.
- Document direct source, MISP collector and hybrid ingestion modes so
  NarrowCTI can be deployed with or without MISP.
- Expand graph hygiene from indicator deduplication into relationship and entity
  quality controls.

Expected outcomes:

- OpenCTI receives more useful context across Threats, Arsenal, Techniques,
  Entities, Locations, Observations and Analyses.
- Analysts can filter intake by monitored actors, sectors, tactics, malware
  families and infrastructure classes.
- Relationship evidence is auditable before it becomes graph knowledge.
- Score decisions can account for high-value graph context without hiding the
  base score or bypassing policy.
- The product architecture clearly supports organizations that use MISP and
  organizations that need NarrowCTI to ingest direct sources into OpenCTI.
- Source metadata validation is broad enough for OTX, MISP and MITRE evidence
  to enrich OpenCTI graph views with high-signal CTI context instead of only
  reports and indicators.
- The MITRE architecture is explicit: the official MITRE connector should own
  canonical ATT&CK loading in OpenCTI, while NarrowCTI uses MITRE as curation
  context for OTX, MISP and future feeds.

## v0.8.0 - Analyst Review And Product Operations

Status: released.

Detailed design and validation:

- `docs/graph-promotion-v0.8.md`
- `docs/operational-validation-v0.8.md`
- `docs/deployment-operations-v0.8.md`
- `docs/analyst-review-v0.8.md`
- `docs/curation-reporting-v0.8.md`
- `docs/support-diagnostics-v0.8.md`
- `docs/infrastructure-correlation-v0.8.md`
- `docs/opencti-coverage-matrix-v0.8.md`

Purpose:

- Add analyst review API/UI for quarantine, release and policy tuning. v0.8
  starts with an internal analyst review service used by the CLI; HTTP/UI
  surfaces remain future work.
- Prepare the reporting model for analyst-facing CTI curation reports. v0.8
  starts with a read-only curation report model over gateway, decision,
  quarantine and graph-readiness evidence.
- Provide a cleaner installation and upgrade path.
- Add read-only support diagnostics for preflight, evidence inventory and
  curation posture. v0.8 includes support and external redaction profiles for
  shareable diagnostic snapshots and customer-safe report delivery.
- Add deployment templates. v0.8 starts with a safe gateway compose template
  and env example for existing OpenCTI Docker networks.
- Add controlled graph promotion with OpenCTI entity/relationship lookup,
  including canonical ATT&CK lookup by external id or STIX id.
- Validate the Infrastructure/ASN/IP correlation model so NarrowCTI can enrich
  actor and malware infrastructure with IP, CIDR and ASN relationships without
  turning raw IOCs into low-context graph entities.
- Add MISP graph-only replay for improved curation mappings so already-known
  events can add missing semantic edges without replaying indicator bundles.
  The v0.8 gate is opt-in through `NARROWCTI_GRAPH_REPLAY_ON_ARTIFACT_DEDUP`
  or `MISP_GRAPH_REPLAY_ON_ARTIFACT_DEDUP` and remains bounded to export-mode
  validation.
- Add an operational validation checklist for v0.8 graph lookup evidence,
  OpenCTI duplicate review and local resource posture.
- Harden configuration defaults.
- Document customer installation procedures.
- Add preflight-visible capability inventory by feed, environment or capability
  declaration. v0.8 keeps the core open source and does not add runtime
  commercial activation blocking.
- Maintain a tab-level OpenCTI coverage matrix so export support, validation
  status, held-by-design objects and backlog gaps remain visible as graph
  promotion expands.

Expected outcomes:

- The product can be deployed repeatably outside the lab.
- Upgrade steps are clear.
- Customer onboarding becomes predictable.
- Product use can be validated without requiring internet access.
- Operators and support teams can identify capability posture and configuration
  drift.

## v0.9.0 - Analyst Operations And Graph Quality

Status: in development.

Detailed design and release tracking:

- `docs/architecture-v0.9.md`
- `docs/release-v0.9.0.md`

Purpose:

- Expose the existing analyst review service through a governed HTTP API with
  authentication, authorization and audit continuity.
- Improve canonical entity and relationship lookup, graph deduplication and
  post-export state handling before the v1.0 production-ready release.
- Close the highest-value OpenCTI coverage gaps for Diamond, victimology,
  Timeline, Kill Chain and source-backed semantic relationships.
- Validate richer ASN, CIDR, IP, infrastructure, actor, arsenal, ATT&CK and
  victimology context without promoting weak source inference.
- Keep governed direct source onboarding ready for the next adapter. MalwareBazaar
  is the first v1.0 candidate and URLHaus is the next infrastructure-oriented
  priority; neither is claimed as a v0.9 runtime feature without real-data
  validation.
- Keep Community Edition reporting intentionally simple: operational totals,
  decisions, source contribution and graph-quality indicators. Advanced
  enterprise reporting remains outside the v0.9 Community scope.
- Make SAST, applicable DAST, code quality, dependency review and container
  image scanning explicit release gates.

Expected outcomes:

- Analysts can review quarantine records and perform release, partial release
  or rejection through one audited service boundary.
- Repeated ingestion converges on canonical OpenCTI objects and relationships
  with measurable duplicate prevention.
- Source-backed OpenCTI graph views receive richer and safer adversary,
  capability, infrastructure and victimology context.
- The source-onboarding boundary remains governed by the shared candidate,
  policy, audit and export contracts, ready for the first v1.0 direct adapter.
- Operators receive a concise operational report without exposing a future
  advanced enterprise reporting capability prematurely.
- The release cannot be published until CI/CD security, quality, image and
  end-to-end validation gates pass.

## v1.0.0 - Open Source Production-Ready Release

Purpose:

- Ship a stable, documented and installable product.
- Finalize open source release posture and optional services/support guidance.
- Ship the enterprise curation engine with quarantine release, graph enrichment,
  contextual scoring, explainable policy and measurable graph-quality outcomes.
- Provide enterprise CTI reporting that explains what was ingested, what was
  filtered, how policy was applied, which sources contributed, and how graph
  quality improved.
- Provide validated deployment guidance.
- Maintain a clear changelog and upgrade path.
- Carry the v1.0 market position: NarrowCTI as an OpenCTI-native CTI
  curation gateway.

Expected outcomes:

- NarrowCTI is ready for controlled open source production adoption.
- Product, engineering, licensing and operations are aligned around the
  Apache-2.0 core.
- Operators and CTI teams can produce an enterprise-grade report from gateway
  evidence, decision audit, quarantine/release history and graph hygiene
  metrics.
- Release messaging is aligned with `docs/market-positioning-v1.0.md`.

## Post-v1.0 - ML-Assisted Curation

Detailed design:

- `docs/post-v1-ml-roadmap.md`

Purpose:

- Add an optional ML-assisted curation layer after the deterministic v1.0
  engine is stable.
- Use ML to suggest aliases, related entities, relationship candidates,
  priority ranking, semantic deduplication and weak-signal enrichment.
- Learn from decision audit, quarantine release, rejection and graph-quality
  outcomes without bypassing policy controls.
- Keep ML suggestions explainable, versioned, source-scoped, auditable and
  reversible.

Expected outcomes:

- Analysts get better prioritization and entity/relationship suggestions.
- OpenCTI receives richer graph context only after NarrowCTI policy and
  governance checks.
- ML improves scale and discovery while deterministic curation remains the
  source of truth for safe promotion.
- NarrowCTI evolves from an explainable curation gateway into an adaptive CTI
  curation gateway without becoming a black-box ingestion engine.
