# Changelog

All notable NarrowCTI Community Edition changes are summarized here.

Detailed operator-facing release notes remain in `docs/release-v*.md`.

## v0.8.0

Graph promotion, analyst review and product operations release.

- Adds read-only OpenCTI graph lookup for canonical object reuse before graph
  promotion.
- Adds controlled graph promotion readiness for ATT&CK, locations,
  infrastructure, autonomous systems and supported observables.
- Adds source-backed graph hygiene for OTX and MISP so enrichment can promote
  entities and relationships only when provenance supports them.
- Adds analyst review, curation reporting, support diagnostics and deployment
  operations documentation.
- Adds OpenCTI coverage matrix and rules-engine alignment for pre-ingestion
  curation versus post-ingestion inference.

See `docs/release-v0.8.0.md`.

## v0.7.0

Graph enrichment and enterprise-filter foundation.

- Adds graph evidence and graph candidate models.
- Adds audit-first graph planning for actors, intrusion sets, malware, tools,
  vulnerabilities, sectors, locations, techniques, infrastructure and
  relationships.
- Adds MITRE ATT&CK curation architecture: the official MITRE connector remains
  the canonical ATT&CK loader, while NarrowCTI uses ATT&CK as enrichment
  context for source-backed intelligence.
- Adds source metadata validation and official connector mapping references for
  MISP and OTX compatibility.
- Adds contextual scoring, source onboarding and ingestion mode documentation.

See `docs/release-v0.7.0.md`.

## v0.6.0

Quarantine and enrichment foundation.

- Adds reviewable quarantine storage and CLI workflows.
- Adds release, reject, partial-release and replay audit evidence.
- Adds OTX entity extraction and local MITRE ATT&CK cache resolution.
- Adds preflight and reporting coverage for quarantine, release audit and MITRE
  resolver posture.

See `docs/release-v0.6.0.md`.

## v0.5.0

Unified gateway runtime and decision engine release.

- Adds the `gateway.connector` runtime and source registry.
- Adds the `NARROWCTI_*` configuration namespace.
- Adds source failure isolation, aggregate run summaries and operational
  reporting.
- Adds gateway image support through `Dockerfile.gateway`.
- Adds local artifact correlation and optional OpenCTI indicator lookup
  posture.

See `docs/release-v0.5.0.md`.

## v0.4.0

Multi-feed expansion release.

- Adds the MISP adapter foundation alongside the OTX reference adapter.
- Adds MISP guardrails for event volume, attribute count, exported IoCs, date
  filters, tag filters and published-only imports.
- Adds dry-run and run-once execution for controlled MISP validation.
- Preserves collector and original-source provenance when available.

See `docs/release-v0.4.0.md`.
