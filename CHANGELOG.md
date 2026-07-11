# Changelog

All notable NarrowCTI Community Edition changes are summarized here.

Detailed operator-facing release notes remain in `docs/release-v*.md`.

## v0.9.0 - Release Candidate

Analyst operations and graph-quality release candidate. All four GitHub Actions
workflows passed for commit `5d665ad`; merge, tag and publication remain
maintainer-controlled.

- Formalizes the governed analyst review API, graph-quality hardening and the
  governed source-onboarding boundary. A new direct adapter remains a v1.0
  backlog item until it has source-specific validation evidence.
- Keeps Community reporting operational and concise while reserving advanced
  enterprise reporting for a future separately scoped capability.
- Makes SAST, applicable DAST, code quality, dependency review and container
  image scanning mandatory release gates.
- Pins `pycti 7.260710.0` and adds a centralized, fail-closed compatibility
  boundary for live-validated OpenCTI `6.9.x` ingestion.
- Adds an authenticated, role-governed analyst review API and isolated Compose
  profile with real export disabled by default.
- Adds a blocking, disposable OWASP ZAP OpenAPI DAST workflow for the review
  API.
- Separates OpenCTI entity reuse from directed relationship deduplication and
  requires an exact existing edge and relationship type before suppressing a
  graph relationship export.

See `docs/release-v0.9.0.md`.

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
