# NarrowCTI Architecture - v0.9.0

## Status

Status: in development.

v0.9 preserves the product boundary established from v0.2 through v0.8:
NarrowCTI is the curation and decision gateway, while OpenCTI remains the
knowledge graph, investigation and visualization platform.

## Release Theme

v0.9 is the bridge between controlled graph promotion in v0.8 and the
production-ready Community Edition target in v1.0.

```text
OTX / MISP / governed direct sources
  -> source adapters
  -> normalization and source evidence
  -> scoring, policy, deduplication and quarantine
  -> analyst review and controlled release
  -> canonical OpenCTI lookup and graph-quality checks
  -> STIX/OpenCTI export
  -> audit and simple operational reporting
```

## Architecture Workstreams

### Analyst Operations

- Reuse `AnalystReviewService` as the single transition boundary for CLI and
  HTTP operations.
- Add authenticated and authorized read, release, partial-release, reject,
  preview and replay operations.
- Preserve mandatory reasons, immutable audit records and source evidence.
- Do not let an API or future UI bypass quarantine transition policy.

The v0.9 HTTP foundation implements this boundary with hashed bearer
credentials, role-based permissions, authenticated reviewer identity, raw
snapshot protection and a disabled-by-default real export gate. The public
operation contract is `docs/analyst-review-api.md`.

### Graph Quality

- Resolve canonical entities and relationships before graph creation.
- Keep deterministic identifiers and source-aware aliases as convergence tools.
- Mark export state only after OpenCTI confirms successful import or native
  object creation.
- Measure duplicate prevention, canonical reuse, held relationships and graph
  promotion outcomes.
- Keep weak attribution and ambiguous multi-anchor evidence in Report, Note,
  quarantine or audit context.

### OpenCTI Coverage

- Validate Infrastructure victimology before enabling broad semantic export.
- Expand real source validation for Campaign, Organization, deeper Locations,
  Channels, Events, Security Platforms, Systems, Individuals and Sightings.
- Validate Diamond quadrants, Timeline and Kill Chain in OpenCTI API and UI
  views with controlled real payloads.
- Continue detection-rule compatibility validation without forcing unsupported
  rule formats into native Indicator objects.

### Source Expansion

- Add direct adapters only through the shared feed candidate and source
  onboarding contracts.
- Prioritize MalwareBazaar for malware family, sample, Artifact and hash
  context; keep URLHaus as the next infrastructure-oriented source.
- Preserve the original logical source in the OpenCTI author convention:
  `<Source display name> via NarrowCTI`.

### Reporting Boundary

The v0.9 Community report remains deliberately small. It may summarize run
outcomes, source contribution, decision reasons, quarantine posture,
deduplication and graph-quality indicators.

Advanced executive narratives, configurable enterprise templates, PDF packs,
tenant-specific presentation and leadership reporting are not v0.9 Community
release requirements. They remain reserved for a future separately scoped
capability without weakening the open source curation core.

## Release Security And Quality Gates

The v0.9 release is blocked unless all applicable gates pass:

- unit and integration tests;
- code compilation and deterministic release validation;
- code quality and lint checks;
- SAST and dependency vulnerability scanning;
- secret protection and repository hygiene checks;
- container image build and vulnerability scan;
- SBOM or equivalent dependency inventory for the release image;
- DAST against the analyst HTTP API once that surface exists;
- controlled OpenCTI end-to-end ingestion and graph validation;
- upgrade and recovery validation from the latest v0.8 release.

The authoritative policy and evidence contract is
`docs/security-quality-gates.md`.

The version-scoped OpenCTI client boundary and compatibility evidence are
defined in `docs/opencti-compatibility.md`.

DAST must target a disposable test deployment. It must not run against a
production OpenCTI, MISP or NarrowCTI environment.

## Non-Goals

- Machine-learning-driven promotion.
- Automatic quarantine release without explicit policy or analyst action.
- Guessing relationships that are not supported by source evidence.
- Replacing the official MITRE ATT&CK connector as the canonical ATT&CK loader.
- Implementing every future source adapter in one release.
- Shipping the future advanced enterprise reporting product in Community v0.9.

## Definition Of Done

- The v0.9 scope and configuration are documented in public product docs.
- Every new API transition is authorized, auditable and covered by tests.
- Graph-quality changes include duplicate and relationship regression coverage.
- At least one new direct source follows the governed adapter contract.
- Real OpenCTI validation covers the promoted graph paths claimed by the
  release.
- CI/CD security and quality gates pass before merge to `main`, version tag and
  GitHub Release publication.
