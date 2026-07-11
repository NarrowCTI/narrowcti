# NarrowCTI v0.9.0 Release Notes

## Status

Status: release candidate.

v0.9 is the analyst operations and graph-quality release. These notes must be
updated as each capability is implemented and validated; planned work must not
be presented as released behavior.

## Purpose

The release turns the v0.8 graph-promotion and analyst-review foundations into
governed operator capabilities while keeping graph hygiene, provenance and
explainability as the primary product boundary.

Detailed design is tracked in `docs/architecture-v0.9.md`.

## Planned Scope

- Governed analyst review HTTP API over `AnalystReviewService`.
- Authentication, authorization and audit continuity for review transitions.
- Canonical entity and relationship lookup improvements.
- Graph deduplication and post-export state hardening.
- Controlled Infrastructure victimology and broader Diamond validation.
- Timeline, Kill Chain and priority OpenCTI coverage validation.
- Governed source onboarding contracts, with new direct adapters deferred until
  source-specific real-data evidence is available.
- Simple Community operational and graph-quality reporting.
- CI/CD security and quality release gates.
- Upgrade, recovery and controlled end-to-end validation from v0.8.

## Reporting Scope

The v0.9 Community report remains operational and concise. It should explain:

- what was reviewed, ingested, dropped, quarantined, skipped or failed;
- which sources contributed;
- which policy reasons shaped the result;
- how many graph objects or relationships were reused, held or promoted;
- whether the run and graph-quality posture passed the configured checks.

Advanced enterprise report packs, executive narratives, tenant-specific
templates and polished PDF delivery are deferred to a future separately scoped
capability.

## Implemented Foundation

- Added versioned Ruff, Bandit and `pip-audit` gates.
- Added exact-image smoke testing, Trivy scanning and CycloneDX SBOM generation
  before registry authentication or publication.
- Upgraded the pinned OpenCTI client dependency to `pycti 7.260710.0` with no
  known vulnerabilities in the opening v0.9 dependency audit.
- Added a centralized, fail-closed OpenCTI `6.9.x` compatibility boundary for
  empty GraphQL fields introduced by `pycti 7`.
- Live-validated OpenCTI `6.9.4` authentication and idempotent Report import:
  two imports, zero rejected objects and exactly one resulting Report.
- Passed 503 tests in the rebuilt v0.9 development image.
- Added the authenticated analyst review API with `reader`, `reviewer`,
  `exporter` and `admin` roles, hashed bearer credentials, strict request
  models, protected raw snapshots and disabled-by-default real export.
- Added an isolated `review-api` Compose profile bound to host loopback with a
  read-only root filesystem, dropped capabilities and healthcheck.
- Added a disposable OWASP ZAP `2.17.0` OpenAPI DAST workflow with temporary
  authentication, boundary checks, archived evidence and guaranteed cleanup.

Compatibility behavior and validation commands are documented in
`docs/opencti-compatibility.md`.
Analyst API security and operation are documented in
`docs/analyst-review-api.md`.

## Candidate Validation Evidence

The current v0.9 candidate was validated locally on July 10, 2026 with:

- 503 passing unit and integration tests in the rebuilt runtime image;
- runtime module smoke imports passing;
- Ruff and Bandit passing;
- `pip-audit` reporting no known vulnerabilities for runtime and development
  requirements;
- Trivy HIGH/CRITICAL image scan passing for digest
  `sha256:498bb08200e7e9fc9e62b2a723497ce9ae7d77adf68b4248711aeb0f2fa4c49f`;
- CycloneDX SBOM generated for that same image digest;
- live OpenCTI 6.9.4 validation with two imports, zero rejected objects and
  exactly one deterministic Report;
- disposable API boundary validation with `401` unauthenticated and `200`
  authenticated responses.
- GitHub Actions `CI`, `Security and Quality`, `Container Image` and `DAST`
  workflows passed for commit `5d665ad`.

Workflow evidence:

- [CI](https://github.com/NarrowCTI/narrowcti/actions/runs/29136096186)
- [Security and Quality](https://github.com/NarrowCTI/narrowcti/actions/runs/29136096216)
- [Container Image](https://github.com/NarrowCTI/narrowcti/actions/runs/29136096202)
- [DAST](https://github.com/NarrowCTI/narrowcti/actions/runs/29136096182)

The full OWASP ZAP execution passed in CI. These notes must not be changed to
`Released` until the final merge, tag and GitHub Release checks are approved.

## Mandatory Release Gates

- Full unit and integration validation passes.
- SAST passes with no unaccepted blocking finding.
- Code-quality checks pass.
- Dependency vulnerability review passes according to the documented policy.
- The release image is built, scanned and accompanied by an inventory or SBOM.
- DAST passes against the disposable analyst API deployment once the API is
  implemented.
- Controlled OpenCTI ingestion validates every graph claim in the release.
- Upgrade and recovery from v0.8 are documented and validated.
- Public documentation, changelog, image tags and GitHub Release notes are
  current.

## Release Boundary

`VERSION` is now `v0.9.0` on the release-candidate branch. The public flow is
ready but has not been executed yet:

```text
feature/* -> dev -> main -> v0.9.0 tag -> GitHub Release
```

## Non-Goals

- Advanced enterprise reporting.
- ML-assisted curation.
- Unreviewed automatic quarantine release.
- Weak or speculative graph inference.
- Broad implementation of every candidate source adapter.
