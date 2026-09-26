# Security And Quality Gates

This document defines the security, quality and release evidence required for
NarrowCTI Community Edition.

## Product Rule

A successful build is not enough to publish a NarrowCTI release. Source,
dependencies, container image, runtime surface and release artifacts must pass
their applicable gates before a version tag and GitHub Release are created.

## Gate Matrix

| Gate | Purpose | Required evidence | Blocking policy |
| --- | --- | --- | --- |
| Unit and integration tests | Protect runtime and curation behavior | CI test result and release validation output | Any failure blocks release. |
| Code quality | Catch undefined names, unsafe patterns and maintainability regressions | Versioned linter configuration and successful CI job | Any configured rule failure blocks merge. |
| SAST | Detect source and workflow security flaws | CodeQL plus repository-owned Python security analysis | Unaccepted high or critical findings block release; lower findings require triage. |
| Actions supply chain | Prevent mutable workflow dependencies from changing under the same ref | Third-party Actions pinned to full commit SHAs and reviewed updates | An unpinned or unreviewed privileged Action blocks release hardening. |
| Dependency review | Detect vulnerable Python dependencies | Dependabot and a reproducible dependency audit | Unaccepted high or critical findings block release. |
| Secret protection | Prevent credentials from entering history | GitHub secret scanning/push protection and release-history scan evidence | Any verified secret blocks publication and requires rotation. |
| Container scan | Detect operating-system and Python package vulnerabilities in the final image | Scan of the exact image before publication | Unaccepted high or critical findings block image push. |
| SBOM | Record release image contents | Machine-readable SBOM attached to the workflow or release | Missing SBOM blocks the final release image. |
| DAST | Test an exposed HTTP surface at runtime | Baseline scan of a disposable analyst review API deployment | Required once the HTTP API exists; alerts require triage before release. |
| OpenCTI end-to-end | Validate claimed graph behavior | Controlled ingestion and relationship audit evidence | Missing evidence blocks the related release claim. |
| Upgrade and recovery | Protect operator continuity | Documented v0.9 to v1.0 upgrade and rollback/recovery result | Failure blocks release. |

Exceptions must identify the finding, affected component, reason, compensating
control, owner and expiration. A silent allow-list is not an accepted release
gate.

## v0.9 Opening Baseline

The initial v0.9 audit established:

- The versioned CI compiles modules and runs the unit suite.
- GitHub CodeQL default setup analyzes Python and GitHub Actions.
- CodeQL reported one medium workflow finding because `ci.yml` did not declare
  explicit permissions; v0.9 corrects the workflow to `contents: read`.
- Dependabot security updates are enabled and no open dependency alerts were
  present at the opening audit.
- GitHub secret scanning and push protection are enabled after the repository
  became public.
- Gitleaks `v8.30.1`, downloaded from the official release and verified against
  its published SHA-256 checksum, scanned 285 commits with no leak found.
- Local ignored OTX and MISP `.env` files contain credentials as expected; they
  are not tracked and must never be included in source archives or container
  build context.
- The container workflow now builds the exact candidate image, runs a smoke
  test, blocks on high or critical Trivy findings, generates a CycloneDX SBOM
  and authenticates to the registry only after those gates pass.
- The repository-owned security and quality workflow now runs Ruff, Bandit and
  `pip-audit` with pinned tool versions.
- The runtime dependency set now uses `pycti 7.260710.0`; the July 10, 2026
  dependency audit reported no known vulnerabilities.
- A version-scoped, fail-closed compatibility client was live-validated against
  OpenCTI `6.9.4`: two imports, zero rejected objects and exactly one Report.
- The v0.9 analyst HTTP API now has a dedicated DAST workflow. It creates an
  isolated API deployment, validates unauthenticated and authenticated access,
  runs OWASP ZAP `2.17.0` against its OpenAPI contract, archives JSON/HTML
  evidence and removes the deployment after every run.

This baseline is audit evidence, not a permanent claim. Every release must
refresh the checks against the release commit and image.

## DAST Boundary

DAST must run only against a disposable test deployment created for CI or an
isolated release-validation environment. It must not target production or a
shared OpenCTI/MISP lab containing operational data.

The release cannot close until the DAST workflow starts the disposable service,
waits for its health endpoint, proves protected endpoints reject missing
credentials, exercises authenticated access, scans the OpenAPI surface and
archives the result.

## Container Publication Order

The required order is:

```text
build exact image
  -> run image smoke validation
  -> scan vulnerabilities
  -> generate SBOM
  -> retain the exact candidate as a short-lived workflow artifact
  -> require the protected release environment
  -> authenticate to the registry with job-scoped package permission
  -> publish immutable and channel tags
```

An image must not be pushed first and scanned later.

The `Container Image` workflow keeps build and publication in separate jobs. The
build job runs for pull requests and has read-only repository permissions. The
publication job runs only for `main` or `v*` tags, downloads the exact scanned
candidate, requests the `release` environment and is the only job with
`packages: write`. The environment must be configured in GitHub with required
reviewers and branch/tag restrictions before it is considered a blocking gate.

GitHub Rulesets require job check names rather than workflow display names. The
current blocking job names are `Python tests`, `Python quality, SAST and
dependencies`, `Build, scan and publish gateway image` and `Analyst review API
OWASP ZAP`. A check should be selected only when its workflow runs for the
target pull request or release ref.

## Release Evidence

The release notes must record:

- commit and version;
- test and code-quality result;
- SAST and dependency result;
- secret-history scan result;
- image digest, scan result and SBOM location;
- DAST result or the explicit reason it is not applicable;
- OpenCTI end-to-end validation result;
- upgrade and recovery result;
- accepted findings and their expiration, if any.
