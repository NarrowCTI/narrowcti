# NarrowCTI v1.0.0 Release Notes

## Status

Status: in development.

These notes distinguish planned, implemented and validated behavior. Nothing in
the planned sections should be presented as released until all blocking gates
pass on the final release commit.

## Release Theme

v1.0 is the production-ready Community Edition release for the existing OTX and
MISP curation gateway. It prioritizes deterministic decision quality, graph
hygiene, operational resilience and reproducible deployment over source-count
expansion.

## Frozen Scope

- Validated sources: OTX and MISP.
- Canonical context: MITRE ATT&CK through the official OpenCTI baseline and
  NarrowCTI resolution.
- No new direct source adapter.
- MalwareBazaar and URLHaus deferred to v1.1.

## Validation Record

The release remains unpublished while the final evidence is reviewed. The
following controlled validations were executed against the local OpenCTI 6.9
and MISP environments on 2026-07-12:

- OTX real ingestion of `LummaC2 Stealer`: `ingested=1`, `errors=0`; the
  repeat run produced `skipped=2` through source state and artifact
  deduplication.
- MISP real ingestion of event `1649` with Sigma content: `ingested=1`,
  `errors=0`; the export recorded 51 graph entities and 84 relationships,
  including 35 ATT&CK relationships. The repeat run produced `skipped=1`.
- MISP matrix validation of events `5505`, `7`, `1578`, `1150`, `1534` and
  `5559`: six events reviewed, two quarantined by policy, four skipped as
  already-known artifacts, and zero transport or export errors.
- OpenCTI relationship audits confirmed Kill Chain coverage for Lumma Stealer
  and Sandworm Team. The infrastructure path confirmed
  `178.21.14.0/23 belongs-to AS49352` and retained the report relationship.
- OpenCTI 6.9 partial-bundle failures are fail-closed: permanent worker import
  errors are surfaced as ingestion errors and are not marked as imported.
- The complete test suite passed with 536 tests. Ruff, Bandit and both strict
  `pip-audit` checks passed with no known vulnerabilities.

The repository CI/CD gates are present and versioned: `security-quality.yml`
runs Ruff, Bandit and `pip-audit`; `dast.yml` runs the disposable review API
through OWASP ZAP; and `container-image.yml` builds, scans with Trivy,
generates an SBOM and publishes only the approved image refs. The local
Ruff/Bandit/dependency gates passed. A local Trivy run was attempted through a
socket-free image tar, but the vulnerability database download stalled before
analysis; this is not treated as a passing image scan and the GitHub workflow
must provide the authoritative result before publication.

## Evidence Boundaries

The audits distinguish absent source evidence from a failed export. Lumma
Stealer and the infrastructure object correctly expose the relationships that
their source data supports; they do not receive invented actor, victimology or
Kill Chain relationships. Sandworm carries broad ATT&CK context, while the
real MISP Dust Storm campaign currently has only its Report relationship in
OpenCTI. Campaign propagation and infrastructure victimology propagation
remain evidence-driven follow-up work, not reasons to fabricate graph data.

MITRE and CVE remain official OpenCTI connector paths in the v1.0 frozen
architecture, rather than new direct NarrowCTI adapters. Their connector
health is therefore validated separately from the OTX/MISP gateway ingestion
contract.
- Concise Community operational reporting.
- No ML, automatic quarantine release, advanced report packs or full browser
  administration UI.

## Planned Capabilities

- Contextual scoring with `off`, `shadow` and `enforce` modes.
- Visible scoring configuration and complete decision-effect evidence.
- Priority Diamond, victimology, Timeline and Kill Chain validation.
- Runtime retry, backoff, timeout, checkpoint and health controls.
- Audit-ready Community report for decisions, sources and graph quality.
- Clean installation, v0.9 upgrade, backup/restore and restart recovery.
- Complete CI, SAST, DAST, dependency, image and SBOM release gates.

## Implemented Foundation

- Added contextual scoring `off`, `shadow` and `enforce` modes to OTX and MISP.
- Added validated category-impact configuration, maximum-impact bounds,
  preflight visibility and decision audit fields for configured versus applied
  scoring behavior.
- Kept `shadow` as the default and preserved TLP, hard age cutoff, graph holds
  and indicator-type controls as independent blocking policy.
- Unified OTX/MISP gateway runtime and source contracts.
- Base scoring, explicit policy, TLP, data-age and indicator-type controls.
- Source and artifact deduplication.
- Quarantine repository and governed CLI/API analyst review.
- Canonical OpenCTI entity and exact directed relationship lookup.
- Atomic checkpoint and deduplication-state writes for restart-safe recovery.
- Bounded OTX and MISP retry backoff with independently configurable jitter.
- Graph-safe STIX/OpenCTI export and source-aware author naming.
- Operational, decision, curation and support reports in machine-readable and
  operator-readable formats.
- Public Community governance, release and security documentation.

## Validation Status

Validation evidence will be added only after each capability passes its local,
container and controlled OpenCTI checks. The final release requires all gates
defined in `docs/architecture-v1.0.md` and `docs/security-quality-gates.md`.

Source-dependent gaps such as PCRE or OTX ASN/netblock real-feed examples may be
recorded as contract-tested but not real-feed validated when the available
sources do not provide the required shape.

Local container validation on July 11, 2026 passed:

- 516 unit and integration tests;
- Python compilation for connectors, core, exporters, gateway and tests;
- Ruff checks across the repository;
- Bandit with the same medium-severity blocking threshold used by CI.

GitHub Actions and controlled OpenCTI runtime evidence remain pending for this
development branch.

## Upgrade Boundary

The supported upgrade path is:

```text
v0.9.0 -> v1.0.0
```

Upgrade validation must preserve quarantine records, release audit, decision
audit, deduplication state and source checkpoints. Rollback instructions must
be documented before publication.

## Release Boundary

The public flow remains:

```text
feature/v1.0-production-ready -> dev -> main -> v1.0.0 tag -> GitHub Release
```

No tag or GitHub Release should be created while these notes have status
`in development` or while a blocking validation gate is incomplete.
