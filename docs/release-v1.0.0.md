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
