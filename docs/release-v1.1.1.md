# NarrowCTI v1.1.1 Release Notes

## Status

Status: released.

NarrowCTI v1.1.1 was promoted through the protected `dev -> main` flow,
validated, tagged immutably and published as a GitHub Release on 2026-09-14.

## Release Theme

v1.1.1 is a dependency-maintenance patch for the v1.1 Community Edition line.
It updates the OpenCTI client and Ruff to the reviewed versions without changing
application behavior, graph contracts, state format or the environment contract.

## Changes

- Upgrade `pycti` from `7.260828.0` to `7.260904.0`.
- Upgrade Ruff from `0.16.5` to `0.16.6`.
- Keep the security-quality audit rationale aligned with the current pycti
  packaging constraint and its explicitly documented exception boundary.
- Preserve the v1.1.0 detection-relationship, provenance, audit, dry-run,
  quarantine, graph and OpenCTI compatibility behavior.

## Upgrade Guidance

No environment-variable migration, state reset, graph backfill or data-schema
migration is required. Existing deployments can be upgraded in place after
publication. Production-like deployments should be pinned to the immutable
release image only after the tag and protected image publication complete:

```text
NARROWCTI_GATEWAY_IMAGE=ghcr.io/narrowcti/narrowcti-gateway:1.1.1
```

The published immutable image is `1.1.1`; production deployments should remain
pinned to that tag. The moving `latest` and `main` tags point to the approved
main build but should be used only when intentionally tracking the moving line.

## Validation Record

- Dependabot maintenance PR #74 was reviewed and merged into `dev`.
- Promotion PR #76 was reviewed and merged into `main` with a merge commit.
- Release promotion PR [#78](https://github.com/NarrowCTI/narrowcti/pull/78) was
  reviewed and merged into `main`.
- Local validation for the dependency batch passed 544 unit tests, Ruff 0.16.6,
  Bandit and strict dependency audits, with the existing documented
  `PYSEC-2026-3447` exception retained.
- [CI run 34907559398](https://github.com/NarrowCTI/narrowcti/actions/runs/34907559398),
  [Security and Quality run 34907559445](https://github.com/NarrowCTI/narrowcti/actions/runs/34907559445),
  [DAST run 34907559397](https://github.com/NarrowCTI/narrowcti/actions/runs/34907559397)
  and the code-quality gates passed on the final main promotion.
- [Container Image run 34907559606](https://github.com/NarrowCTI/narrowcti/actions/runs/34907559606)
  built, smoke-tested, scanned, generated the SBOM and published the approved
  image after release-environment approval.
- The published `latest`, `main` and `sha-ebef338` tags resolve to
  `sha256:70509ae9509182bcfee29fe143626d9743e997891ff96a8170df09a9bee84efe`.

## Traceability

- Source branch: `release/prepare-v1.1.1`, created from `dev`.
- Dependency maintenance: PR [#74](https://github.com/NarrowCTI/narrowcti/pull/74).
- Promotion to `main`: PR [#76](https://github.com/NarrowCTI/narrowcti/pull/76).
- Release promotion: PR [#78](https://github.com/NarrowCTI/narrowcti/pull/78).
- Main promotion commit: `ebef338efbc0dce743c80d91ea3b55d079d8c69c`.
- Git tag: `v1.1.1`.
- Release commit: final `main` commit containing this release documentation.

The intended release path remains:

```text
release/prepare-v1.1.1 -> dev -> main -> v1.1.1 tag -> GitHub Release
```

## Known Boundaries

- This release does not add a new source adapter or MITRE D3FEND connector.
- The setuptools advisory remains constrained by the pycti `~=82.0.0` contract;
  forcing an incompatible version would not be a safe dependency fix.
- Historical OpenCTI objects are not rewritten automatically by this patch.

## License

NarrowCTI Community Edition remains distributed under the Apache License 2.0.
