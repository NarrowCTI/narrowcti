# NarrowCTI v1.1.1 Release Notes

## Status

Status: release candidate.

The candidate is prepared on `release/prepare-v1.1.1` from the reviewed
`dev` branch. It becomes an official release only after the protected
`dev -> main` flow, required checks, the immutable `v1.1.1` tag and the GitHub
Release are complete. Until then, `v1.1.0` remains the latest published stable
release.

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

Until publication, keep using the approved `1.1.0` image or a deliberately
selected `main`/`latest` build for validation; those moving tags are not the
immutable `1.1.1` release.

## Validation Record

- Dependabot maintenance PR #74 was reviewed and merged into `dev`.
- Promotion PR #76 was reviewed and merged into `main` with a merge commit.
- Local validation for the dependency batch passed 544 unit tests, Ruff 0.16.6,
  Bandit and strict dependency audits, with the existing documented
  `PYSEC-2026-3447` exception retained.
- The protected `main` CI, Security and Quality, DAST and Container Image
  workflows passed for the promoted dependency batch; the approved image flow
  completed successfully. The final `v1.1.1` tag workflow must still publish
  the immutable release tags from the final release commit.

## Traceability

- Source branch: `release/prepare-v1.1.1`, created from `dev`.
- Dependency maintenance: PR [#74](https://github.com/NarrowCTI/narrowcti/pull/74).
- Promotion to `main`: PR [#76](https://github.com/NarrowCTI/narrowcti/pull/76).
- Main promotion commit: `d366da85a8bb6794dfcdf4ea0e487a5013de8994`.
- Git tag and release commit: to be recorded only after publication.

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
