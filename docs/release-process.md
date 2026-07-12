# Release Process

This document defines the public release process for NarrowCTI Community
Edition.

## Release Model

Official releases are published from `main` only:

```text
feature/* -> dev -> main -> version tag -> GitHub Release
```

A Git tag alone is not considered a complete public release. The GitHub Release
must include curated release notes, validation status and operator-facing
upgrade guidance.

## Pre-Release Checklist

- `VERSION` contains the target version.
- `README.md` points to the current release and public docs.
- `CHANGELOG.md` summarizes the release for public repository visitors.
- `docs/getting-started.md` and `docs/development-guide.md` are current.
- `docs/architecture.md`, `docs/deployment-operations.md`,
  `docs/configuration-reference.md`, `docs/curation-decision-reference.md` and
  `docs/environment-profiles.md` describe the current product behavior.
- `docs/container-images.md` describes the current image naming and tag policy.
- `docs/security-quality-gates.md` describes the current security, quality,
  image and DAST release policy.
- `docs/documentation-map.md` classifies public docs and development evidence.
- `docs/community-governance.md` describes contribution scope, permissions and
  maintainer review.
- `docs/release-vX.Y.Z.md` is product-facing and does not read like a lab log.
- Versioned docs such as `docs/deployment-operations-vX.Y.md` are kept only as
  release snapshots when needed.
- `CONTRIBUTING.md`, `SUPPORT.md`, `SECURITY.md` and `CODE_OF_CONDUCT.md` are
  present.
- `.github/` issue, pull request and CI templates are present.
- `.github/CODEOWNERS` and `.github/dependabot.yml` are present and reviewed.
- GitHub `main` and `dev` branch protection requires pull requests, maintainer
  review and applicable required checks; this must be verified in repository
  settings, not inferred from the source tree.
- The GitHub `release` environment requires maintainer approval and accepts
  deployments only from protected `main` or semantic version tags.
- No `.env`, local state, raw feed payloads, credentials or `AGENTS.md` are
  tracked.
- Private market positioning, competitive research and internal legal strategy
  are not part of the public product path.
- `.dockerignore` excludes local agent instructions, runtime state and local
  secrets from Docker build context.
- SAST, code-quality and dependency-audit workflows pass.
- Third-party GitHub Actions are pinned to reviewed full commit SHAs.
- Secret scanning and push protection are enabled, and release-history secret
  scan evidence is current.
- The exact release image passes vulnerability scanning and has a generated
  SBOM before publication.
- DAST passes against a disposable deployment when the release exposes an HTTP
  surface; otherwise the release evidence records why the gate is not
  applicable.
- Controlled OpenCTI end-to-end, upgrade and recovery validation pass.
- Full validation passes.

## Validation

Run unit validation:

```text
python -m unittest discover -s tests -v
```

Run image validation when Docker is available:

```text
powershell -ExecutionPolicy Bypass -File scripts\validate-release.ps1 -Image narrowcti/gateway:local
```

Security and quality policy, blocking thresholds and required evidence are
defined in `docs/security-quality-gates.md`.

## Source Archive Policy

GitHub exposes source archives for tags and releases. NarrowCTI uses
`.gitattributes` with `export-ignore` to keep archives focused on product
source and public docs.

The repository may keep development evidence, mapping research and validation
notes for transparency. Those files do not all need to be included in release
source archives.

Before publishing, inspect the archive contents:

```text
git archive --worktree-attributes --format=tar HEAD | tar -tf -
```

Confirm that archives exclude:

- `AGENTS.md`;
- `state/`;
- `.env` files;
- raw local evidence;
- development validation notes marked with `export-ignore`.

## GitHub Release Notes

Release notes should be concise and operator-facing:

- summary;
- highlights;
- upgrade notes;
- validation evidence;
- breaking changes, if any;
- known limitations;
- contributors.

Do not paste raw lab logs, customer data, local file paths or internal agent
instructions into release notes.

## Container Image Release

Official image publication follows the same release boundary as GitHub releases.

- Feature branches may build local images, but should not publish stable tags.
- Merges to `main` may publish `latest` and a `main` tracking tag.
- Tags matching `vX.Y.Z` publish immutable release tags such as `X.Y.Z`, `X.Y`,
  `X` and `sha-<short-sha>`.
- The image is built and scanned before publication; the publication job loads
  the exact scanned candidate and requires the protected `release` environment.
- Only the publication job receives `packages: write`; pull request workflows
  never receive registry credentials or release secrets.
- Release notes should mention the canonical image for the release, for example
  `ghcr.io/narrowcti/narrowcti-gateway:0.9.0` while v1.0 remains in
  development.
- Operators should pin `NARROWCTI_GATEWAY_IMAGE` to a release tag for stable
  deployments.
