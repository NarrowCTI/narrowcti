# Container Images

This document defines the NarrowCTI Gateway container image policy.

## Image Name

The canonical Community Edition gateway image is:

```text
ghcr.io/narrowcti/narrowcti-gateway
```

Local development and lab validation can continue to use:

```text
narrowcti/gateway:local
```

The Compose deployment template reads the image from:

```text
NARROWCTI_GATEWAY_IMAGE
```

## Tag Policy

| Tag | When it is published | Stability |
| --- | --- | --- |
| `latest` | Push to `main` | Moving stable branch tag. |
| `main` | Push to `main` | Moving branch tag. |
| `0.8.0` | Git tag `v0.8.0` | Immutable release tag. |
| `0.8` | Git tag `v0.8.0` | Moving latest patch in minor line. |
| `0` | Git tag `v0.8.0` | Moving latest release in major line. |
| `sha-<short-sha>` | Every published build | Immutable traceability tag. |

Operators should pin production-like environments to an immutable release tag,
for example:

```text
NARROWCTI_GATEWAY_IMAGE=ghcr.io/narrowcti/narrowcti-gateway:0.8.0
```

Use `latest` only when intentionally tracking the newest stable `main` build.

## Local Build

```powershell
docker build -f Dockerfile.gateway -t narrowcti/gateway:local .
```

Then validate:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\validate-release.ps1 -Image narrowcti/gateway:local
```

## Publish Workflow

The GitHub Actions workflow in `.github/workflows/container-image.yml` publishes
to GitHub Container Registry on `main` and semantic version tags.

Publication requires:

- repository write permission to GitHub Packages;
- a clean Docker build from `Dockerfile.gateway`;
- CI validation kept green before creating a release tag.

The v0.9 publication gate uses this order for the exact candidate image:

```text
build -> smoke test -> Trivy scan -> CycloneDX SBOM -> registry login -> push
```

Pull requests and `dev` builds exercise the build, smoke, scan and SBOM path but
do not publish stable image tags. `main` and version tags publish only after the
same job has passed the image gates. See `docs/security-quality-gates.md` for
the blocking policy.

Docker Hub mirroring can be added later with explicit repository secrets and the
same tag policy. Until then, GHCR is the canonical public registry.
