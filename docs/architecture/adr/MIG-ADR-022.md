# MIG-ADR-022 — Package-based runtime and deployment portability

## Status

Accepted for W7 / PR-20.

## Context

The Community runtime currently executes from a dual-root source checkout,
relies on `PYTHONPATH`, and requires an externally managed Docker network even
when OpenCTI or MISP are configured as routed endpoints. CI and release
validation also maintain duplicate source-file inventories.

## Decision

The root `pyproject.toml` is the package and dependency authority. CI builds
and installs the project package, the production gateway image runs the
installed wheel without a source checkout or runtime `PYTHONPATH`, and the
runtime executes as a fixed non-root UID. Only `/app/state` and `/tmp` are
runtime-writable; existing state-volume ownership is migrated explicitly by
the operator when required.

The base Compose deployment uses its normal project network. A small optional
shared-network override attaches services to the external integration network
while retaining the default network, so routed, shared and mixed topologies
use the same `OPENCTI_URL` and `MISP_URL` contracts. No Docker hostname is
inferred and no internal OpenCTI/MISP backend network is required.

Standard preflight remains deterministic and network-free. Endpoint structure,
credential-bearing URLs and state readiness may be checked statically. Active
MISP probing is not introduced, and the existing OpenCTI validation command
remains the explicit active validation surface.

The exact release chain remains build → smoke → Trivy → SBOM → exact artifact
→ protected approval → load → retag → publish. Behavioral CI, wheel
validation and final-image validation remain separate contracts.

Python `>=3.11` remains the compatibility floor; Python 3.11 is the only
runtime certified by CI and release. Later versions are installable but not
certified. The historical `connectors/otx/Dockerfile` remains untouched.

## Dependencies

- current CI/container/release/deployment characterization
- MIG-ADR-002
- MIG-ADR-003
- MIG-ADR-014
- MIG-ADR-018

## Related ADRs

- MIG-ADR-012
- MIG-ADR-015
- MIG-ADR-019

## Consequences

The image is smaller and its runtime import path is reproducible, but existing
root-owned state volumes may need an explicit ownership migration. Operators
who need Docker-local service discovery select the shared-network override;
remote and mixed endpoint deployments do not require that network.

## Target wave

W7 / PR-20.
