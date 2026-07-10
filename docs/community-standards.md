# Community Standards

This document maps the public repository standards NarrowCTI expects to keep as
an open source Community Edition project.

The goal is not to copy another project's governance text. The goal is to keep
NarrowCTI predictable for contributors, operators and security reporters.

## Public Repository Surfaces

| Surface | NarrowCTI file | Purpose |
| --- | --- | --- |
| README | `README.md` | Product identity, quick start, release status and key docs. |
| Code of Conduct | `CODE_OF_CONDUCT.md` | Community behavior and moderation expectations. |
| Contributing | `CONTRIBUTING.md` | Issue, branch, PR, testing and documentation expectations. |
| License | `LICENSE` | Apache-2.0 Community Edition license for the core project. |
| Security | `SECURITY.md` | Supported versions, private reporting and disclosure process. |
| Support | `SUPPORT.md` | Community support channels and data handling guidance. |
| Release process | `docs/release-process.md` | Tag, GitHub Release and image release process. |
| Container images | `docs/container-images.md` | Image naming, tags and operator pinning guidance. |

## NarrowCTI Posture

NarrowCTI Community Edition is distributed under Apache-2.0. There is no
commercial feature gate in the core repository. Future paid services or
separate optional modules should not make the open source gateway ambiguous.

Public docs should explain:

- what the product does;
- how to deploy it safely;
- how to configure curation decisions;
- how to validate those decisions;
- how to contribute without leaking secrets or feed payloads;
- how releases and container images are produced.

## Maintainer Checklist

Before a public release:

- README logo, badges, quick start and current version are accurate.
- `CONTRIBUTING.md`, `SECURITY.md`, `SUPPORT.md` and `CODE_OF_CONDUCT.md` are
  present and linked.
- The source archive excludes local state, secrets, raw payloads and local
  assistant/operator instructions.
- `docs/container-images.md` matches the image workflow and compose examples.
- GitHub Release notes mention validation status, known limitations and the
  canonical container image tag.
- No development-only validation log is promoted as the primary product doc.
