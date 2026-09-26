# NarrowCTI Documentation

This directory contains the current product documentation, architecture and
community guidance, historical release evidence, and approved brand assets.
The machine-readable migration ledger is
[`development/documentation-migration-map.json`](development/documentation-migration-map.json).

## Current entry points

- Product: [`product/getting-started.md`](product/getting-started.md),
  [`product/deployment-operations.md`](product/deployment-operations.md),
  [`product/configuration-reference.md`](product/configuration-reference.md),
  [`product/product-reference.md`](product/product-reference.md),
  [`product/brand-guidelines.md`](product/brand-guidelines.md)
- Architecture: [`architecture/overview.md`](architecture/overview.md) and
  [`architecture/adr/README.md`](architecture/adr/README.md)
- Validation: [`validation/opencti-coverage-matrix-v0.8.md`](validation/opencti-coverage-matrix-v0.8.md)
- Community: [`community/community-governance.md`](community/community-governance.md),
  [`community/community-standards.md`](community/community-standards.md)
- Development: [`development/development-guide.md`](development/development-guide.md)
- Releases: [`releases/release-v1.1.1.md`](releases/release-v1.1.1.md)

`architecture.md` remains a compatibility stub pointing to the overview. The
old NarrowCTI PNG assets remain retained for historical consumers; new content
uses `assets/brand/`.

## Taxonomy

| Area | Purpose |
| --- | --- |
| `product/` | operator and product contracts |
| `architecture/` | current architecture and historical design snapshots |
| `community/` | governance and contributor guidance |
| `development/` | contributor workflows and migration evidence |
| `validation/` | validation, mapping and W0 evidence |
| `releases/` | release process and immutable release notes |

The six documentation categories are `product/`, `architecture/`, `community/`,
`development/`, `validation/`, and `releases/`. Operational identity assets
are a sibling artifact tree under `assets/brand/`, not a seventh documentation
category.

See [`documentation-map.md`](documentation-map.md) for release/archive intent.
