# NarrowCTI Documentation

This directory contains current product and contributor documentation as well
as retained release and implementation history. Historical/versioned files
are evidence, not current product guidance. The machine-readable documentation
inventory is
[`development/documentation-migration-map.json`](development/documentation-migration-map.json).

## Current guidance

- Product: [`product/getting-started.md`](product/getting-started.md),
  [`product/deployment-operations.md`](product/deployment-operations.md),
  [`product/configuration-reference.md`](product/configuration-reference.md),
  [`product/web-source-explorer.md`](product/web-source-explorer.md),
  [`product/community-web-ux.md`](product/community-web-ux.md),
  [`product/product-reference.md`](product/product-reference.md),
  [`product/brand-guidelines.md`](product/brand-guidelines.md)
- Architecture: [`architecture/overview.md`](architecture/overview.md) and
  [`architecture/adr/README.md`](architecture/adr/README.md)
- Validation: [`product/opencti-coverage-matrix.md`](product/opencti-coverage-matrix.md)
- Community: [`community/community-governance.md`](community/community-governance.md),
  [`community/community-standards.md`](community/community-standards.md)
- Development: [`development/development-guide.md`](development/development-guide.md),
  [`development/source-adapter-onboarding.md`](development/source-adapter-onboarding.md),
  [`development/release-process.md`](development/release-process.md)

The current architecture overview, product contracts and deployment guides
define supported behavior. The current release record is available under
[`releases/`](releases/); release notes describe the release they name and are
not substitutes for current operator instructions.

`architecture.md` remains a compatibility stub pointing to the overview. The
old NarrowCTI PNG assets remain retained for historical consumers; new content
uses `assets/brand/`.

## Taxonomy

| Area | Purpose |
| --- | --- |
| `product/` | operator and product contracts |
| `architecture/` | current overview and retained historical design snapshots |
| `community/` | governance and contributor guidance |
| `development/` | contributor workflows, release process and migration evidence |
| `validation/` | historical validation, mapping and W0 evidence |
| `releases/` | release notes and immutable release snapshots |

The six documentation categories are `product/`, `architecture/`, `community/`,
`development/`, `validation/`, and `releases/`. Operational identity assets
are a sibling artifact tree under `assets/brand/`, not a seventh documentation
category.

See [`documentation-map.md`](documentation-map.md) for the distinction between
current guidance and retained historical records.
