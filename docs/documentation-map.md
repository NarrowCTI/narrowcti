# Documentation Map

The current source of truth follows the directory taxonomy below. Historical
files are moved without content rewrites; the migration ledger records every
baseline path and its disposition.

## Current paths

- Product: `docs/product/`
- Architecture: `docs/architecture/`
- Community: `docs/community/`
- Development: `docs/development/`
- Validation: `docs/validation/`
- Releases: `docs/releases/`

The six documentation categories are:

- `docs/product/`
- `docs/architecture/`
- `docs/community/`
- `docs/development/`
- `docs/validation/`
- `docs/releases/`

Operational assets are a separate sibling tree at `docs/assets/brand/`; they are
not a seventh documentation category.

The current architecture overview is
[`architecture/overview.md`](architecture/overview.md). The current brand
guide is [`product/brand-guidelines.md`](product/brand-guidelines.md).

## Archive policy

Release notes and historical snapshots remain release-visible unless their
ledger disposition says otherwise. Validation evidence is organized under
`validation/`; W0 baseline and OpenCTI coverage evidence are intentionally not
excluded from release archives. Development-only evidence continues to be
controlled by explicit `.gitattributes` entries.

## Migration ledger

[`development/documentation-migration-map.json`](development/documentation-migration-map.json)
is the authoritative machine-readable record. Every baseline `docs/` path has
exactly one disposition: `STAY`, `MOVE`, `LEGACY-RETAIN`, or
`CANONICAL-REPLACEMENT`. Historical immutable moves carry a SHA-256 hash.
