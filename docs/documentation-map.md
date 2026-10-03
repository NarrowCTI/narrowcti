# Documentation Map

The directory taxonomy below organizes both current guidance and retained
historical evidence; a file's location alone does not make it normative. The
current architecture overview and unversioned product/deployment documents
define supported Community behavior. Versioned architecture, validation and
release snapshots describe their named historical state and do not override
current contracts.

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

Start with [`architecture/overview.md`](architecture/overview.md) for current
architecture and the unversioned documents under `product/` for current
operator contracts. The current brand guide is
[`product/brand-guidelines.md`](product/brand-guidelines.md).

## Archive policy

Release notes and historical snapshots remain available as historical evidence
unless their ledger disposition says otherwise. They are not current setup or
architecture instructions. Validation evidence is organized under
`validation/`; W0 baseline and versioned OpenCTI coverage evidence remain
historical records. Development-only evidence continues to be controlled by
explicit `.gitattributes` entries.

## Migration ledger

[`development/documentation-migration-map.json`](development/documentation-migration-map.json)
is the machine-readable baseline inventory. Its historical disposition
(`STAY`, `MOVE`, `LEGACY-RETAIN` or `CANONICAL-REPLACEMENT`) is preserved;
schema version 2 separately records whether each path is present in the current
tree. Historical immutable moves carry a SHA-256 hash. Neither `STAY` nor a
present path alone means that a document is current product guidance.
