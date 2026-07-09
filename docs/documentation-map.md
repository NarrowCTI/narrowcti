# Documentation Map

NarrowCTI keeps documentation paths stable across pre-1.0 releases. For v0.8,
the project uses an index-first documentation model instead of moving historical
files into new directories.

This avoids broken links in release notes while still giving operators and
contributors a clear public entry point.

## Public Product Path

Use these docs first:

- `getting-started.md`
- `deployment-operations-v0.8.md`
- `configuration-reference-v0.6.md`
- `architecture-v0.8.md`
- `graph-promotion-v0.8.md`
- `opencti-coverage-matrix-v0.8.md`
- `release-v0.8.0.md`
- `roadmap.md`

These files are product-facing and should be included in release source
archives.

## Community Path

Use these docs for contribution, support and repository governance:

- `../CONTRIBUTING.md`
- `development-guide.md`
- `community-issue-triage.md`
- `repository-structure.md`
- `release-process.md`
- `../SUPPORT.md`
- `../SECURITY.md`
- `../CODE_OF_CONDUCT.md`

These files are public and should be included in release source archives.

## Architecture and Design Path

Current architecture:

- `architecture-v0.8.md`
- `graph-promotion-v0.8.md`
- `infrastructure-correlation-v0.8.md`
- `opencti-rules-engine-v0.8.md`

Historical design context:

- `product-foundation-v0.3.md`
- `multi-feed-expansion-v0.4.md`
- `gateway-runtime-v0.5.md`
- `enterprise-intelligence-gateway-v0.5.md`
- `quarantine-enrichment-v0.6.md`
- `architecture-v0.7.md`
- `graph-enrichment-v0.7.md`
- `mitre-curation-architecture-v0.7.md`
- `source-ingestion-modes-v0.7.md`

Historical architecture docs may remain public when they help contributors
understand why the product evolved into a gateway.

## Release Notes Path

- `../CHANGELOG.md`
- `release-v0.8.0.md`
- `release-v0.7.0.md`
- `release-v0.6.0.md`
- `release-v0.5.0.md`
- `release-v0.4.0.md`

Release notes should remain operator-facing. Lab logs and raw validation output
belong in development evidence, not public release notes.

## Development Evidence Path

Development evidence stays versioned when useful for maintainers, but many
evidence-heavy files are excluded from release source archives by
`.gitattributes`.

Examples:

- `operational-validation-v*.md`
- `*-official-connector-mapping-v*.md`
- `*-validation-v*.md`
- `metadata-validation-v*.md`
- `product-architecture-validation-v*.md`
- `market-positioning-v*.md`
- `post-v1-ml-roadmap.md`

These files should not be the first operator-facing documentation surface.

## Future Directory Migration

If the repository later moves docs into directories, use this target taxonomy:

```text
docs/product/
docs/architecture/
docs/community/
docs/development/
docs/validation/
docs/releases/
```

Do this only with a dedicated documentation migration commit, because many
release notes and historical docs currently reference root-level `docs/*.md`
paths.
