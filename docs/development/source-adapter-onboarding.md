# Source Adapter Onboarding

This is the current contributor guide for adding or changing a NarrowCTI
source adapter. Start with the [architecture overview](../architecture/overview.md)
and keep source-specific behavior separate from the canonical domain and
application boundaries.

## Canonical owners

New source work should use the current package owners:

- `src/narrowcti/adapters/sources/` — source-specific extraction and adapter
  infrastructure;
- `src/narrowcti/domain/graph/evidence/` — pure graph evidence contracts and
  family-specific normalization;
- `src/narrowcti/application/ingestion/` — candidate-level orchestration and
  deterministic outcome ordering;
- `src/narrowcti/ports/` — minimal contracts at infrastructure boundaries.

The `connectors/*`, `core/*`, `exporters/*` and `gateway/*` trees remain
compatibility seams for supported legacy imports and entrypoints. Do not add
new domain logic there, and do not bypass the canonical owners from new code.

## Adapter contract

Before coding, document the source identity, authentication and endpoint
configuration, rate limits, timeouts, retry behavior, and the source's dry-run
and run-once semantics. Define how source records become candidates while
preserving provenance, tags, timestamps, and raw evidence.

Record state keys and checkpoint behavior explicitly. A checkpoint is written
only after the current export contract succeeds; quarantine, deduplication and
error paths must remain auditable and idempotent.

For graph-aware sources, identify the evidence family, target STIX/OpenCTI
objects and relationships, confidence and policy inputs, lookup/deduplication
behavior, and the provenance carried into the export plan. Keep unresolved
relationships out of the graph rather than inventing edges.

## Tests and review

Use small sanitized fixtures. Add characterization for source normalization,
metadata fallback, terminal policy outcomes, deduplication, checkpoint timing,
audit records and graph evidence. Run the full repository test command and
the applicable quality, security, package and container gates before opening a
pull request.
