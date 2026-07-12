# Architecture

This is the current public architecture entry point for NarrowCTI Community
Edition.

The latest released architecture snapshot is `architecture-v0.9.md`. Active
v1.0 development is tracked in `architecture-v1.0.md`. Versioned architecture
files remain in the repository as release history; operators and contributors
should link to this unversioned document when they need the current product
architecture entry point.

## Product Boundary

NarrowCTI is a pre-ingestion curation gateway for OpenCTI.

```text
External and internal intelligence sources
  -> NarrowCTI source adapters
  -> normalization and metadata extraction
  -> scoring, policy, deduplication and quarantine
  -> graph evidence and graph candidate policy
  -> STIX/OpenCTI export
  -> OpenCTI graph, knowledge and visualization
```

OpenCTI remains the knowledge platform. NarrowCTI decides what should reach
OpenCTI, why it should reach OpenCTI and which graph context is safe to promote.

## Current Runtime Shape

- `gateway/`: unified gateway runtime, preflight, reports, diagnostics and
  operator CLIs.
- `connectors/`: source adapters such as OTX and MISP.
- `core/`: scoring, policy, graph evidence, graph deduplication, quarantine and
  state handling.
- `exporters/`: STIX bundle and OpenCTI export logic.
- `deployment/`: Docker Compose deployment template.
- `docs/`: product, architecture, operations and community documentation.

## Current Architecture Documents

- `architecture-v1.0.md`: active production-readiness architecture and release
  contract.
- `architecture-v0.9.md`: released analyst operations and graph-quality
  snapshot.
- `architecture-v0.8.md`: v0.8 detailed architecture snapshot.
- `graph-promotion-v0.8.md`: controlled OpenCTI graph promotion boundary.
- `opencti-coverage-matrix-v0.8.md`: OpenCTI tab/object coverage.
- `infrastructure-correlation-v0.8.md`: infrastructure, ASN and IP correlation.
- `opencti-rules-engine-v0.8.md`: NarrowCTI curation versus OpenCTI inference.
- `source-ingestion-modes-v0.7.md`: direct, MISP collector and hybrid source
  modes.

## Operator References

- `getting-started.md`
- `deployment-operations.md`
- `configuration-reference.md`
- `curation-decision-reference.md`
- `environment-profiles.md`
