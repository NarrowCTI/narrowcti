# MIG-ADR-009 — STIX IR, serialization and OpenCTI export boundary

- Status: accepted for W4 / PR-14
- Context: `exporters.stix_builder` currently combines candidate-to-STIX
  compilation, generic STIX serialization, OpenCTI-specific STIX conventions,
  deterministic identifiers, relationship construction and report context.
  `exporters.opencti` additionally combines bundle import with OpenCTI-native
  GraphQL mutations and fail-soft worker handling.
- Proposed Decision: Keep the candidate/promotion policy upstream of a small,
  semantic compiler boundary. The compiler produces only the minimum
  source-neutral object, relationship, report-context and compilation-result
  semantics required by the existing export contract. A generic STIX adapter
  serializes standard STIX without knowing OpenCTI platform semantics. An
  OpenCTI-specific STIX profile and OpenCTI exporter own custom SDOs,
  extension conventions, native objects, GraphQL mutations, hydration and
  import error handling. Existing deterministic IDs, source publication dates,
  relationship metadata, provenance, bundle ordering and existing references
  remain contractually unchanged.
- Alternatives: Build STIX in source adapters; make OpenCTI mutations the
  domain model; introduce a DTO-only IR mirroring `stix2`; or make one new
  module identical to the historical exporter. These alternatives either
  couple sources/platforms to serialization or fail to create a real
  boundary while breaking the legacy compatibility surface.
- Consequences: STIX compilation can be tested offline, OpenCTI-specific
  behavior remains isolated, and the historical `exporters.stix_builder` /
  `exporters.opencti` surfaces can remain compatibility wrappers. The
  compatibility window must preserve legacy symbol identity without exposing
  incidental third-party globals as canonical APIs.
- Dependencies:
  - current STIX/OpenCTI characterization and parity fixtures
  - MIG-ADR-006
  - MIG-ADR-008
  - MIG-ADR-014
- Related ADRs:
  - MIG-ADR-007 — the PR relies on the already-characterized upstream
    candidate/promotion boundary, but does not authorize or modify that policy
    boundary
  - MIG-ADR-002 — only if the implementation changes the established package
    compatibility surface
- Target Wave: W4 / PR-14

This ADR authorizes only the bounded STIX/compiler/OpenCTI adapter split. It
does not authorize changes to graph evidence, graph provider/index semantics,
source extraction, ingestion orchestration, gateway runtime, configuration,
deployment, or PR-15 provider-registry work.
