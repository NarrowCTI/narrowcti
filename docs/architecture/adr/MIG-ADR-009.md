# MIG-ADR-009 — STIX and export boundary

- Status: proposed
- Context: `exporters.stix_builder` maps accepted candidates into STIX/OpenCTI objects and relationships.
- Proposed Decision: Keep STIX construction downstream of policy and preserve source publication dates and proposed relationship metadata.
- Alternatives: Build STIX objects in source adapters; use OpenCTI mutation calls as the domain model.
- Consequences: Export remains auditable, testable offline and independent of source transport.
- Dependencies: STIX golden fixture; ADR-006, ADR-007 and ADR-008.
- Target Wave: W1 architecture foundation; implementation deferred.

No exporter or Docker behavior is changed in W0.
