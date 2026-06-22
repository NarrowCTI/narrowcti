# NarrowCTI v0.7.0 Development Notes

## Status

`v0.7.0-dev` is the active graph enrichment and enterprise-filter development
track. `v0.6.0` remains the latest stable release until v0.7 completes
implementation, validation, merge and tag.

## Purpose

v0.7 should move NarrowCTI from curated `Report + Indicator` export toward
richer STIX/OpenCTI graph enrichment. The release should validate source
metadata broadly enough to decide what can safely become graph knowledge and
what must remain as evidence, labels, notes or quarantine context.

The detailed design is tracked in `docs/graph-enrichment-v0.7.md`.

## Initial Scope

- Centralize source metadata evidence before STIX export.
- Expand OTX, MISP and MITRE evidence mapping into graph-aware candidate data.
- Add enterprise filters for actor, arsenal, ATT&CK, sector, geography,
  artifact criticality and graph state.
- Introduce relationship confidence, provenance and audit evidence.
- Extend graph hygiene beyond indicator deduplication into entity and
  relationship quality controls.

## Validation Target

v0.7 is not complete until the test suite covers source metadata extraction,
STIX object creation, relationship construction, enterprise filters,
deduplication, quarantine release and OpenCTI import behavior for representative
OTX, MISP and MITRE evidence.
