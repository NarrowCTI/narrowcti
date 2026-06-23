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

## Implemented Foundation

- Added `core/graph_evidence.py` as the first shared graph-evidence model.
- OTX decision and quarantine metadata now include `graph_evidence` records
  built from OTX entity extraction and resolved MITRE ATT&CK context.
- MISP decision and quarantine metadata now include `graph_evidence` records
  built from collector provenance, original source and TLP/tag evidence.
- Each evidence record carries the logical entity type, suggested STIX/OpenCTI
  object type, intended relationship type, confidence, source field and source
  provenance.
- The STIX exporter still emits the existing stable `Report + Indicator`
  bundle. v0.7 graph evidence is deliberately audit-only until the graph-aware
  STIX builder and OpenCTI validation are implemented.
- Added `docs/metadata-validation-v0.7.md` to validate OTX and MITRE metadata
  coverage, current mapping depth and remaining intelligent-mapping gaps.
- Expanded OTX metadata normalization to handle `target_countries` aliases and
  object `display_name` values from OTX metadata fields.
- Expanded MITRE technique cache metadata to preserve description, platforms,
  data sources, detection text, domains, versioning, created/modified timestamps
  and sub-technique state.

## Validation Target

v0.7 is not complete until the test suite covers source metadata extraction,
STIX object creation, relationship construction, enterprise filters,
deduplication, quarantine release and OpenCTI import behavior for representative
OTX, MISP and MITRE evidence.

Current validation:

```text
.\scripts\validate-v0.6.ps1
Ran 192 tests
OK
```
