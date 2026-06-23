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
- Define contextual scoring based on graph evidence so actor, arsenal, TTP,
  sector, geography and author relevance can influence decisions without
  bypassing policy.
- Define direct source, MISP collector and hybrid ingestion modes so NarrowCTI
  does not depend on MISP to act as the OpenCTI curation gateway.
- Introduce relationship confidence, provenance and audit evidence.
- Extend graph hygiene beyond indicator deduplication into entity and
  relationship quality controls.

## Implemented Foundation

- Added `core/graph_evidence.py` as the first shared graph-evidence model.
- Added `core/graph_candidates.py` as the first normalized graph-candidate
  model for future graph-aware STIX export.
- OTX decision and quarantine metadata now include `graph_evidence` records
  built from OTX entity extraction and resolved MITRE ATT&CK context.
- MISP decision and quarantine metadata now include `graph_evidence` records
  built from collector provenance, original source and TLP/tag evidence.
- OTX and MISP decision/quarantine metadata now include normalized
  `graph_candidates` derived from `graph_evidence`, still audit-only.
- Each evidence record carries the logical entity type, suggested STIX/OpenCTI
  object type, intended relationship type, confidence, source field and source
  provenance.
- The STIX exporter still emits the existing stable `Report + Indicator`
  bundle. v0.7 graph evidence and candidates are deliberately audit-only until
  the graph-aware STIX builder and OpenCTI validation are implemented.
- Added `docs/metadata-validation-v0.7.md` to validate OTX and MITRE metadata
  coverage, current mapping depth and remaining intelligent-mapping gaps.
- Added `docs/misp-official-connector-mapping-v0.7.md` to validate the
  official OpenCTI MISP connector mapping model and define it as the
  compatibility baseline for NarrowCTI curated MISP graph export.
- Added `docs/otx-official-connector-mapping-v0.7.md` to validate the
  official OpenCTI AlienVault connector mapping model and define it as the
  source-specific compatibility baseline for NarrowCTI curated OTX graph
  export.
- Added `docs/contextual-scoring-reference-v0.7.md` to evaluate the OpenCTI
  scoring-calculator connector as a reference for NarrowCTI contextual
  pre-ingestion scoring.
- Added `docs/source-ingestion-modes-v0.7.md` to formalize direct source, MISP
  collector and hybrid ingestion modes.
- Expanded OTX metadata normalization to handle `target_countries` aliases and
  object `display_name` values from OTX metadata fields.
- Expanded MITRE technique cache metadata to preserve description, platforms,
  data sources, detection text, domains, versioning, created/modified timestamps
  and sub-technique state.
- MITRE technique resolution now emits reusable audit-only graph candidates for
  ATT&CK external references, kill chain phase attributes, platforms, data
  sources and detection guidance.
- Graph candidates now carry explicit `relationship_confidence` and normalized
  source `provenance` for future graph-aware STIX relationship creation.
- OTX and MISP decision/quarantine metadata now include audit-only
  `graph_candidate_policy` results with accepted and held graph candidates.

## Validation Target

v0.7 is not complete until the test suite covers source metadata extraction,
STIX object creation, relationship construction, enterprise filters,
deduplication, quarantine release and OpenCTI import behavior for representative
OTX, MISP and MITRE evidence.

Current validation:

```text
.\scripts\validate-v0.6.ps1
Ran 199 tests
OK
```
