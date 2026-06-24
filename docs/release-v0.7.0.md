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

The consolidated architecture is tracked in `docs/architecture-v0.7.md`. The
detailed graph-enrichment design is tracked in
`docs/graph-enrichment-v0.7.md`.

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

- Added `docs/architecture-v0.7.md` to consolidate the product architecture,
  runtime modes, graph evidence contracts, graph candidate policy surface,
  implemented foundation and pending graph-export work.
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
- Added `core/graph_export_plan.py` so OTX and MISP decision/quarantine
  metadata can record graph export intent in `audit` or `dry-run` mode without
  creating OpenCTI graph objects yet. `export` mode is blocked until the
  graph-aware STIX builder and OpenCTI validation are implemented.
- Extended the decision audit report to aggregate `graph_export_plan` evidence
  by mode, status, action, held reason, source and query, including
  would-create object and relationship counts for graph export dry-runs.
- Added intra-plan graph deduplication to `graph_export_plan`, with
  deterministic entity and relationship keys, duplicate counts and adjusted
  dry-run would-create object/relationship totals before real graph export
  exists.
- Added `core/graph_deduplication.py` as the local graph deduplication state
  model for persisted entity/relationship keys and source sightings. It is a
  future graph export foundation and is not used to mark dry-run plans as
  exported knowledge.
- Wired OTX and MISP `graph_export_plan` metadata to optionally read local
  graph known keys from `NARROWCTI_GRAPH_DEDUP_STATE_FILE`. This is read-only
  planning evidence: matching local keys are marked as deduplicated, but v0.7
  still does not mark dry-run plans as exported or replace future OpenCTI graph
  lookup.
- Added MISP Galaxy/Cluster audit mapping for event, object and attribute
  metadata. Known clusters now produce graph evidence and candidates for ATT&CK
  attack patterns, threat actors, intrusion sets, malware, tools, target
  sectors, countries and regions before future graph-aware STIX export.
- Expanded OTX audit extraction with CVE vulnerability candidates and
  author/source identity evidence. Pulse lifecycle, vote summary and indicator
  first/last-seen windows are now preserved in audit metadata for future
  report/indicator STIX enrichment.
- Added MISP CVE/vulnerability audit extraction from tags, event text,
  attributes and object attributes. CVE ids now produce audit-only
  `vulnerability` graph evidence and candidates, including vulnerability
  Galaxy/Cluster evidence when present.
- Added MISP EventReport audit extraction. Non-deleted EventReport entries now
  produce audit-only `event_report` / `note` graph evidence and candidates so
  analyst context can be preserved for future graph-aware STIX export.
- Added MISP attribute sighting audit extraction. Attribute and object-attribute
  sightings now produce audit-only `sighting` graph evidence and candidates
  with observed value, date, source, organization and attribute context.

## Validation Target

v0.7 is not complete until the test suite covers source metadata extraction,
STIX object creation, relationship construction, enterprise filters,
deduplication, quarantine release and OpenCTI import behavior for representative
OTX, MISP and MITRE evidence.

Current validation:

```text
.\scripts\validate-v0.6.ps1
Ran 228 tests
OK
```
