# NarrowCTI v0.7.0 Release Notes

## Status

`v0.7.0` closes the graph enrichment and enterprise-filter foundation. The
release remains conservative: stable OpenCTI export continues through the
curated `Report + Indicator` path, while richer graph objects and relationships
are validated through audit metadata, graph export planning and in-memory STIX
preview before real OpenCTI graph promotion is enabled.

## Purpose

v0.7 moves NarrowCTI from curated `Report + Indicator` export toward richer
STIX/OpenCTI graph enrichment. The release validates source
metadata broadly enough to decide what can safely become graph knowledge and
what must remain as evidence, labels, notes or quarantine context.

The consolidated architecture is tracked in `docs/architecture-v0.7.md`. The
detailed graph-enrichment design is tracked in
`docs/graph-enrichment-v0.7.md`.
Operational dry-run validation evidence is tracked in
`docs/operational-validation-v0.7.md`.

The MITRE ATT&CK curation architecture is tracked in
`docs/mitre-curation-architecture-v0.7.md`.

## MITRE Curation Decision

v0.7 closes the MITRE role as curation context, not a competing ATT&CK import
path:

```text
Official MITRE connector
  -> populates OpenCTI with the canonical ATT&CK baseline

NarrowCTI
  -> uses MITRE to enrich OTX, MISP and future source evidence
  -> creates curated relationships only when source evidence supports them
```

The NarrowCTI target flow is:

```text
OTX / MISP / raw feed
  -> find ATT&CK ids such as T1059
  -> resolve name, tactic, kill chain, platform, data sources and detection
     guidance through MITRE reference data
  -> relate with actor, malware, sector or geography when provenance supports it
  -> apply score, filters, TLP, deduplication, policy and audit
  -> send contextualized intelligence to OpenCTI
```

In v0.7, this is implemented through local MITRE resolution, graph evidence,
graph candidates, contextual scoring evidence and safe STIX preview summaries.
Canonical OpenCTI ATT&CK lookup and real graph relationship promotion remain the
next controlled implementation gate.

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
- Added `docs/source-adapter-onboarding-v0.7.md` with source intake,
  metadata-mapping, adapter contract, testing, documentation and promotion-gate
  requirements for future adapters, including adapter-level metadata extractor
  conventions.
- Added `docs/mitre-curation-architecture-v0.7.md` to formalize the product
  boundary between the official MITRE connector as the canonical ATT&CK loader
  and NarrowCTI as the MITRE-aware curation gateway.
- Added preflight ingestion-mode reporting. `gateway.preflight` now emits
  `ingestion_mode=direct`, `misp-collector` or `hybrid` in text and JSON
  output based on enabled sources.
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
  graph export runtime wiring and OpenCTI validation are implemented.
- Added the first graph-aware STIX builder foundation. Accepted graph
  candidates can now be converted into OpenCTI-compatible STIX objects for
  attack patterns, actors, intrusion sets, malware, tools, vulnerabilities,
  identities, locations, detection indicators and supported observables, with
  report references, audit-preserving relationships and skipped-candidate
  summary evidence. The runtime still does not promote graph export
  automatically.
- Added trusted semantic relationship previews to the graph STIX builder.
  Candidates with a safe source anchor, such as MISP Galaxy parent cluster
  metadata, can now preview object-to-object relationships like
  `threat-actor -> targets -> sector`; candidates without a safe source anchor
  still fall back to report-context `related-to` relationships.
- Wired OTX and MISP decision metadata to build a safe `graph_stix_preview`
  summary from accepted candidates. This validates bundle construction,
  object/relationship counts, semantic/report-context relationship split and
  skipped candidates in memory without importing graph objects into OpenCTI.
- Extended the decision audit report to aggregate `graph_stix_preview`
  evidence by source and query, including bundle object counts, graph object
  counts, actual relationship counts, proposed relationship counts, semantic
  relationship counts, report-context relationship counts, skipped candidates,
  STIX object types and relationship types.
- Added contextual scoring dry-run evidence from accepted graph candidates.
  OTX and MISP decision metadata now include `contextual_scoring` with base
  score, suggested contextual score, category counts, impact ratio and every
  matched Threat, Toolbox, TTP, Sector, Location, Vulnerability, Author or
  Graph State adjustment. This is audit evidence only and is not applied to the
  current ingest/quarantine decision.
- Extended the decision audit report to aggregate `contextual_scoring`
  evidence by source and query, including score delta totals, average deltas,
  max contextual score, category counts, capped records and decision-application
  counts.
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
- Added MISP Galaxy metadata victimology extraction. Targeted sector, country
  and region aliases in `GalaxyCluster.meta` now produce audit-only target
  candidates with parent cluster provenance, covering real cases where a
  threat actor cluster carries target-sector context instead of standalone
  sector clusters.
- Expanded OTX audit extraction with CVE vulnerability candidates and
  author/source identity evidence. Pulse lifecycle, vote summary and indicator
  first/last-seen windows are now preserved in audit metadata for future
  report/indicator STIX enrichment.
- Added actor-anchored OTX relationship source metadata. When an OTX pulse has
  exactly one adversary, malware, ATT&CK technique, target sector and target
  country candidates can now preview semantic graph relationships such as
  `threat-actor -> uses -> malware/attack-pattern` and
  `threat-actor -> targets -> sector/location`; multi-adversary pulses remain
  report-context only until stronger attribution exists.
- Added OTX YARA audit extraction. YARA pulse indicators now produce audit-only
  `detection_rule` / `indicator` graph evidence and candidates with pattern
  type, raw rule content, indicator id and observation timing.
- Added OTX observable audit extraction. Supported OTX indicator values now
  produce audit-only `observable` graph evidence and candidates with SCO type,
  original indicator type, hash algorithm and observation timing.
- Added MISP CVE/vulnerability audit extraction from tags, event text,
  attributes and object attributes. CVE ids now produce audit-only
  `vulnerability` graph evidence and candidates, including vulnerability
  Galaxy/Cluster evidence when present.
- Added MISP EventReport audit extraction. Non-deleted EventReport entries now
  produce audit-only `event_report` / `note` graph evidence and candidates.
  Accepted note candidates now become STIX `note` objects in the safe
  in-memory graph preview, preserving analyst context before controlled
  OpenCTI export is enabled.
- Added MISP attribute sighting audit extraction. Attribute and object-attribute
  sightings now produce audit-only `sighting` graph evidence and candidates
  with observed value, date, source, organization and attribute context.
- Added MISP object-reference audit extraction. Object references now produce
  audit-only `object_reference` / `relationship` graph evidence and candidates
  with source object, target UUID, MISP relationship type and comment context.
- Added MISP detection-rule audit extraction. YARA, Sigma, Snort, Suricata and
  PCRE attributes now produce audit-only `detection_rule` / `indicator`
  candidates with pattern type, raw pattern, tags and attribute context.
- Added operational dry-run validation evidence for live OTX and MISP lab
  samples, including graph export planning, STIX preview, contextual scoring,
  guardrails, confirmed gaps and safe promotion blockers.
- Added a live MISP Packrat Galaxy validation showing threat-actor and
  targeted-sector candidates from source metadata without OpenCTI graph
  promotion.
- Tightened OTX author extraction so numeric OTX author ids remain provenance
  data and do not become `source_identity` graph candidates.
- Normalized `dry_run` decision records to `dry-run` in the decision audit
  report so operator-facing source, query, reason and score rollups use one
  action vocabulary.

## Closure Validation

v0.7 closure is validated as an audit-first graph enrichment foundation. The
test suite must cover source metadata extraction, STIX object creation,
relationship construction, enterprise filters, deduplication, quarantine release
and representative OTX, MISP and MITRE evidence.

OpenCTI graph import behavior, canonical ATT&CK lookup against the OpenCTI graph
and runtime graph-promotion marking remain blocked for the next controlled
promotion gate.

Current validation:

```text
.\scripts\validate-v0.6.ps1
Ran 254 tests
OK
```
