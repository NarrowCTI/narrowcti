# NarrowCTI v0.7 Architecture

## Purpose

This document consolidates the v0.7 architecture for graph enrichment and
enterprise curation.

v0.7 is the release where NarrowCTI stops being only a curated IoC forwarding
layer and becomes an audit-first graph enrichment foundation. The product goal
is to make OpenCTI more useful as an intelligence graph while keeping
NarrowCTI responsible for validation, scoring, policy, deduplication,
quarantine and explainability before data reaches OpenCTI.

The target is not to blindly recreate every source field in OpenCTI. The target
is to decide, with evidence, which source metadata should become graph
entities, relationships, labels, markings, external references, notes, scoring
signals or quarantine-only context.

## Product Role

NarrowCTI is the pre-ingestion CTI curation gateway.

OpenCTI is the intelligence graph, storage, visualization and knowledge
management platform.

MISP is optional. It can act as a collector and event hub, but it should not be
required for NarrowCTI to deliver value. NarrowCTI must support direct source,
MISP collector and hybrid ingestion modes.

Official OpenCTI connectors are compatibility references. They help validate
how source metadata can be represented in OpenCTI, but the target product flow
keeps curation inside NarrowCTI before graph promotion.

MITRE ATT&CK has a specific reference role. The official MITRE connector should
populate OpenCTI with the canonical ATT&CK baseline. NarrowCTI should use MITRE
as enrichment context for OTX, MISP and future feeds, then create curated
relationships to ATT&CK knowledge only when source evidence, policy and
deduplication allow it.

## Architecture Principles

- Curation happens before ingestion into OpenCTI.
- Source metadata is untrusted until validated.
- Graph enrichment must be evidence-backed.
- Every candidate entity and relationship must carry provenance.
- Relationship confidence must be explicit and auditable.
- Weak metadata should remain as labels, notes, audit evidence or quarantine
  context until policy allows graph promotion.
- OpenCTI graph hygiene matters more than ingest volume.
- MITRE ATT&CK context enriches curation; it must not become a competing
  ATT&CK import path inside NarrowCTI.
- Source-specific richness must be normalized into shared NarrowCTI contracts.
- Operators must see the policy surface through configuration, not hidden code.
- v0.7 graph candidates are audit-first until graph-aware STIX export is
  implemented and validated against OpenCTI.

## Runtime Modes

```text
Direct source mode
  External source -> NarrowCTI -> OpenCTI

MISP collector mode
  External sources -> MISP -> NarrowCTI -> OpenCTI

Hybrid mode
  Some sources -> MISP -> NarrowCTI
  Other sources -> NarrowCTI directly
  NarrowCTI -> OpenCTI
```

All three modes must preserve the same product invariant:

```text
source payload
  -> NarrowCTI curation gateway
  -> validated intelligence output
  -> OpenCTI graph
```

## Component View

```text
connectors/*
  -> source adapter and runtime settings
  -> normalized candidate records
  -> source-specific metadata extraction

core/scoring.py
core/policy.py
core/indicator_policy.py
core/tlp.py
  -> base curation policy
  -> score, age, type, TLP and ingest decision controls

core/graph_evidence.py
  -> source metadata evidence records
  -> logical entity type
  -> suggested STIX/OpenCTI object type
  -> suggested relationship type
  -> confidence and source field provenance

core/graph_candidates.py
  -> normalized graph candidates
  -> stable candidate fingerprint
  -> object confidence
  -> relationship confidence
  -> graph candidate policy result

core/graph_deduplication.py
  -> local graph entity and relationship state model
  -> persisted graph deduplication records
  -> source sightings for future graph promotion audit

core/quarantine.py
core/state_repository.py
core/decision_audit.py
  -> review workflow
  -> state tracking
  -> release audit
  -> evidence retained for explainability

exporters/stix_builder.py
  -> current stable Report + Indicator export
  -> future graph-aware STIX object and relationship export

exporters/opencti.py
  -> OpenCTI delivery boundary
```

## Current v0.7 Flow

The current implementation is intentionally conservative:

```text
source payload
  -> source adapter
  -> normalized indicator candidate
  -> base score and policy decision
  -> source metadata extraction
  -> optional MITRE ATT&CK reference enrichment
  -> graph_evidence
  -> graph_candidates
  -> graph_candidate_policy
  -> optional local graph dedup known-key lookup
  -> graph_export_plan
  -> decision audit and quarantine metadata
  -> stable Report + Indicator STIX bundle
  -> OpenCTI
```

At this stage, graph evidence, graph candidates and graph export plans remain
audit metadata in the stable OpenCTI export path. The in-memory
`graph_stix_preview` can build graph objects and controlled relationship
previews. v0.8 adds an explicit `export` gate for controlled OpenCTI graph
promotion after import validation is complete.

This keeps v0.7 safe while the project validates source metadata depth,
relationship confidence, official connector compatibility and OpenCTI import
behavior.

## Target Graph Export Flow

The intended v0.7/v0.8 direction is:

```text
graph_candidates
  -> graph policy
  -> graph deduplication and OpenCTI lookup
  -> canonical ATT&CK object lookup when MITRE evidence is present
  -> graph export dry-run report
  -> graph-aware STIX bundle
  -> OpenCTI import validation
  -> controlled graph promotion
```

The graph-aware STIX builder should create objects and relationships only when
candidate evidence passes configured policy and OpenCTI compatibility checks.
When a candidate carries a trusted source anchor, such as MISP Galaxy parent
cluster metadata, the preview may create a semantic relationship between graph
objects. When no safe source anchor exists, it falls back to a report-context
`related-to` relationship instead of inventing attribution.

For MITRE ATT&CK, the target behavior is to relate curated source evidence to
canonical OpenCTI ATT&CK objects, preferably loaded by the official MITRE
connector, instead of creating duplicate `attack-pattern` objects.

## Current Data Contracts

### graph_evidence

`graph_evidence` is the raw normalized evidence layer produced from source
metadata.

It records:

- NarrowCTI graph evidence version.
- Source key.
- External source id.
- Source title.
- Entity counts.
- Evidence records.

Each evidence record includes:

- Logical `entity_type`.
- Source `value`.
- Suggested `stix_object_type`.
- Suggested `relationship_type`.
- `source_key`, `source_name` and `source_field`.
- Confidence.
- Optional display name.
- Optional attributes.

Current entity targets include actor, malware, tool, ATT&CK technique, ATT&CK
tactic, target sector, target country, source identity, collector, tag,
marking, external reference, attack platform, attack data source and detection
guidance.

### graph_candidates

`graph_candidates` converts evidence into a normalized candidate set for future
graph-aware STIX export.

Each candidate includes:

- Stable fingerprint.
- Logical entity type.
- Source value and display name.
- Suggested STIX/OpenCTI object type.
- Suggested relationship type.
- Source provenance.
- Object confidence.
- Relationship confidence.
- Optional source attributes.

Candidates are source-agnostic. This is the contract that lets OTX, MISP,
MITRE and future feeds feed the same graph enrichment engine without copying
each source's internal structure into the exporter.

Relationship source anchoring is intentionally explicit. A candidate can carry
source metadata such as `relationship_source_stix_object_type`,
`relationship_source_value` or trusted parent-cluster fields. This lets
NarrowCTI convert evidence like `Packrat -> targets -> Activists` into graph
relationships without turning weak report context into false attribution.

### graph_candidate_policy

`graph_candidate_policy` is the audit-only decision layer for graph candidates.

It separates candidates into:

- `accepted`: candidates that passed current graph policy.
- `held`: candidates blocked by current graph policy with reasons.

Current reasons include:

- `entity_confidence_below_min`
- `relationship_confidence_below_min`
- `entity_type_not_allowed`
- `stix_object_type_not_allowed`
- `relationship_provenance_required`

In v0.7, "accepted" means accepted for audit readiness, not automatically
exported as OpenCTI graph objects.

### graph_export_plan

`graph_export_plan` converts the graph candidate policy result into an
operator-visible plan.

It records:

- Graph export plan version.
- Graph export mode.
- Plan status.
- Candidate, accepted and held counts.
- Held reason counts.
- Accepted object and relationship counts.
- Deterministic local entity and relationship deduplication keys.
- Duplicate entity, duplicate relationship and duplicate candidate counts.
- Dry-run would-create counts when dry-run mode is enabled.
- Per-candidate actions.

Current modes are:

- `audit`: default. Records candidates as audit-only.
- `dry-run`: records accepted candidates as `would_create` actions and counts
  the objects/relationships that would be attempted later.
- `export`: enabled in v0.8 as the first controlled promotion gate. Accepted
  candidates are sent in the curated STIX bundle only after source policy,
  graph candidate policy and deduplication planning pass.

This gives operators a controlled path from graph promotion intent to OpenCTI
graph state. The current deduplication is intra-plan and known-key aware: it
prevents obvious duplicate entity/relationship intent inside the same decision
record and produces audit evidence. OTX and MISP can also read
`NARROWCTI_GRAPH_DEDUP_STATE_FILE` as an optional local known-key index when
building `graph_export_plan`; matching keys are reported as deduplicated in the
plan. Dry-run plans are not marked as exported. In export mode, the local index
is marked only after OpenCTI import succeeds. Known keys returned by local state
or OpenCTI lookup are skipped by the first export gate to avoid duplicating
canonical graph objects.

## Policy Surface

Graph curation policy must remain visible and configurable.

Current v0.7 graph candidate controls:

```text
NARROWCTI_MIN_ENTITY_CONFIDENCE=0
NARROWCTI_MIN_RELATIONSHIP_CONFIDENCE=0
NARROWCTI_REQUIRE_RELATIONSHIP_PROVENANCE=false
NARROWCTI_ALLOWED_GRAPH_ENTITY_TYPES=
NARROWCTI_ALLOWED_GRAPH_STIX_OBJECT_TYPES=
NARROWCTI_GRAPH_EXPORT_MODE=audit
NARROWCTI_GRAPH_DEDUP_STATE_FILE=
```

These are deliberately permissive by default because the current graph layer
is guarded by `NARROWCTI_GRAPH_EXPORT_MODE=audit`. `dry-run` enables graph
export planning evidence without importing graph entities or relationships.
`export` should be used only with restrictive thresholds, allow-lists,
deduplication state and OpenCTI lookup validation.

Future graph export controls should include:

```text
NARROWCTI_GRAPH_REQUIRE_OPENCTI_LOOKUP=true
NARROWCTI_GRAPH_DEDUP_MODE=source|opencti|hybrid
NARROWCTI_ALLOWED_ATTACK_TACTICS=
NARROWCTI_ALLOWED_ATTACK_TECHNIQUES=
NARROWCTI_ALLOWED_THREAT_ACTORS=
NARROWCTI_ALLOWED_MALWARE_FAMILIES=
NARROWCTI_ALLOWED_TARGET_SECTORS=
NARROWCTI_ALLOWED_TARGET_COUNTRIES=
NARROWCTI_ALLOWED_TLP=
```

The product rule is simple: configuration defines the operator's policy;
NarrowCTI applies it automatically and records the decision trail.

## Implemented Foundation

| Area | Current state |
| --- | --- |
| OTX entity extraction | Implemented for actor, malware family, ATT&CK, CVE vulnerability, sector, country, author/source identity, observable evidence, YARA detection-rule evidence, TLP, references and tags. Pulse lifecycle, vote summary and indicator observation windows are captured as audit metadata. Malware, ATT&CK, sector and country candidates carry actor relationship source metadata when the pulse has exactly one adversary. |
| MISP metadata evidence | Implemented for collector, original source, tags, TLP markings, EventReport note evidence, attribute sighting evidence, object-reference relationship evidence, detection-rule evidence, CVE vulnerability evidence and common Galaxy/Cluster graph evidence. |
| MISP Galaxy audit mapping | Implemented for event, object and attribute galaxy clusters covering ATT&CK attack patterns, threat actors, intrusion sets, malware, tools, sectors, countries and regions as audit-only graph candidates. Galaxy `meta.targeted-sector`, `meta.targeted-country` and `meta.targeted-region` aliases also emit victimology candidates with parent cluster provenance. |
| MITRE ATT&CK enrichment | Implemented for technique identity, external references, kill chain phases, platforms, data sources, detection guidance, domains and lifecycle fields. |
| Graph evidence model | Implemented in `core/graph_evidence.py`. |
| Graph candidate model | Implemented in `core/graph_candidates.py`. |
| Relationship provenance | Implemented on graph candidates. |
| Relationship confidence | Implemented on graph candidates. |
| Graph candidate policy | Implemented as accepted and held candidate output for audit, dry-run and controlled export. |
| Graph export planning | Implemented as audit/dry-run/export metadata for OTX and MISP decisions, including intra-plan entity and relationship deduplication evidence. |
| Local graph deduplication index | Implemented in `core/graph_deduplication.py` for persisted entity/relationship keys and source sightings, with post-import marking in controlled export mode. |
| Read-only graph known-key lookup | Implemented for OTX and MISP `graph_export_plan` metadata through optional `NARROWCTI_GRAPH_DEDUP_STATE_FILE`; this marks known local entity/relationship keys in the plan without marking anything exported. |
| Decision audit metadata | Implemented for OTX and MISP processors. |
| Decision audit graph export reporting | Implemented in `gateway.decisions` with graph export modes, statuses, actions, would-create counts, deduplicated counts, held reasons, source rollups and query rollups. |
| Decision audit contextual scoring reporting | Implemented in `gateway.decisions` with contextual score deltas, category counts, capped records, source rollups and query rollups. |
| Initial graph-aware STIX builder | Implemented in `exporters.stix_builder` for accepted graph candidates covering attack patterns, actors, intrusion sets, malware, tools, vulnerabilities, identities, locations, notes, detection indicators and supported observables. |
| Graph STIX preview metadata | Implemented for OTX and MISP decisions as in-memory bundle validation summary without OpenCTI import. |
| Decision audit graph STIX preview reporting | Implemented in `gateway.decisions` with bundle counts, graph object counts, actual relationship counts, proposed relationship counts, semantic/report-context relationship counts, skipped candidates, source rollups and query rollups. |
| MITRE curation posture | Closed for v0.7 as an architecture decision: the official MITRE connector owns canonical ATT&CK loading, while NarrowCTI uses MITRE as source-curation context and preview evidence. |
| Contextual scoring evidence | Implemented as dry-run `contextual_scoring` metadata derived from accepted graph candidates; it is not applied to ingest decisions yet. |
| Ingestion mode preflight | Implemented in `gateway.preflight` as `ingestion_mode` with `direct`, `misp-collector` and `hybrid` values. |
| Quarantine metadata | Implemented for OTX and MISP processors. |
| Stable STIX export | Implemented as current `Report + Indicator` bundle. |

## Pending Work

| Area | Target |
| --- | --- |
| Graph export runtime wiring | Connect the initial graph-aware STIX builder to controlled export mode after OpenCTI lab validation. |
| Graph deduplication runtime promotion | Mark successfully exported graph objects in the local graph index and add OpenCTI entity/relationship lookup before promotion. |
| Canonical MITRE/OpenCTI lookup | Resolve ATT&CK candidates against existing OpenCTI objects by external id or STIX id before creating graph relationships. |
| Graph export dry-run reporting | Extend implemented decision-audit graph export rollups into OpenCTI lab comparison evidence and future enterprise CTI reports. |
| MISP rich mapping | Expand official-compatible observable/indicator export, STIX relationship export semantics, STIX sighting export semantics, NVD vulnerability enrichment and richer taxonomy tags beyond the initial EventReport note preview, sighting, object-reference, detection-rule, CVE and Galaxy/Cluster audit mapping. |
| OTX rich mapping | Expand observable STIX export, NVD vulnerability enrichment, country normalization and relationship semantics beyond the current actor-anchored preview support and audit-only observable, CVE, YARA, author, lifecycle, vote and indicator timing metadata. |
| Contextual scoring policy controls | Add operator-visible category impact configuration and a controlled path for applying contextual score to decisions after validation. |
| Quarantine release for graph candidates | Allow reviewed graph candidates to be promoted later with release audit. |
| OpenCTI lab validation | Compare NarrowCTI output with official connector behavior and inspect resulting graph quality. |
| Enterprise reporting | Summarize what was ingested, held, enriched and why. |

## Trust Boundaries

External feeds are untrusted.

MISP is trusted as an internal collector only when the operator chooses that
mode. MISP event metadata still needs validation because it can include
provider data, user-created tags, galaxies, objects and enrichment artifacts.

MITRE ATT&CK is reference data, not an IoC feed. It enriches technique context
and should improve graph quality, not bypass source policy. The official MITRE
connector can own the canonical ATT&CK import into OpenCTI; NarrowCTI owns the
curation decision that connects feed evidence to that canonical context.

OpenCTI is the protected graph boundary. NarrowCTI should avoid creating new
OpenCTI entities or relationships until source evidence, policy, confidence and
deduplication checks are satisfied.

Secrets and local runtime state must remain outside versioned documentation and
examples. Real `.env` files are local only.

## Validation Responsibilities

v0.7 closure validates the audit-first foundation:

- Source metadata extraction for OTX, MISP and MITRE.
- Graph evidence and graph candidate generation.
- Graph candidate policy reasons.
- Decision audit and quarantine metadata.
- STIX object and relationship creation.
- Safe in-memory STIX preview behavior and guarded OpenCTI graph promotion.
- TLP, source, score, actor, arsenal, ATT&CK, sector and geography filters.
- Quarantine release behavior.
- Comparison with official OpenCTI connector mappings.

Before real graph export is enabled outside a bounded lab run, validation must
additionally cover OpenCTI import behavior, deduplication against existing
OpenCTI graph data and canonical MITRE ATT&CK lookup against the OpenCTI graph.

Current validation is still anchored in the existing suite:

```text
.\scripts\validate-v0.6.ps1
```

The script name is historical. It currently validates the active codebase,
including v0.7 graph evidence and graph candidate tests.

Operational dry-run evidence from the local OpenCTI/MISP lab is tracked in
`docs/operational-validation-v0.7.md`. That evidence currently confirms
observable graph metadata, graph export planning, STIX preview summaries,
contextual scoring evidence, MISP guardrails and real MISP Galaxy
threat-actor/victimology extraction without enabling real graph promotion.

## Related Documents

- `docs/graph-enrichment-v0.7.md`
- `docs/mitre-curation-architecture-v0.7.md`
- `docs/metadata-validation-v0.7.md`
- `docs/source-ingestion-modes-v0.7.md`
- `docs/source-adapter-onboarding-v0.7.md`
- `docs/misp-official-connector-mapping-v0.7.md`
- `docs/otx-official-connector-mapping-v0.7.md`
- `docs/contextual-scoring-reference-v0.7.md`
- `docs/operational-validation-v0.7.md`
- `docs/release-v0.7.0.md`

## Architecture Decision

v0.7 is the graph enrichment foundation, not the final graph export release.

The correct product posture is:

```text
validate metadata deeply
  -> normalize graph candidates
  -> use MITRE as curation context, not as a duplicate ATT&CK importer
  -> expose policy and audit decisions
  -> prove compatibility with OpenCTI
  -> then promote graph-aware STIX export
```

This keeps NarrowCTI aligned with its enterprise goal: a professional CTI
gateway that improves OpenCTI graph quality instead of flooding it with
low-confidence feed artifacts.
