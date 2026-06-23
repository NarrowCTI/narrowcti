# Graph Enrichment And Enterprise Filters - v0.7.0

## Purpose

v0.7 must move NarrowCTI from curated `Report + Indicator` export into rich,
validated STIX/OpenCTI graph enrichment.

The goal is not only to send more objects to OpenCTI. The goal is to make
OpenCTI more useful as an intelligence graph: analysts should pivot from a
report or indicator into actors, intrusion sets, malware, tools, ATT&CK
techniques, infrastructure, vulnerabilities, campaigns, victimology, locations,
confidence, provenance and relationship evidence.

This is the product step that should bring NarrowCTI closer to the user
experience expected from mature commercial CTI offerings such as Kaspersky
Threat Intelligence: rich context, useful pivots, explainable relationships and
high-signal visualization. NarrowCTI should not claim parity with commercial
providers, but v0.7 should deliberately move the OpenCTI environment toward
that level of operational intelligence visibility.

## Problem To Solve

The current exporter is intentionally conservative. It creates:

- `identity`
- `indicator`
- `report`

That is safe, but it does not fully populate OpenCTI graph areas such as
Threats, Arsenal, Techniques, Entities, Locations, Observations and richer
Analyses. A MISP event imported directly can appear richer because MISP may
carry tags, galaxies, objects, clusters, ATT&CK mappings and source-specific
relationships that NarrowCTI currently preserves mainly as metadata or decision
evidence.

v0.7 must close this gap without blindly trusting feed metadata.

## Product Principles

- Source metadata must be validated before it becomes graph knowledge.
- Rich graph export must be evidence-backed, not decorative.
- Every inferred object or relationship must retain source provenance.
- Relationship confidence must be explicit and auditable.
- Weak or ambiguous metadata should become labels, notes or quarantine evidence
  before it becomes a strong graph relationship.
- OpenCTI graph hygiene matters: the gateway must avoid duplicate entities,
  noisy aliases and low-confidence relationship pollution.
- Feed-specific richness should be normalized into a shared NarrowCTI graph
  candidate model before STIX export.

## Source Metadata Validation

v0.7 requires a deeper metadata validation pass for each source. The objective
is to understand what each feed can really provide, how reliable each field is,
and how it should map to STIX/OpenCTI.

For every supported source, NarrowCTI should document and test:

- Raw payload fields available from the source.
- Which fields are stable identifiers versus display labels.
- Which fields are authoritative and which are weak hints.
- Which fields represent actors, malware, tools, techniques, sectors,
  countries, vulnerabilities, infrastructure, campaigns, references and TLP.
- Whether the field comes from the feed provider, an upstream taxonomy, a tag,
  a user-created object or an enrichment process.
- Whether the field should produce a STIX object, relationship, label,
  external reference, note or quarantine-only evidence.
- Which confidence value should be applied by default.
- Which validation rule prevents bad graph enrichment.

OTX and MITRE ATT&CK metadata coverage is tracked in
`docs/metadata-validation-v0.7.md`. MISP official connector compatibility is
tracked in `docs/misp-official-connector-mapping-v0.7.md`, and OTX official
connector compatibility is tracked in
`docs/otx-official-connector-mapping-v0.7.md`. Contextual scoring references
from the OpenCTI scoring-calculator connector are tracked in
`docs/contextual-scoring-reference-v0.7.md`.

The source ingestion architecture for direct, MISP collector and hybrid modes
is tracked in `docs/source-ingestion-modes-v0.7.md`.

The consolidated v0.7 architecture, including runtime boundaries, current
contracts, policy surface and graph-export promotion path, is tracked in
`docs/architecture-v0.7.md`.

## Initial Source Focus

### OTX

OTX v0.6 already extracts useful entity hints. v0.7 should validate and map:

| OTX evidence | STIX/OpenCTI target | Notes |
| --- | --- | --- |
| `indicators` | `indicator`, SCOs, future `observed-data`/`sighting` | Keep current indicator hygiene and deduplication. |
| `adversary` | `threat-actor` or `intrusion-set` | Requires confidence and alias handling. |
| `malware_families` | `malware` or `tool` | Should not be treated as high-confidence attribution by itself. |
| `attack_ids` | `attack-pattern` | Resolve through local MITRE cache and include tactics. |
| `industries` | sector `identity` or OpenCTI sector entity | Treat as victimology evidence. |
| `targeted_countries` | `location` | Treat as victimology/geography evidence. |
| `target_countries` | `location` | Alias accepted from normalized OTX schemas. |
| `references` | `external_references` | Preserve evidence trail. |
| TLP fields/tags | `marking-definition` / OpenCTI marking | Must preserve sharing constraints. |
| `tags` | labels plus extraction candidates | Tags are weak unless mapped to a known taxonomy. |

The code-level baseline from `opencti/connector-alienvault:6.9.4` shows that
direct OTX import can create reports, observables, indicators, Intrusion Sets,
Malware, Attack Patterns, sector identities, country locations, vulnerabilities
and relationships such as `uses`, `targets`, `based-on` and `indicates`.
NarrowCTI should keep its custom OTX runtime and curation controls, but the
official connector is the source-specific compatibility baseline for how OTX
evidence should eventually land in the OpenCTI graph.

### MISP

MISP must receive a broader validation pass than v0.6. The NarrowCTI MISP
adapter should inspect representative raw MISP events and map them against the
official OpenCTI MISP connector behavior. The official connector is the
compatibility baseline for how curated MISP evidence should land in the OpenCTI
graph, while NarrowCTI remains responsible for curation before graph promotion.

| MISP evidence | STIX/OpenCTI target | Notes |
| --- | --- | --- |
| Event `info`, `uuid`, `date`, `timestamp`, `published` | `report` / provenance fields | Preserve source identity and publication state. |
| Attributes and object attributes | `indicator`, SCOs, infrastructure candidates | Respect `to_ids`, object relations and type semantics. |
| Tags and taxonomies | labels, markings, sectors, weak graph hints | TLP and taxonomy context must be parsed carefully. |
| Galaxy clusters | actors, malware, tools, ATT&CK, campaigns | Strong candidate for graph enrichment when taxonomy is known. |
| MITRE ATT&CK galaxies | `attack-pattern` | Resolve against MITRE cache when possible. |
| Threat actor galaxies | `intrusion-set` or `threat-actor` | Requires aliases and confidence. |
| Malware/tool galaxies | `malware` or `tool` | Useful for Arsenal enrichment. |
| Sector/geography tags | sector `identity`, `location` | Victimology context. |
| CVE attributes/tags | `vulnerability` | Can connect reports, malware and exploited technology. |
| Organization/sharing/TLP | markings and provenance | Do not lose handling constraints. |

The code-level baseline from `opencti/connector-misp:6.9.4` shows that direct
MISP import can create reports, indicators, observables, notes, labels,
markings, Intrusion Sets, Malware, Tools, Attack Patterns, sectors, countries,
regions and relationships such as `based-on`, `indicates`, `related-to` and
`uses`. NarrowCTI should reproduce those graph semantics only when evidence
passes its scoring, policy, deduplication, guardrail and confidence checks.

### MITRE ATT&CK

MITRE remains reference data, not an IoC feed. v0.7 should use the local cache
to create or enrich:

| ATT&CK evidence | STIX/OpenCTI target |
| --- | --- |
| Technique/sub-technique | `attack-pattern` |
| Tactic | `kill_chain_phases` and tactic filters |
| Platforms and domains | filtering and detection context |
| Data sources and detection text | hunting and detection guidance |
| Group | `intrusion-set` |
| Software | `malware` or `tool` |
| Campaign | `campaign` |
| `uses` relationships | `relationship` |
| External ATT&CK references | `external_references` |

## Target STIX/OpenCTI Objects

v0.7 should introduce a richer STIX builder that can create and link:

- `report`
- `indicator`
- STIX cyber observable objects where appropriate
- `observed-data` where source evidence supports sightings
- `malware`
- `tool`
- `attack-pattern`
- `intrusion-set`
- `threat-actor`
- `campaign`
- `vulnerability`
- `infrastructure`
- `identity` for sectors, organizations or victim classes
- `location`
- `marking-definition`
- `note` for weak or analyst-review context
- `relationship`
- future `sighting`

## Ingestion Modes

NarrowCTI must support environments with and without MISP. The target product
architecture supports three modes:

```text
Direct source mode:
  External source -> NarrowCTI -> OpenCTI

MISP collector mode:
  External sources -> MISP -> NarrowCTI -> OpenCTI

Hybrid mode:
  Some sources -> MISP -> NarrowCTI
  Other sources -> NarrowCTI directly
  NarrowCTI -> OpenCTI
```

Official OpenCTI connectors should be used as mapping references for graph
compatibility, not as replacements for NarrowCTI's curation path. Future
direct sources should enter through source adapters and produce graph evidence
and graph candidates before STIX export.

## Relationship Model

Relationships should be created only when source evidence supports them.

Target relationship patterns:

```text
report
  -> object_refs -> indicators, malware, tools, attack patterns, actors,
                    sectors, countries, vulnerabilities and infrastructure

indicator
  -> indicates -> malware, campaign, infrastructure or intrusion set

intrusion-set / threat-actor
  -> uses -> malware, tools and attack patterns
  -> targets -> sectors, countries, regions or organizations

malware / tool
  -> uses -> attack patterns
  -> targets -> sectors or regions when source evidence supports it

campaign
  -> attributed-to -> intrusion set or threat actor
  -> uses -> malware, tools, infrastructure and attack patterns
  -> targets -> sectors, countries or organizations
```

When evidence is weak, use lower confidence, `related-to`, labels or notes
instead of strong attribution.

## Confidence And Provenance

Every graph candidate should carry:

- Source key such as `alienvault:otx`, `misp:misp` or `mitre:attack`.
- Source object id such as OTX pulse id or MISP event uuid.
- Source field name that produced the object or relationship.
- Extracted raw value.
- Normalized value.
- Confidence score.
- Relationship confidence.
- Decision reason.
- TLP/marking evidence.
- References.
- Created/modified/published timestamps when available.

The current audit-only `core/graph_candidates.py` model now carries explicit
`relationship_confidence` and normalized `provenance` derived from source
evidence. This gives the future graph-aware STIX builder enough context to
explain why an object or relationship would be created before the gateway
promotes it into OpenCTI.

Confidence should be policy-driven. Example:

| Evidence type | Default confidence |
| --- | --- |
| MITRE ATT&CK technique id resolved from official cache | High |
| MISP galaxy cluster with known taxonomy | Medium/high |
| OTX `malware_families` field | Medium |
| OTX free-text `adversary` field | Medium/low until corroborated |
| Generic tag containing actor/malware-like text | Low |
| Analyst-released quarantine item | Configurable boost with audit evidence |

## Contextual Scoring

v0.7 should treat graph evidence as a future scoring input, not only as export
metadata. The OpenCTI `scoring-calculator` internal enrichment connector
validates a useful pattern: indicator scores can be increased by high-value
context across Threat, Toolbox, Location, Sector, TTP and Author categories.

NarrowCTI should adapt that pattern before ingestion. The current base score in
`core/scoring.py` should remain responsible for source confidence, query
relevance, indicator volume and recency. A contextual scoring layer should then
apply a bounded relative impact based on graph evidence:

```text
contextual_score = base_score + ((100 - base_score) * impact_ratio)
```

The first implementation must run in dry-run/audit mode and record every
contextual adjustment with category, priority, matched value, source field and
impact. It must not bypass TLP, quarantine, confidence or provenance policy.

The detailed design and backlog are tracked in
`docs/contextual-scoring-reference-v0.7.md`.

## Enterprise Filters

v0.7 should add visible policy controls for graph-aware curation:

```env
NARROWCTI_ALLOWED_THREAT_ACTORS=
NARROWCTI_ALLOWED_INTRUSION_SETS=
NARROWCTI_ALLOWED_MALWARE_FAMILIES=
NARROWCTI_ALLOWED_TOOLS=
NARROWCTI_ALLOWED_ATTACK_PATTERN_IDS=
NARROWCTI_ALLOWED_MITRE_TACTICS=
NARROWCTI_ALLOWED_TARGET_SECTORS=
NARROWCTI_ALLOWED_TARGET_COUNTRIES=
NARROWCTI_ALLOWED_VULNERABILITIES=
NARROWCTI_MIN_ENTITY_CONFIDENCE=50
NARROWCTI_MIN_RELATIONSHIP_CONFIDENCE=60
NARROWCTI_REQUIRE_RELATIONSHIP_PROVENANCE=true
NARROWCTI_ALLOWED_GRAPH_ENTITY_TYPES=attack_pattern,malware,threat_actor
NARROWCTI_ALLOWED_GRAPH_STIX_OBJECT_TYPES=attack-pattern,malware,threat-actor
NARROWCTI_GRAPH_EXPORT_MODE=dry-run
```

These filters must not hide decisions. If intelligence is blocked because it is
outside actor, arsenal, tactic, sector or geography policy, the decision audit
must explain that clearly.

The first implemented v0.7 filter layer is audit-only. OTX and MISP metadata
now include `graph_candidate_policy` with accepted and held candidates, held
reason counts, entity confidence checks, relationship confidence checks,
optional provenance requirements and allowed graph entity/STIX object filters.
This does not block source ingestion or export yet; it makes the future graph
promotion decision visible and testable first.

OTX and MISP metadata also include `graph_export_plan`. This turns the
candidate policy result into an operator-visible plan. In `audit` mode the plan
records candidates as audit-only. In `dry-run` mode it records accepted
candidates as `would_create` actions and counts the graph objects and
relationships that would be attempted later. `export` mode is explicitly
blocked until the graph-aware STIX builder, graph deduplication and OpenCTI
validation are complete.

`graph_export_plan` now also performs intra-plan graph hygiene. It creates
deterministic entity and relationship deduplication keys, marks duplicate
entities and duplicate relationships, and reduces dry-run would-create object
or relationship counts when duplicate graph intent appears inside the same
decision record. This is not yet OpenCTI-side deduplication; it is the first
safe dedup layer before persisted graph lookup and real export.

The decision audit report now aggregates `graph_export_plan` evidence across
decision audit records. Operators can see graph export modes, statuses,
actions, accepted and held candidate counts, would-create object/relationship
counts, deduplicated entity/relationship counts, held reasons and source/query
rollups without reading raw JSONL.

## Graph Hygiene

v0.7 graph enrichment must avoid polluting OpenCTI.

Required controls:

- Stable IDs or deterministic names where STIX allows safe reuse.
- Alias normalization for actors, malware and tools.
- Relationship deduplication.
- Optional OpenCTI lookup for existing objects and relationships.
- Separate handling for strong relationships versus weak `related-to` links.
- Confidence thresholds before creating relationship objects.
- Quarantine or dry-run mode for low-confidence graph candidates.
- Reporting for created, skipped, deduplicated and quarantined graph objects.

## Validation Plan

v0.7 validation must be broader than v0.6 because the risk shifts from
indicator volume to graph quality.

Minimum validation:

- Source payload fixture library for OTX, MISP and MITRE.
- Field-level metadata extraction tests for each source.
- STIX object creation tests for actors, malware, tools, ATT&CK, sectors,
  countries, vulnerabilities and infrastructure.
- Relationship creation tests with confidence and provenance.
- Negative tests proving weak evidence does not create strong attribution.
- Deduplication tests for repeated entities and repeated relationships.
- Dry-run graph export tests.
- OpenCTI lab validation showing the expected tabs populate:
  Threats, Arsenal, Techniques, Entities, Locations, Observations and Analyses.
- Before/after validation comparing a direct MISP import with NarrowCTI-curated
  graph export for the same event.
- Decision audit and report validation showing what graph context was created,
  skipped, quarantined or deduplicated.

## Acceptance Criteria

v0.7 should not be considered complete until:

- NarrowCTI can export more than `Report + Indicator`.
- At least one OTX sample produces actor/malware/ATT&CK/victimology graph
  candidates when source evidence exists.
- At least one MISP sample maps tags, attributes and galaxies into richer graph
  candidates when source evidence exists.
- MITRE technique ids resolve into `attack-pattern` objects with tactic context.
- Relationship confidence and provenance are visible in audit evidence.
- Low-confidence metadata is not promoted blindly into high-confidence graph
  knowledge.
- OpenCTI graph views show richer pivots without obvious duplicate pollution.
- Operators can explain why each graph object and relationship was created or
  held back.

## Out Of Scope For v0.7

- Customer-facing UI.
- Full commercial CTI-provider parity.
- Automated attribution claims without source evidence.
- Enterprise reporting UI.
- Paid external enrichment integrations.
- License enforcement.

## Implementation Backlog

1. Create a shared graph candidate model. Initial audit-only foundation added
   in `core/graph_evidence.py`; normalized graph candidates are now represented
   in `core/graph_candidates.py` and attached to OTX/MISP audit metadata.
2. Expand OTX metadata mapping into graph candidates. Initial OTX and MITRE
   evidence mapping is now present as `graph_evidence` and `graph_candidates`
   in decision/quarantine metadata, and the official AlienVault connector
   mapping has been validated as the source-specific graph baseline.
3. Add MISP metadata and galaxy extraction fixtures. Initial provenance,
   original-source, TLP and tag evidence mapping is present as `graph_evidence`
   and `graph_candidates`; MISP official connector compatibility has been
   validated as the graph baseline; MISP galaxy extraction remains pending.
4. Extend MITRE cache usage beyond technique names into reusable graph
   references. Technique-level external references, kill chain phase
   attributes, platforms, data sources and detection guidance are now emitted
   as audit-only graph evidence/candidates.
5. Build a graph-aware STIX exporter.
6. Add relationship confidence and provenance. Initial audit-only support is
   implemented in `core/graph_candidates.py`.
7. Add enterprise graph filters. Initial audit-only candidate policy is
   implemented for entity confidence, relationship confidence, provenance and
   allowed graph entity/STIX object types.
8. Add graph deduplication and optional OpenCTI graph lookup. Initial
   intra-plan entity and relationship deduplication is implemented in
   `graph_export_plan`; persisted graph state and OpenCTI lookup remain
   pending.
9. Add graph export dry-run reporting. Initial per-decision
   `graph_export_plan` metadata and decision-audit aggregate rollups are
   implemented for audit/dry-run visibility; OpenCTI comparison evidence
   remains pending.
10. Validate in OpenCTI with OTX and MISP samples.
11. Compare a direct official MISP connector import with a NarrowCTI-curated
    import for the same event and document object/relationship differences.
12. Add contextual scoring dry-run evidence using graph categories inspired by
    the OpenCTI scoring-calculator reference.
13. Document and preflight the active ingestion mode: direct, MISP collector or
    hybrid.

## Decision

v0.7 is the release where NarrowCTI should stop behaving like an IoC-forwarding
connector at export time. The gateway must start shaping OpenCTI into a richer
CTI knowledge base by validating source metadata deeply, building high-quality
STIX objects and relationships, and preserving enough evidence for analysts to
trust the graph.
