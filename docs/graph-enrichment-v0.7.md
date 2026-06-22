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
| `references` | `external_references` | Preserve evidence trail. |
| TLP fields/tags | `marking-definition` / OpenCTI marking | Must preserve sharing constraints. |
| `tags` | labels plus extraction candidates | Tags are weak unless mapped to a known taxonomy. |

### MISP

MISP must receive a broader validation pass than v0.6. The NarrowCTI MISP
adapter should inspect representative raw MISP events and map:

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

### MITRE ATT&CK

MITRE remains reference data, not an IoC feed. v0.7 should use the local cache
to create or enrich:

| ATT&CK evidence | STIX/OpenCTI target |
| --- | --- |
| Technique/sub-technique | `attack-pattern` |
| Tactic | `kill_chain_phases` and tactic filters |
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

Confidence should be policy-driven. Example:

| Evidence type | Default confidence |
| --- | --- |
| MITRE ATT&CK technique id resolved from official cache | High |
| MISP galaxy cluster with known taxonomy | Medium/high |
| OTX `malware_families` field | Medium |
| OTX free-text `adversary` field | Medium/low until corroborated |
| Generic tag containing actor/malware-like text | Low |
| Analyst-released quarantine item | Configurable boost with audit evidence |

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
NARROWCTI_GRAPH_EXPORT_MODE=dry-run
```

These filters must not hide decisions. If intelligence is blocked because it is
outside actor, arsenal, tactic, sector or geography policy, the decision audit
must explain that clearly.

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

1. Create a shared graph candidate model.
2. Expand OTX metadata mapping into graph candidates.
3. Add MISP metadata and galaxy extraction fixtures.
4. Extend MITRE cache usage beyond technique names into reusable graph
   references.
5. Build a graph-aware STIX exporter.
6. Add relationship confidence and provenance.
7. Add enterprise graph filters.
8. Add graph deduplication and optional OpenCTI graph lookup.
9. Add graph export dry-run reporting.
10. Validate in OpenCTI with OTX and MISP samples.

## Decision

v0.7 is the release where NarrowCTI should stop behaving like an IoC-forwarding
connector at export time. The gateway must start shaping OpenCTI into a richer
CTI knowledge base by validating source metadata deeply, building high-quality
STIX objects and relationships, and preserving enough evidence for analysts to
trust the graph.
