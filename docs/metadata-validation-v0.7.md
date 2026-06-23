# Source Metadata Validation - v0.7.0

## Purpose

This document validates how far NarrowCTI currently maps OTX and MITRE ATT&CK
metadata toward the v0.7 graph-enrichment objective.

The target is not to copy every source field into OpenCTI. The target is to
decide, with evidence, which fields should become graph objects,
relationships, labels, markings, external references, scoring inputs,
quarantine context or audit-only provenance.

## Validation Inputs

- LevelBlue OTX External API schema for pulse fields:
  `https://otx.alienvault.com/assets/static/external_api.html`
- OTX pulse enrichment schema cross-check:
  `https://docs.panther.com/enrichment/otx`
- MITRE ATT&CK STIX data repository:
  `https://github.com/mitre-attack/attack-stix-data`
- MITRE ATT&CK Data Model schema:
  `https://mitre-attack.github.io/attack-data-model/schemas/`
- Official OpenCTI AlienVault connector image:
  `opencti/connector-alienvault:6.9.4`
- Local validation snapshot:
  `state/mitre_attack_cache.json`, generated `2026-06-22T23:22:23Z`,
  `858` techniques, `858` with tactics, `858` with STIX ids, `12`
  deprecated, `149` revoked.

## Current Implementation Summary

NarrowCTI v0.7 currently has an audit-first graph evidence layer:

- `connectors/otx/entity_extraction.py` extracts OTX metadata hints.
- `core/mitre_attack.py` normalizes Enterprise ATT&CK techniques.
- `core/graph_evidence.py` converts OTX, MISP and MITRE metadata into
  `graph_evidence` records.
- `core/graph_candidates.py` converts evidence into normalized
  `graph_candidates` for audit and future STIX graph export. Each candidate
  carries object confidence, relationship confidence and normalized source
  provenance.
- OTX and MISP processors write `graph_evidence` and `graph_candidates` into
  decision audit and quarantine metadata.
- OTX and MISP processors also write `graph_candidate_policy` into decision
  audit and quarantine metadata so operators can see accepted and held graph
  candidates before any graph export exists.
- The STIX exporter still emits the stable v0.6 `Report + Indicator` bundle.

This is intentional. v0.7 should validate graph candidates before creating new
OpenCTI entities and relationships.

## OTX Metadata Coverage

| OTX field | Meaning | Current NarrowCTI mapping | Target OpenCTI/STIX use | Status |
| --- | --- | --- | --- | --- |
| `id` | Pulse stable id | Source external id, state key, quarantine id input | Report external reference, provenance, dedup key | Partial |
| `name` | Pulse title | Candidate/report title | `report.name` | Implemented |
| `description` | Pulse narrative | Candidate/report description | `report.description`, future note/evidence text | Implemented |
| `created` | Pulse creation time | Age/scoring input, candidate created | `report.published`, recency policy | Partial |
| `modified` | Pulse update time | Preserved in raw snapshot only | `modified`, update/dedup signal | Pending |
| `pulse_source` | Web/API origin | Preserved in raw snapshot only | Source provenance/scoring input | Pending |
| `TLP` / `tlp` | Sharing marking | Extracted as `marking` evidence | `marking-definition` / OpenCTI marking | Audit-ready |
| `tags` | Free labels | Extracted as low-confidence `tag` evidence | Labels, weak extraction candidates, policy filters | Audit-ready |
| `industries` | Target sector hints | Extracted as `target_sector` evidence | Sector/victimology identity, `targets` relation | Audit-ready |
| `targeted_countries` | Target country hints | Extracted as `target_country` evidence | `location`, `targets` relation | Audit-ready |
| `target_countries` | Alternate country field seen in normalized OTX schemas | Extracted as alias for `targeted_countries` | `location`, `targets` relation | Implemented in v0.7 |
| `malware_families` | Malware family objects or names | Extracted as `malware` evidence, including `display_name` objects | `malware` or `tool`, arsenal context | Audit-ready |
| `attack_ids` | ATT&CK technique object/name/id hints | Extracted and resolved through MITRE cache | `attack-pattern`, tactic context | Audit-ready |
| `references` | External report URLs | Extracted as `external_reference` evidence | External references on report/entities | Audit-ready |
| `indicators` | IoCs | Existing indicator export and dedup | `indicator`, future SCO/observed-data/sighting | Partial |
| `indicator_type_counts` | Aggregate indicator types | Preserved in raw snapshot only | Scoring, report summary, quality checks | Pending |
| Indicator `created` / `expiration` | Indicator timing | Not normalized today | Indicator validity, sighting/observed-data windows | Pending |
| Indicator type/value metadata | IoC semantics | Normalized into supported indicator patterns | Indicator and future SCO type mapping | Partial |
| `adversary` | Actor/adversary hint | Extracted as `threat_actor` evidence | `threat-actor` or `intrusion-set` with alias policy | Audit-ready |
| `groups` | OTX user/group context, not threat group | Preserved in raw snapshot only | Source provenance only, not actor mapping | Pending |
| `author` / `author_name` | Pulse producer | Preserved in raw snapshot only | Source reputation, confidence, provenance | Pending |
| `public` | Sharing/public flag | Preserved in raw snapshot only | Handling/provenance policy | Pending |
| `revision` / `is_modified` / `cloned_from` | Pulse lifecycle | Preserved in raw snapshot only | Update detection, dedup and provenance | Pending |
| `vote`, `votes_count`, `upvotes_count`, `downvotes_count` | Community signal | Preserved in raw snapshot only | Source confidence/scoring feature | Pending |
| `validator_count` | Validation/community trust hint | Preserved in raw snapshot only | Source confidence/scoring feature | Pending |
| `subscriber_count`, `export_count`, `comment_count`, `follower_count` | Popularity/engagement | Preserved in raw snapshot only | Optional quality signal, not graph entity | Pending |
| `threat_hunter_has_agents`, `threat_hunter_scannable` | OTX operational hints | Preserved in raw snapshot only | Optional scoring/handling signal | Pending |

## OTX Findings

Current OTX graph-evidence coverage is good for the high-value CTI fields:
actor hint, malware family, ATT&CK ids, sectors, countries, TLP, references and
tags.

The official OpenCTI AlienVault connector mapping was also validated in
`docs/otx-official-connector-mapping-v0.7.md`. It confirms that OTX-specific
graph export should cover reports, observables, indicators, Intrusion Sets,
Malware, Attack Patterns, sectors, countries, vulnerabilities and relationships
such as `uses`, `targets`, `based-on` and `indicates`.

The remaining gap is not basic extraction; it is intelligent promotion:

- Actor names need alias normalization and corroboration before strong
  `intrusion-set` or `threat-actor` creation.
- Malware family values need malware/tool classification and alias handling.
- Sector/country values need controlled vocabulary normalization.
- OTX community signals should influence confidence but should not create graph
  entities.
- Indicator-specific timestamps and expiration should feed indicator validity
  and future observations.
- OTX `groups` must not be confused with ATT&CK groups or threat actors.

## MITRE ATT&CK Coverage

| MITRE evidence | Current NarrowCTI mapping | Target OpenCTI/STIX use | Status |
| --- | --- | --- | --- |
| `attack-pattern.id` | Stored as `stix_id` | Stable reference to ATT&CK technique object | Implemented |
| ATT&CK external id `Txxxx` / `Txxxx.xxx` | Stored as `attack_id`, resolver key | Human-readable technique key, policy filter | Implemented |
| `name` | Stored and exposed in resolver | `attack-pattern.name` | Implemented |
| `description` | Stored in normalized cache | Technique description / note / relationship context | Implemented in v0.7 |
| `external_references.url` | Stored as `url` and emitted as `external_reference` candidate | External reference to ATT&CK page | Candidate audit-ready |
| `kill_chain_phases` | Normalized into tactics and kill chain phase attributes | Tactic filters and ATT&CK phase context | Candidate audit-ready |
| `x_mitre_platforms` | Stored as `platforms` and emitted as `attack_platform` candidates | Target platform filters and detection context | Candidate audit-ready |
| `x_mitre_data_sources` | Stored as `data_sources` and emitted as `attack_data_source` candidates | Hunting/detection guidance context | Candidate audit-ready |
| `x_mitre_detection` | Stored as `detection` and emitted as `detection_guidance` note candidates | Analyst guidance and future detection mapping | Candidate audit-ready |
| `x_mitre_domains` | Stored as `domains` | Enterprise/mobile/ICS scope filter | Implemented in v0.7 |
| `x_mitre_version` | Stored as `version` | ATT&CK object lifecycle provenance | Implemented in v0.7 |
| `x_mitre_attack_spec_version` | Stored as `attack_spec_version` | Parser compatibility/audit | Implemented in v0.7 |
| `created` / `modified` | Stored in normalized cache | Object freshness and update audit | Implemented in v0.7 |
| `x_mitre_is_subtechnique` | Stored as `is_subtechnique` | Parent/sub-technique graph logic | Implemented in v0.7 |
| `revoked` | Stored and exposed | Prevent stale graph promotion or mark as revoked | Implemented |
| `x_mitre_deprecated` | Stored and exposed | Prevent stale graph promotion or mark as deprecated | Implemented |
| ATT&CK groups | Not imported today | `intrusion-set`, aliases, relationships | Pending |
| ATT&CK software | Not imported today | `malware` / `tool`, arsenal relationships | Pending |
| ATT&CK campaigns | Not imported today | `campaign`, attribution and uses relationships | Pending |
| ATT&CK data sources/components | Not imported as objects today | Detection/hunting graph context | Pending |
| ATT&CK relationship objects | Not imported today | `uses`, `subtechnique-of`, `attributed-to` graph | Pending |
| ATT&CK tactics as objects | Not imported today | `x-mitre-tactic` or OpenCTI tactic context | Pending |

## MITRE Findings

NarrowCTI now preserves enough technique-level metadata to enrich OTX-derived
ATT&CK ids with technique name, tactic, platforms, data sources, detection text,
domain, versioning and lifecycle state. Technique-level MITRE context is now
also emitted as normalized graph candidates for external references, kill chain
phase attributes, platforms, data sources and detection guidance.

The main v0.7 gap is broader ATT&CK graph coverage. MITRE is not just a
technique lookup table. For the product goal, NarrowCTI eventually needs to
understand ATT&CK groups, software, campaigns, data sources and relationship
objects so OpenCTI can show richer pivots across actor, arsenal, technique and
detection context.

## Current Mapping Depth

The current mapping depth is:

```text
OTX raw pulse
  -> OTX normalized candidate
  -> otx_entities metadata
  -> mitre_attack resolved metadata
  -> graph_evidence audit records
  -> graph_candidates audit records
  -> stable Report + Indicator STIX export
```

This means v0.7 has crossed the first important line: the gateway can now
explain which graph objects and relationships it could create, why they were
accepted by graph policy or why they were held back.

It has not yet crossed the second line: creating those graph objects and
relationships in OpenCTI.

## Required Intelligent Mapping Before Graph Export

Before NarrowCTI promotes audit evidence into graph objects, these controls are
required:

- Alias normalization for actors, intrusion sets, malware and tools.
- Confidence policy by source field and source reputation.
- Relationship policy that distinguishes `related-to`, `uses`, `targets`,
  `indicates` and `attributed-to`.
- Relationship confidence and source provenance are now present in normalized
  graph candidates, but still need graph-aware STIX export and OpenCTI import
  validation.
- Vocabulary normalization for sectors, countries, platforms and tactics.
- Revoked/deprecated handling for MITRE objects.
- Duplicate graph entity detection before STIX export.
- External reference preservation on every generated object or relationship.
- Audit trail that shows source field, raw value, normalized value and decision.

## v0.7 Completion Criteria For OTX And MITRE

For OTX and MITRE, v0.7 should not be considered complete until:

- OTX sample payloads produce graph candidates for actor, malware, technique,
  tactic, sector, country, marking, reference and indicator context.
- MITRE sample/cache payloads produce graph candidates for technique,
  sub-technique, tactic, platform, data source and detection context.
- Weak OTX actor/malware/tag values remain low-confidence until corroborated.
- Deprecated or revoked ATT&CK objects are not promoted as clean current facts.
- The graph-aware STIX builder can dry-run the objects and relationships that
  would be exported.
- OpenCTI validation confirms entities and relationships land in the expected
  graph areas without duplicate or misleading nodes.
