# MISP Official Connector Mapping Baseline - v0.7.0

## Purpose

This document records how the official OpenCTI MISP connector maps MISP data
into STIX/OpenCTI and how NarrowCTI should use that behavior as a compatibility
baseline for v0.7 graph enrichment.

The goal is not to replace curation with a blind clone of the official
connector. The goal is to make NarrowCTI-created MISP imports land in OpenCTI
with equivalent graph semantics after NarrowCTI has applied policy, scoring,
deduplication, guardrails, confidence and quarantine decisions.

## Validation Evidence

Local validation inspected the official connector image already used by the lab
Compose environment:

```text
image: opencti/connector-misp:6.9.4
digest: sha256:0ce614eebf82564e8018e74dcd18d590ec9174b38484ab66335e7cf523ebc76c
size: 46482829 bytes
```

Important files inspected inside the image:

```text
/opt/opencti-connector-misp/misp.py
/opt/opencti-connector-misp/connector/config_loader.py
/opt/opencti-connector-misp/connector/threats_guesser.py
/opt/opencti-connector-misp/connector/use_cases/convert_event.py
/opt/opencti-connector-misp/connector/use_cases/convert_attribute.py
/opt/opencti-connector-misp/connector/use_cases/convert_object.py
/opt/opencti-connector-misp/connector/use_cases/convert_galaxy.py
/opt/opencti-connector-misp/connector/use_cases/convert_tag.py
/opt/opencti-connector-misp/connector/use_cases/convert_event_report.py
```

No runtime credentials or MISP API keys are required for this code-level
mapping validation.

## Official Connector Flow

The official connector follows this high-level flow:

```text
MISP event search
  -> event-level filters
  -> EventConverter
  -> STIX bundle
  -> OpenCTI send_stix2_bundle(cleanup_inconsistent_bundle=true)
```

The `EventConverter` is configured with feature toggles for:

- Creating one OpenCTI report per MISP event.
- Creating indicators from MISP attributes.
- Creating cyber observables from MISP attributes.
- Creating text observables for MISP objects.
- Creating labels, authors and markings from tags.
- Guessing threat entities from tags through OpenCTI lookup.
- Propagating report labels.
- Assigning fallback score to non-detection attributes.

For very large events, the connector disables relationship generation when the
event has `10000` or more top-level attributes. This avoids a graph explosion,
but it is not the same as NarrowCTI's bounded per-run, per-event and per-IoC
guardrails.

## Official Event Mapping

| MISP data | Official STIX/OpenCTI target | Notes |
| --- | --- | --- |
| Event `Orgc` | `identity` author | Uses organization identity when present. |
| Event `info` | `report.name` and default description | Report type defaults to `misp-event`. |
| Event `date` | `report.published` and `report.created` | Converted to UTC. |
| Event `timestamp` | `report.modified` | Converted to UTC. |
| Event tags | labels, markings, author, entity candidates | Depends on converter config and tag taxonomy. |
| Event galaxies | domain entities | Threat actor, intrusion set, malware, tool, attack pattern, sector, country and region are supported. |
| Event external-analysis links | external references | Added to report or objects. |
| Event PDF attachments | OpenCTI associated files | Controlled by attachment import config. |
| Event reports | `note` | MISP EventReport becomes a STIX Note linked to the report. |
| Event object refs | `relationship` | Attempts to map MISP object references to STIX relationships. |

The report receives `object_refs` for converted indicators, observables,
entities, relationships and notes. When a report would have no object refs, the
official connector inserts a placeholder object to satisfy STIX report
requirements.

## Official Attribute Mapping

The official connector treats MISP attributes as the main source for OpenCTI
Observations and Indicators.

| MISP attribute evidence | Official STIX/OpenCTI target |
| --- | --- |
| `domain`, `hostname`, `url`, email types | Domain, hostname, URL and email observables plus indicators when enabled. |
| `ip-src`, `ip-dst`, `ip-src|port`, `ip-dst|port` | IPv4/IPv6 observables plus optional text port context. |
| `md5`, `sha1`, `sha256`, `filename|hash`, `malware-sample` | File observables and file-hash indicators. |
| `email-subject` | Email message observable. |
| `regkey` | Windows registry key observable. |
| `phone-number`, `text`, `windows-scheduled-task` | OpenCTI custom observables. |
| `github-username` | User account observable. |
| `full-name` | Individual identity. |
| `yara`, `sigma`, `pcre`, `snort`, `suricata` | Indicator using the raw rule pattern and matching `pattern_type`. |
| Attribute tags | Labels, markings and entity objects. |
| Attribute galaxies | Entity objects and relationship context. |
| Attribute sightings | STIX sighting relationship when usable. |

For standard observable-backed indicators, the official connector creates the
indicator from the observable pattern and adds OpenCTI custom properties such
as main observable type, detection flag and score.

## Official Galaxy And Tag Mapping

MISP galaxies are the richest path into the OpenCTI graph.

| MISP galaxy/tag evidence | Official STIX/OpenCTI target |
| --- | --- |
| MISP or MITRE threat actor / intrusion set | `intrusion-set` |
| MITRE tool | `tool` |
| MITRE malware, MISP ransomware, MISP tool, Android and Malpedia galaxies | `malware` with family semantics |
| MITRE attack pattern | `attack-pattern` with `x_mitre_id` when available |
| MISP sector | `identity` with class semantics |
| MISP country | `location` with country semantics |
| MISP region | `location` with region semantics |
| TLP tags | OpenCTI marking definitions |
| PAP tags | OpenCTI PAP marking definitions |
| `creator=` tags | Optional author identity |
| Other non-entity tags | Labels when enabled |

The official connector also supports an optional threat guessing mode that looks
up existing OpenCTI Intrusion Set, Malware, Tool and Attack Pattern entities by
name, MITRE id or aliases. NarrowCTI should treat this as an optional
compatibility behavior, not as default trusted enrichment, because guessed
entities need confidence and audit evidence.

## Official Relationship Model

The official connector creates these important relationships:

| Source | Relationship | Target | Trigger |
| --- | --- | --- | --- |
| Indicator | `based-on` | Observable | Indicator was generated from one or more observables. |
| Indicator | `indicates` | Intrusion Set, Malware, Tool | Event or attribute tags/galaxies provide those entities. |
| Indicator | `related-to` | Country, Sector | Event or attribute tags/galaxies provide victimology/geography. |
| Observable | `related-to` | Intrusion Set, Malware, Tool, Country, Sector | Event or attribute tags/galaxies provide those entities. |
| Malware or Intrusion Set | `uses` | Attack Pattern | ATT&CK attack pattern and malware/intrusion set context are present. |
| MISP object reference source | `related-to` | MISP object reference target | MISP object references can be resolved to generated STIX objects. |
| Sighting organization | `sighting` | Indicator | MISP sightings provide usable organization and timestamp data. |

This relationship model is the key compatibility baseline for NarrowCTI v0.7.
If NarrowCTI imports a curated MISP event, the resulting OpenCTI graph should be
able to show the same kinds of pivots as the official connector: reports,
indicators, observables, actors, arsenal, techniques, sectors, countries,
markings, notes and relationships.

## Official Filters And Controls

The official connector exposes useful MISP-side filters:

- Import tags and excluded tags.
- Creator organization include and exclude lists.
- Owner organization include and exclude lists.
- Keyword filter.
- Distribution level filter.
- Threat level filter.
- Published-only import.
- Date filter field and import-from date.
- Warning-list enforcement.
- Attachment import.
- Tag-to-label, tag-to-marking and tag-to-author behavior.

The official connector maps MISP threat levels to OpenCTI score as:

| MISP threat level | Score |
| --- | --- |
| `1` | `90` |
| `2` | `60` |
| `3` | `30` |
| Other or missing | `50` |

NarrowCTI should preserve this score mapping as a MISP compatibility input, but
it should remain only one input to NarrowCTI's broader curation score.

## Comparison With Current NarrowCTI

| Capability | Official MISP connector | Current NarrowCTI v0.7 state | v0.7 target |
| --- | --- | --- | --- |
| Event report semantics | Rich `misp-event` report with dates, refs, markings, files and notes. | Stable generic report export through `exporters/stix_builder.py`. | Add MISP-compatible report fields after curation. |
| Attribute coverage | Broad observable and indicator mapping. | Bounded IoC extraction for common indicator types. | Expand to official-compatible observable and indicator mapping. |
| Observables | Creates STIX/OpenCTI observables. | Not emitted by current exporter. | Emit observables in graph-aware STIX builder. |
| Indicators | Creates indicators with observable-derived patterns and score metadata. | Creates simple STIX indicators for selected types. | Preserve official pattern semantics plus NarrowCTI score evidence. |
| Galaxies | Converts known galaxies to entities. | Parses common event/object/attribute GalaxyCluster metadata into audit-only graph evidence and candidates for ATT&CK, actor, intrusion set, malware, tool, vulnerability and victimology context. | Convert accepted candidates into official-compatible graph STIX objects after policy, deduplication and OpenCTI validation. |
| Tags | Labels, markings and optional entity extraction. | TLP, generic tags and CVE tags are audit evidence; CVE ids become vulnerability candidates. | Parse more known taxonomy tags, keep weak tags as labels or evidence. |
| Vulnerabilities | Creates vulnerability entities from CVE-oriented evidence. | CVEs from tags, event text, attributes and object attributes become audit-only vulnerability candidates. | Add NVD enrichment and relationship policy before graph export. |
| Relationships | Creates `based-on`, `indicates`, `related-to`, `uses`, sightings and object-reference links. | Not emitted by current exporter. | Add relationship policy with confidence and provenance. |
| Guardrails | Disables relationship generation for very large events. | Has explicit max events, max attributes, max IoCs and oversized-event policy. | Keep NarrowCTI guardrails before official-compatible export. |
| Threat guessing | Optional OpenCTI lookup from tags. | Not implemented. | Backlog only, disabled by default and audited if added. |
| Graph hygiene | Relies on deterministic IDs and OpenCTI cleanup. | Has local state, artifact dedup and quarantine/release foundation. | Add entity/relationship dedup before graph export. |

## NarrowCTI Decision

NarrowCTI should use the official MISP connector as a compatibility baseline,
but should not behave as an unfiltered pass-through.

The target flow is:

```text
MISP event
  -> NarrowCTI source guardrails
  -> metadata and galaxy extraction
  -> scoring, TLP, policy, deduplication and quarantine
  -> graph candidates with confidence and provenance
  -> official-compatible STIX/OpenCTI objects and relationships
  -> OpenCTI import
```

This means a curated MISP event ingested through NarrowCTI should look familiar
to OpenCTI users who know the official connector, but it should be safer,
auditable and less noisy because NarrowCTI decides what is promoted to strong
graph knowledge.

## Required v0.7 Work

The following v0.7 items should be tracked before calling MISP graph enrichment
complete:

1. Add MISP fixture coverage for representative raw events with attributes,
   objects, tags, galaxies, event reports and object references.
2. Add a MISP metadata extractor that understands known galaxy and taxonomy
   structures instead of treating all tags as generic low-confidence labels.
3. Expand MISP attribute mapping toward official-compatible observables and
   indicators.
4. Add MISP-compatible report metadata: event date, timestamp, published state,
   external references, labels, markings, source organization and notes.
5. Add graph candidate and STIX export support for Intrusion Set, Malware, Tool,
   Attack Pattern, Sector, Location, Vulnerability and Infrastructure when
   source evidence supports those objects.
6. Add relationship policy for `based-on`, `indicates`, `related-to`, `uses`,
   object-reference relationships and future sightings.
7. Add confidence and provenance to every promoted object and relationship.
8. Add dry-run comparison evidence showing how a direct official MISP import
   differs from a NarrowCTI-curated import for the same event.
9. Keep threat guessing disabled by default until it has confidence controls,
   OpenCTI lookup safety and audit evidence.

## Validation Strategy

The safest validation path for v0.7 is:

```text
same MISP event
  -> official OpenCTI MISP connector dry/lab import
  -> NarrowCTI dry-run graph export
  -> compare STIX object classes and relationship types
  -> import NarrowCTI curated bundle
  -> validate OpenCTI graph tabs and duplicate posture
```

NarrowCTI should not need to match every object byte-for-byte. It should match
the graph intent where the evidence passes curation:

- Analyses should contain the event report and notes.
- Observations should contain supported observables and indicators.
- Threats should contain actor or intrusion-set context when supported.
- Arsenal should contain malware and tools when supported.
- Techniques should contain ATT&CK attack patterns when supported.
- Entities and Locations should contain sector, country and region context when
  supported.
- Relationships should be explainable through source field, taxonomy, galaxy,
  tag, attribute or object-reference evidence.

This is the model that allows NarrowCTI to keep MISP ingestion familiar to
OpenCTI while evolving into a professional CTI curation gateway.
