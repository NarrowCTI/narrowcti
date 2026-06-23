# Enterprise Intelligence Gateway - v0.5.0

## Purpose

NarrowCTI must be designed as an enterprise intelligence decision gateway, not
as a lab-only filter and not as a collection of feed connectors. The product
must decide what intelligence is allowed into OpenCTI, explain why, preserve
what was held back, and progressively enrich the OpenCTI graph with context
that helps CTI, threat hunting, SOC and detection engineering teams.

The target outcome is to make OpenCTI behave like a curated intelligence base:
when an analyst pivots on an actor, malware family, sector, tactic, technique,
campaign, infrastructure or IoC, the graph should expose how those elements are
connected and why NarrowCTI allowed them in.

## Product Thesis

NarrowCTI is the pre-ingestion brain in front of OpenCTI.

```text
source feeds
  -> source adapter
  -> normalization and entity extraction
  -> curation policy
  -> quarantine / release workflow
  -> STIX graph builder
  -> OpenCTI import
```

OpenCTI remains the knowledge graph, visualization and analyst platform.
NarrowCTI owns the decision logic, source normalization, score, policy,
deduplication, quarantine, enrichment and graph-shaping before import.

NarrowCTI must support direct source, MISP collector and hybrid ingestion
modes. MISP is an optional collector and hub, not a hard product dependency.
The detailed v0.7 ingestion-mode decision is tracked in
`docs/source-ingestion-modes-v0.7.md`.

The product should move from IoC forwarding to intelligence shaping:

- Which threat actor or intrusion set is involved?
- Which malware, tools, infrastructure, vulnerabilities and techniques appear?
- Which MITRE tactics and techniques are supported by source evidence?
- Which sectors, countries, regions or victim classes are targeted?
- Which artifacts are new, repeated, correlated, low confidence or stale?
- Which data should be ingested, quarantined, released, dropped or used only as
  correlation evidence?

## Current Implementation Boundary

The current v0.5 code path is intentionally narrower than the enterprise target.
It currently exports STIX `Report` and `Indicator` objects and protects graph
hygiene through source state, bundle-level indicator deduplication, a local
artifact index and optional OpenCTI indicator lookup.

This is useful but not sufficient for the enterprise product target. A mature
NarrowCTI gateway must also produce and relate richer STIX/OpenCTI knowledge:

| Intelligence dimension | STIX/OpenCTI target |
| --- | --- |
| Threat actor / cluster | `threat-actor`, `intrusion-set` |
| Campaign / operation | `campaign`, `report`, `grouping` |
| Malware arsenal | `malware`, `malware-analysis` |
| Tools | `tool` |
| Infrastructure | `infrastructure`, cyber observables, indicators |
| TTPs | `attack-pattern` with ATT&CK external ids and tactics |
| Vulnerabilities | `vulnerability` |
| Victimology | `identity` for sectors/organizations and `location` for geography |
| Evidence and confidence | `relationship`, `sighting`, `note`, confidence and markings |
| Detection guidance | `course-of-action`, future Sigma/YARA/IDS references |

## Implemented Filters And Meaning

These are implemented or partially implemented today and must remain documented
for operators.

| Control | Meaning | Risk if too strict |
| --- | --- | --- |
| `MIN_SCORE_TO_INGEST` | Minimum score required for normal ingest. | Important low-context items can be dropped. |
| `QUARANTINE_SCORE_THRESHOLD` | Score below which candidates are quarantined or dropped. | Low-score but important items may not reach OpenCTI until reviewed. |
| `ENABLE_QUARANTINE` | Keeps low-score items reviewable instead of dropping them. | If disabled, low-score intelligence can be lost. |
| `MAX_DAYS_OLD` | Age threshold where old intelligence needs a stronger score. | Long-lived infrastructure, malware and actor context can be excluded. |
| `MAX_DAYS_HARD_FILTER` | Hard age cutoff when greater than zero. | Can block historically important intelligence before scoring. |
| `MAX_SEARCH_RESULTS_PER_QUERY` | OTX search candidates reviewed per query. | Important items outside the result window are not reviewed. |
| `MAX_PULSES_PER_QUERY` | OTX successful ingests per query. | High-volume queries may stop before a later high-value pulse. |
| `MAX_IOCS_PER_PULSE` | OTX indicator export cap per pulse. | Some indicators from a large pulse are not exported. |
| `MISP_FROM_DATE` / `MISP_TO_DATE` | MISP date range for safe backfill. | Historical context outside the range is ignored. |
| `MISP_TAGS` | MISP tag filter, commonly TLP/source tags. | Important intelligence without matching tags is ignored. |
| `MISP_PUBLISHED_ONLY` | Restricts MISP intake to published events. | Draft/local events are ignored even if relevant. |
| `MISP_MAX_EVENTS_PER_RUN` | MISP event processing cap per run. | Later matching events wait for a future run. |
| `MISP_MAX_ATTRIBUTES_PER_EVENT` | Metadata-first oversized event guardrail. | Large but valuable events can be skipped. |
| `MISP_MAX_IOCS_PER_EVENT` | Indicator export cap per MISP event. | Some event indicators can be truncated. |
| `MISP_OVERSIZED_EVENT_ACTION` | `skip` or `truncate` for oversized MISP events. | `skip` protects resources but can hide high-value events. |
| `NARROWCTI_DEDUP_MODE` | Source-only, artifact or hybrid deduplication. | Aggressive artifact dedup can suppress repeated sightings. |
| `NARROWCTI_OPENCTI_DEDUP_LOOKUP` | Optional OpenCTI lookup for existing indicator patterns. | Reduces duplicate imports but adds API cost and coupling. |

## Enterprise Filter Domains

The enterprise model should support filters and scoring dimensions beyond simple
recency, count and query matching. These should be visible in configuration and
auditable in decision records.

| Domain | Filter examples | Product behavior |
| --- | --- | --- |
| Artifact type | IP, domain, URL, email, hash, vulnerability, file, mutex, registry key | Allow or prioritize high-value indicator classes. |
| Artifact criticality | hash confidence, C2-like infrastructure, exploited CVE, repeated sightings | Override low generic score when the artifact is operationally important. |
| TLP / marking | allowed TLP, blocked TLP, PAP, source handling caveats | Enforce sharing policy before import. |
| Source reliability | source allowlist, source trust score, feed class | Weight intelligence by provider and collection context. |
| Threat actor | actor names, aliases, intrusion sets, clusters | Pull intelligence relevant to tracked adversaries. |
| Arsenal | malware families, tools, infrastructure classes, exploit kits | Build actor capability profiles. |
| MITRE ATT&CK | tactic, technique, sub-technique, ATT&CK id, matrix domain | Prioritize behavior and detection relevance. |
| Victimology | sector, industry, country, region, organization type | Curate intelligence by business exposure. |
| Campaign | campaign name, operation, report family, time window | Connect activity waves to actors and infrastructure. |
| Vulnerability | CVE, exploited status, affected product, EPSS/CVSS when available | Drive vulnerability-aware threat intake. |
| Detection | Sigma, YARA, IDS, analytics, courses of action | Feed detection engineering and hunting use cases. |
| Graph state | already seen in OpenCTI, cross-source corroboration, stale relation | Prevent graph pollution while preserving context. |

Candidate future configuration names:

```env
NARROWCTI_ALLOWED_INDICATOR_TYPES=ipv4,ipv6,domain,hostname,url,filehash-sha256,cve
NARROWCTI_CRITICAL_INDICATOR_TYPES=filehash-sha256,cve,url
NARROWCTI_HIGH_VALUE_TAGS=apt,ransomware,malware,c2,exploited
NARROWCTI_ALLOWED_TLP=white,green,amber
NARROWCTI_ALLOWED_ATTACK_PATTERN_IDS=T1059,T1071,T1105
NARROWCTI_ALLOWED_MITRE_TACTICS=initial-access,execution,command-and-control,exfiltration
NARROWCTI_ALLOWED_THREAT_ACTORS=APT29,Lazarus Group,FIN7
NARROWCTI_ALLOWED_MALWARE_FAMILIES=Cobalt Strike,LummaC2,Stealc
NARROWCTI_ALLOWED_TARGET_SECTORS=finance,government,healthcare,energy
NARROWCTI_ALLOWED_TARGET_COUNTRIES=BRA,USA,GBR
NARROWCTI_MIN_CORROBORATING_SOURCES=2
NARROWCTI_RELEASE_QUARANTINE_REQUIRES_REASON=true
```

## Quarantine And Release Requirement

Quarantine must become a first-class product workflow. Today quarantine is a
decision outcome recorded in audit, but it is not yet a managed review queue.
For enterprise use, quarantine must preserve enough evidence for a user to
release the intelligence safely.

Target behavior:

1. A candidate that fails policy but is not clearly maliciously malformed is
   written to a quarantine repository.
2. The record includes source, external id, title, raw score, policy reason,
   source payload snapshot, indicators, extracted entities, proposed STIX
   objects and proposed relationships.
3. The operator can approve full release, approve partial release, reject,
   expire or replay as dry-run.
4. Release creates a new audit record with reviewer, timestamp, reason and the
   policy overrides used.
5. Released items are exported through the same STIX builder and deduplication
   pipeline, with metadata showing they were analyst-approved.

Target interfaces by maturity:

| Version | Interface | Scope |
| --- | --- | --- |
| v0.6 | CLI and JSONL/SQLite repository | Safe local review and release. |
| v0.7 | Gateway API endpoint | Automation and integration with admin UI. |
| v0.8+ | Web/admin UI | Enterprise analyst workflow and governance. |

Candidate release commands:

```text
python -m gateway.quarantine list --status pending
python -m gateway.quarantine show --id <quarantine-id>
python -m gateway.quarantine release --id <quarantine-id> --reason "Relevant to monitored actor"
python -m gateway.quarantine reject --id <quarantine-id> --reason "Out of scope"
python -m gateway.quarantine release-indicators --id <quarantine-id> --type filehash-sha256,url
```

## OTX Payload Mapping

Current NarrowCTI OTX usage:

- Search pulses through `/api/v1/search/pulses`.
- Enrich a pulse through `/api/v1/pulses/{pulse_id}`.
- Normalize `id`, `name`, `description`, `created`, `tags` or `industries`, and
  `indicators`.

The OTX Python SDK documents additional pulse fields that should be considered
for enterprise mapping: `TLP`, `tags`, `references`, `adversary`,
`targeted_countries`, `industries`, `malware_families` and `attack_ids`.

Target OTX mapping:

| OTX field | NarrowCTI interpretation | STIX/OpenCTI target |
| --- | --- | --- |
| `indicators` | Observable and indicator artifacts | `indicator`, SCOs, future `sighting` |
| `adversary` | Actor or cluster name, source confidence required | `threat-actor` or `intrusion-set` |
| `malware_families` | Actor arsenal / malware context | `malware` |
| `attack_ids` | ATT&CK technique references | `attack-pattern` plus tactic lookup from MITRE |
| `industries` | Victimology / target sector | `identity` with sector class or OpenCTI sector entity |
| `targeted_countries` | Victimology / geography | `location` |
| `references` | External evidence | `external_references`, `report` context |
| `TLP` | Marking and sharing constraints | `marking-definition` / OpenCTI marking |
| `tags` | Source labels and weak entity hints | Labels plus extraction candidates |

Important rule: OTX fields such as `adversary`, `industries` and
`malware_families` should not be blindly trusted as high-confidence graph facts.
They should be imported with source provenance, confidence and explainable
relationship strength.

## MITRE ATT&CK Mapping

MITRE ATT&CK should be treated as a reference knowledge base and enrichment
source, not as an IoC feed. The official ATT&CK data is available in STIX and
TAXII, and includes groups, software, campaigns, techniques, tactics and
relationships.

Target MITRE mapping:

| ATT&CK concept | STIX/OpenCTI target | NarrowCTI use |
| --- | --- | --- |
| Group | `intrusion-set` | Actor profile and actor filter. |
| Software | `malware` or `tool` | Arsenal profile and scoring feature. |
| Technique / sub-technique | `attack-pattern` | TTP filter, detection mapping and graph relation. |
| Tactic | `kill_chain_phases` on attack patterns | Tactic-level filtering and summaries. |
| Campaign | `campaign` | Campaign-level context and time windows. |
| Relationship `uses` | `relationship` | Actor-to-technique, actor-to-software and software-to-technique links. |
| Relationship `targets` where available | `relationship` | Victimology and sector/country enrichment when supported. |

The first enterprise implementation should cache ATT&CK objects locally and use
that cache to enrich OTX `attack_ids` and future MISP tags/galaxy values.

## OpenCTI Graph Target

OpenCTI tabs and graph views become valuable only when NarrowCTI imports more
than isolated indicators. The target STIX graph for a curated candidate should
look like this when source evidence exists:

```text
report/campaign
  -> indicates / contains -> indicators and observables
  -> attributed-to / related-to -> threat actor or intrusion set
  -> uses -> malware, tools, infrastructure, vulnerabilities
  -> uses -> attack patterns mapped to MITRE tactics
  -> targets -> sectors, organizations, countries or regions
  -> mitigated-by / detected-by -> courses of action and future detection rules
```

This must be incremental. v0.5 should not pretend this is implemented. It should
define the standard and prevent the product from drifting into IoC-only import.

## Backlog Placement

The requested enterprise filters make sense, but not all should be implemented
inside v0.5. They require entity extraction, source-specific payload mapping,
relationship confidence and quarantine release mechanics.

Recommended placement:

| Version | Backlog item | Reason |
| --- | --- | --- |
| v0.5 | Document enterprise curation model, filter taxonomy and source payload mapping. | Aligns product direction before more code. |
| v0.5 | Keep artifact correlation and OpenCTI dedup as graph hygiene foundation. | Already implemented and safe. |
| v0.6 | Implement quarantine repository, CLI release and release audit. | Required before strict enterprise filters can be safe. |
| v0.6 | Add OTX enriched entity extraction for adversary, malware families, attack ids, industries, countries and TLP. | Uses fields already available in OTX payloads. |
| v0.6 | Add local MITRE ATT&CK cache and technique/tactic resolver. | Required for ATT&CK filters and TTP graph enrichment. |
| v0.7 | Export richer STIX objects and relationships to OpenCTI. | Starts feeding more OpenCTI tabs and graph pivots. |
| v0.7 | Add enterprise policy variables for actor, arsenal, ATT&CK, sector and geography filters. | Safe after extraction and quarantine exist. |
| v0.7 | Add contextual scoring design and dry-run evidence based on graph categories. | Lets actor, arsenal, TTP, sector, location and author relevance influence decisions without hiding the base score. |
| v0.7 | Document direct source, MISP collector and hybrid ingestion modes. | Ensures NarrowCTI can be used by teams with or without MISP. |
| v0.8 | Add analyst review API/UI and value reporting. | Turns governance into product workflow. |
| v1.0 | Stable enterprise policy engine with explainable scoring, release, enrichment, graph quality metrics and enterprise CTI report output. | Production-grade target. |

The centralized v0.7 graph enrichment design is tracked in
`docs/graph-enrichment-v0.7.md`. That document should drive implementation of
source metadata validation, graph candidate modeling, STIX/OpenCTI object
mapping, relationship confidence and enterprise graph filters.

The contextual scoring reference is tracked in
`docs/contextual-scoring-reference-v0.7.md`. It should guide how NarrowCTI
separates base score from graph-context score and explains every adjustment.

The source ingestion mode reference is tracked in
`docs/source-ingestion-modes-v0.7.md`. It should guide how new direct source
adapters enter the product without bypassing curation.

The enterprise CTI report should be built after reliable evidence exists from
gateway summaries, decision audit, quarantine/release actions, artifact
correlation and graph-enrichment outcomes. It should explain what NarrowCTI
allowed into OpenCTI, what it filtered, why those decisions were made, and what
value was created for CTI and hunting teams.

## Research Notes

Sources used for this design:

- MITRE ATT&CK Data and Tools: https://attack.mitre.org/resources/attack-data-and-tools/
- MITRE ATT&CK STIX data repository: https://github.com/mitre-attack/attack-stix-data
- OASIS STIX introduction: https://oasis-open.github.io/cti-documentation/stix/intro.html
- OASIS STIX 2.1 specification: https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html
- AlienVault OTX Python SDK: https://github.com/AlienVault-OTX/OTX-Python-SDK
- Kaspersky Cyber Threat Intelligence Services: https://www.kaspersky.com/enterprise-security/threat-intelligence
- OpenCTI documentation overview: https://docs.opencti.io/latest/usage/overview/

## Decision

This enterprise model should enter the roadmap now. Implementation should be
phased. The safest next engineering step is not to loosen filters blindly; it is
to add a real quarantine repository and release workflow, then enrich OTX and
MITRE into structured graph objects with confidence, provenance and audit.
