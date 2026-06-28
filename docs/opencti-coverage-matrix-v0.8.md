# OpenCTI Coverage Matrix - v0.8

This matrix maps the OpenCTI analyst areas to the current NarrowCTI graph
export posture. It is a living product artifact for v0.8: it shows what can be
promoted today, what has been validated in the lab, what is intentionally held
for graph hygiene, and what remains in backlog.

Coverage in this document means:

- NarrowCTI can extract or receive source-backed evidence for the object.
- Policy, score, allow-list, deduplication and OpenCTI lookup can decide
  whether the object should be exported.
- The STIX bundle can create or reference the object only when the evidence is
  strong enough.

Coverage does not mean every source will populate every OpenCTI tab. If OTX,
MISP or another feed does not provide actor, victimology, arsenal, location,
timeline or ATT&CK metadata, NarrowCTI must not invent it. The product value is
to curate, enrich, deduplicate and relate what is defensible.

## Status Legend

| Status | Meaning |
| --- | --- |
| Validated export | Implemented and validated against local OpenCTI import behavior. |
| Supported | Implemented in the graph/export path, but not yet fully validated for every UI view. |
| Partial | Some evidence is extracted or exported, but the OpenCTI object taxonomy or source mapping is incomplete. |
| Evidence only | Preserved for scoring, audit or reports, but not promoted by the default graph gate. |
| Held by design | Intentionally not promoted because it would pollute the graph. |
| Backlog | Not implemented as a controlled export target yet. |

## Current Product Boundary

NarrowCTI is the pre-ingestion curation gateway. OpenCTI remains the graph,
storage, visualization and optional post-ingestion inference layer.

The v0.8 export gate is intentionally conservative:

- Use canonical OpenCTI lookup before creating graph objects.
- Prefer existing ATT&CK, malware, tool, vulnerability and intrusion-set
  objects when OpenCTI already has them.
- Preserve source identities as Report authors using the
  `<logical source> via NarrowCTI` convention, for example
  `OTX AlienVault via NarrowCTI` and `MISP via NarrowCTI`, while keeping feed
  bookkeeping out of Organization promotion.
- Preserve source-provided object descriptions when present. When a target
  context object has no source description, NarrowCTI can add a short
  provenance-backed description such as `Packrat targets Activists` so the
  OpenCTI object explains why it exists without inventing intelligence.
- Export semantic relationships only when both endpoints are resolvable.
- Hold weak, unresolved or UI-incompatible evidence for audit or future
  review instead of creating unsafe edges.

## Threats

| OpenCTI area | OpenCTI entry | NarrowCTI target | Current status | Current behavior | Next action |
| --- | --- | --- | --- | --- | --- |
| Threats | Threat actors (group) | `threat-actor` | Validated export | The safe export gate can export `threat_actor` candidates as group-style actors by default. MISP threat-actor Galaxy evidence records `threat_actor_class=group`, and OpenCTI lookup uses `threatActorsGroup` before creation. Real MISP validation materialized `Packrat` and `ENERGETIC BEAR` as `Threat-Actor-Group` objects and created source-backed `targets` relationships to Sectors and Countries. Follow-up unit validation now anchors MISP Galaxy malware and ATT&CK candidates to a single unambiguous Threat Actor, Campaign or Intrusion Set, enabling relationships such as `Threat Actor -> uses -> Malware` when source context is strong enough. | Validate actor/intrusion-set/campaign to ATT&CK/arsenal relationships with real payloads and keep ambiguous multi-actor events as Report context. |
| Threats | Threat actors (individual) | OpenCTI Threat Actor Individual entity | Validated export | Explicit individual actor evidence can be classified as `threat_actor_individual` with `threat_actor_class=individual`. NarrowCTI now keeps this out of the generic STIX `threat-actor` bundle path and exports it through the OpenCTI-native `threatActorIndividualAdd(update=true)` mutation after lookup through `threatActorsIndividuals`. It preserves description, aliases, `threat_actor_types`, motivation fields and confidence, then links the native object back to the imported Report with relationship type `object`. Live validation imported `NarrowCTI Matrix Threat Actor Individual Native Validation 20260626B` twice and returned one `Threat-Actor-Individual`, one Report, one Report link and `would_create_object_count=0`. | Expand real source validation for individual actor payloads and keep these separate from target Individuals. |
| Threats | Intrusion sets | `intrusion-set` | Validated export | OTX adversary evidence can promote Intrusion Set candidates. Alias lookup validated with existing OpenCTI objects such as `BlackTech` from `Palmerworm` and `Lazarus Group` from `Lazarus`. Conservative alias normalization now canonicalizes validated aliases such as `Lazarus` -> `Lazarus Group` and `Palmerworm` -> `BlackTech`, preserves the source value in provenance and raises confidence only for curated alias matches. | Expand alias dictionaries with real source evidence and keep alias promotion conservative. |
| Threats | Campaigns | `campaign` | Validated export | MISP Galaxy campaign evidence can become source-backed Campaign candidates, participate in safe graph export, query OpenCTI by name before creation and anchor relationships such as `Campaign -> targets -> Sector`. Live validation imported `NarrowCTI Matrix Live 20260626 campaign`. Explicit MISP Attribute/Object evidence such as `campaign-name`, `operation-name`, campaign objects and operation objects can now promote Campaign candidates when the value is not IOC-like. Explicit OTX fields such as `campaign`, `campaign_name`, `campaigns`, `operation`, `operation_name` and `operations` are also supported. | Validate the expanded MISP/OTX campaign mappings with real payloads. Do not derive campaigns from report titles alone. |

## Arsenal

| OpenCTI area | OpenCTI entry | NarrowCTI target | Current status | Current behavior | Next action |
| --- | --- | --- | --- | --- | --- |
| Arsenal | Malware | `malware` | Validated export | Malware export and OpenCTI lookup are active. Curated alias normalization now canonicalizes validated family aliases such as `LummaC2` -> `Lumma Stealer` before deduplication and lookup, preserves the original source value in provenance and raises confidence only for curated alias matches. MISP Galaxy malware can now inherit a single trusted Threat Actor, Campaign or Intrusion Set anchor to produce semantic `uses` relationships; ambiguous multi-anchor events remain Report context. | Continue alias and family normalization with source-specific evidence and validate the new source-anchored `uses` edges with real feed payloads. |
| Arsenal | Channels | OpenCTI Channel entity | Validated export | Controlled export is active for explicit source-backed `channel` candidates. NarrowCTI emits OpenCTI custom SDOs with the required `extension-definition`, preserves aliases and `channel_types`, and queries `channels` before creation to avoid duplicates. Live validation imported `NarrowCTI Matrix Channel Builder Validation 20260626C` as a Channel with `c2` and `delivery` types. MISP Galaxy meta aliases such as `c2-channel`, `communication-channel`, `delivery-channel` and `marketplace`, plus explicit OTX fields such as `c2_channels`, `communication_channels`, `delivery_channels` and `marketplaces`, now create controlled Channel candidates when the value is not IOC-like. | Validate the new MISP/OTX channel mappings with real payloads. Do not infer channels from report titles alone. |
| Arsenal | Tools | `tool` | Validated export | Tool export and lookup are implemented. Real MISP validation materialized `Turla` and `Wipbot` from MISP Galaxy Tool evidence and linked the source Report to both Tools. | Add more real feed validation and alias normalization. |
| Arsenal | Vulnerabilities | `vulnerability` | Validated export | CVE-aware lookup validates existing OpenCTI Vulnerability objects before export. Live validation referenced existing `CVE-2019-13939` without duplicating it. | Continue bounded CVE ingestion and dedup hygiene for resource-limited labs. |

## Techniques

| OpenCTI area | OpenCTI entry | NarrowCTI target | Current status | Current behavior | Next action |
| --- | --- | --- | --- | --- | --- |
| Techniques | Attack patterns | `attack-pattern` | Validated export | ATT&CK techniques are resolved through canonical OpenCTI lookup, preferably from the official MITRE connector baseline. Kill-chain phase metadata is preserved through canonical ATT&CK objects, and the NarrowCTI fallback builder now preserves source-backed `kill_chain_phases` when it must create an attack-pattern itself. MISP Galaxy ATT&CK candidates can now inherit a single trusted Threat Actor, Campaign or Intrusion Set anchor to produce semantic `uses` relationships when the source context is unambiguous. | Keep MITRE official connector as the canonical ATT&CK loader and validate source-backed `uses` relationships with real MISP/OTX payloads. |
| Techniques | Narratives | OpenCTI Narrative entity | Validated export | Controlled export is active for explicit source-backed `narrative` candidates. NarrowCTI emits OpenCTI custom SDOs with the required `extension-definition`, preserves aliases and `narrative_types`, and queries `narratives` before creation to avoid duplicates. Live validation imported `NarrowCTI Matrix Narrative Builder Validation 20260626C` as a Narrative with `objective` type. MISP Galaxy meta aliases such as `objective`, `motivation`, `theme`, `goal` and `intent`, plus explicit OTX fields such as `objectives`, `goals`, `motivations` and `narratives`, now create controlled Narrative candidates when the value is not IOC-like. Narrative-like evidence still remains in Reports/Notes unless a source field is precise enough for first-class Narrative promotion. | Validate the new MISP/OTX narrative mappings with real payloads. |
| Techniques | Courses of action | `course-of-action` | Validated export | Explicit MISP Galaxy course-of-action evidence can create source-backed Course of Action candidates. Live validation imported `NarrowCTI Matrix Live 20260626 course of action`. OpenCTI lookup now resolves existing Courses of Action through `coursesOfAction` before creation. When the source explicitly provides a mitigated ATT&CK technique such as `T1059`, NarrowCTI now emits `Course of Action -> mitigates -> Attack Pattern` relationships with source provenance. Free-form detection guidance still exports as Notes instead of being promoted as a mitigation. | Validate source-backed mitigation relationships with real MISP/OTX payloads after the clean OpenCTI reload. |
| Techniques | Data components | `x-mitre-data-component` | Validated export | MITRE data source strings with component detail, for example `Process: Process Creation`, can create source-backed Data Component candidates and `Data Component -> detects -> Attack Pattern` relationships. Live validation materialized `Process Creation` as an OpenCTI Data Component and linked it to canonical `T1059`. OpenCTI lookup now resolves existing Data Components through `dataComponents` and accepts canonical `data-component--` references. Source-backed fallback descriptions are emitted when no explicit description exists. | Expand source mappings for component-level detection telemetry. |
| Techniques | Data sources | `x-mitre-data-source` | Validated export | MITRE data-source candidates materialize as OpenCTI Data Source objects and can relate to ATT&CK techniques with `detects`. OpenCTI lookup now resolves existing Data Sources through `dataSources` and accepts canonical `data-source--` references. Source-backed fallback descriptions are emitted when no explicit description exists. | Expand real feed evidence and keep tactic/platform values evidence-only until useful UI materialization is validated. |

## Entities

| OpenCTI area | OpenCTI entry | NarrowCTI target | Current status | Current behavior | Next action |
| --- | --- | --- | --- | --- | --- |
| Entities | Sectors | `identity` with sector semantics | Validated export | Target sector promotion is active and live validation created the `Crypto` and `Defense` sector evidence paths when source metadata supported them. OpenCTI lookup now resolves existing Sector identities through `sectors` before creation. Real MISP validation hydrated `Activists`, `Journalist` and `Political party` descriptions with source-backed victimology provenance, mapped CFR victimology to `Government`, `Military`, `Private sector`, and validated event `1027` with `Energy`, `Private sector` and `Government` on the same Report as actor and Sigma evidence. Conservative synonym normalization now collapses clear aliases such as `Financial Services` -> `Finance` and `Defence` -> `Defense` while preserving the source value in provenance. Source-specific confidence weighting now treats explicit MISP `targeted-sector` evidence stronger than generic sector evidence and lifts structured OTX `industries` above the neutral threshold. | Expand the controlled alias dictionary and confidence weights with real source evidence. |
| Entities | Events | OpenCTI Event entity | Validated export | Controlled export is active for explicit source-backed `event` candidates. NarrowCTI emits OpenCTI custom SDOs with the required `extension-definition`, preserves aliases, `event_types`, `start_time` and `stop_time`, and queries `events` before creation to avoid duplicates. Live validation imported `NarrowCTI Matrix Event Builder Validation 20260626C` as an Event with `cti-validation` type and start/stop timestamps. MISP EventReports still export as Notes/Reports by default because feed bookkeeping is not automatically a CTI Event. MISP Galaxy meta aliases such as `incident-name`, `observed-event` and `activity-event`, plus explicit OTX fields such as `incident_name`, `incidents`, `event_name` and `events`, now create Event candidates only when the feed explicitly carries event-level context. | Validate the new MISP/OTX event mappings with real payloads and keep feed bookkeeping out of CTI Event promotion. |
| Entities | Organizations | `identity` organization | Validated export | Feed authors and source provenance are still held by design. MISP Galaxy victimology fields such as `targeted-organization`, `victim-organization`, `targeted-company`, `affected-organization` or `impacted-company`, plus explicit MISP `target-org` Attribute/Object evidence, can promote source-backed target Organization identities. OpenCTI lookup now resolves existing Organizations through `organizations` before creation, while provenance values, URLs, domains, emails, ATT&CK ids and CVEs are rejected as target organizations. Live validation imported `NarrowCTI Matrix Live 20260626 target organization`. Real MISP `event:5379` materialized five target Organizations (`Oiltanking GmbH Group`, `Mabanaft GmbH & Co. KG Group`, `SEA-Tank`, `Oiltanking` and `Evos`) with author `MISP via NarrowCTI`; because the only safe source anchor was the Report, OpenCTI displayed these as Report `related-to` context instead of semantic `targets` edges. Follow-up unit validation now anchors explicit MISP victimology to a single trusted Campaign, Intrusion Set or Threat Actor when exactly one such source endpoint exists, allowing `Campaign -> targets -> Organization` style relationships. Multiple possible anchors deliberately keep the victimology as Report context. | Validate the new source-anchored victimology behavior with a real MISP/OTX payload that carries campaign or actor plus target organization in the same event. |
| Entities | Security platforms | OpenCTI Security Platform entity | Validated export | Controlled Security Platform export is active through a dedicated OpenCTI-native GraphQL mutation path, not through STIX Identity import. This avoids the validated lab failure where `identity_class=securityplatform` materialized as Organization. NarrowCTI accepts explicit `security_platform` candidates with `stix_object_type=security-platform`, queries `securityPlatforms` before creation, creates with `securityPlatformAdd(update=true)` and preserves `security_platform_type`, description and confidence. After the Report bundle import, NarrowCTI resolves the Report and links native Security Platforms back to it with OpenCTI `reportEdit.relationAdd` using the `object` relationship, so the object keeps container/report context. Live validation imported `NarrowCTI Matrix Security Platform Report Link Validation 20260626C` twice and returned exactly one `SecurityPlatform`, one Report and one Report link. MISP Galaxy meta aliases such as `security-platform`, `detection-platform`, `siem`, `edr`, `ndr`, `xdr`, `scanner` and `sensor`, plus explicit OTX fields such as `security_platform`, `detection_platform`, `siem`, `edr`, `ndr`, `xdr` and `scanner`, now create controlled Security Platform candidates when the value is not IOC-like. | Validate the new MISP/OTX security-platform mappings with real payloads. |
| Entities | Systems | `identity` with system semantics | Validated export | Source-backed `target_system` candidates export as STIX Identity with `identity_class=system`, materialize as OpenCTI System objects, receive provenance-backed descriptions when needed and use `systems` lookup before creation. Controlled builder validation imported `NarrowCTI Matrix System Builder Validation 20260626B` as `System` with one exact match in OpenCTI. MISP Galaxy meta aliases such as `targeted-system`, `affected-system`, `target-platform`, `affected-platform`, `operating-system` and `targeted-asset`, plus explicit OTX fields such as `targeted_system`, `affected_system`, `targeted_platform`, `affected_platform` and `operating_system`, now create controlled System candidates when the value is not IOC-like. Explicit MISP `target-machine` attributes are preserved in audit, but reverse-domain/package identifiers such as Android application ids are blocked from graph promotion. | Validate real payloads that carry human-readable target systems, platforms or assets. Keep package ids and product-like values out of Systems until a more precise application/software model is designed. |
| Entities | Individuals | `identity` individual | Validated export | Controlled Individual export is active only for explicit source-backed victimology/person evidence such as `targeted-person`, `target-individual`, `victim-individual`, `affected-person` or `impacted-person`. NarrowCTI emits STIX Identity with `identity_class=individual`, rejects provenance, URLs, domains, emails, ATT&CK ids, CVEs and numeric-only values, and queries OpenCTI `individuals` before creation. Live validation imported `NarrowCTI Matrix Individual Builder Validation 20260626B` twice and returned exactly one `Individual`, one Report, one Report link and `would_create_object_count=0`. | Expand real source payload mapping for named victim/person evidence. Keep threat-actor individuals separate from target Individuals. |

## Locations

| OpenCTI area | OpenCTI entry | NarrowCTI target | Current status | Current behavior | Next action |
| --- | --- | --- | --- | --- | --- |
| Locations | Regions | `location` | Validated export | Region candidates are allowed, exported with OpenCTI `x_opencti_location_type=Region`, and validated in the local OpenCTI lab as `Region` objects with actor `targets` relationships. MISP Galaxy meta and explicit OTX fields such as `targeted_region`, `target_region`, `targeted_regions` and `target_regions` can create Region candidates. Explicit MISP `targeted-*` geography and OTX `targeted_*` geography now receive source-specific confidence weighting. Conservative region normalization maps common operational aliases such as `APAC` -> `Asia-Pacific`, `LATAM` -> `Latin America` and `EMEA` -> `Europe, Middle East and Africa`. | Validate the same path with a real source payload carrying region-level victimology. |
| Locations | Countries | `location` | Validated export | Country lookup and deterministic export were validated with `Argentina`; repeat exports referenced the existing object. Conservative country normalization now maps common source aliases and ISO-style values such as `AR` -> `Argentina`, `BR` -> `Brazil` and `US` -> `United States` while preserving the original feed value in provenance. Structured MISP/OTX victimology geography now receives source-specific confidence weighting. Explicit MISP `target-location` dry-run validation extracted Belgium, Sweden, Russia and China from real `event:280`; the event was not ingested under default policy because it scored `50`. | Expand the controlled country alias dictionary with real source evidence and validate deeper country/region hierarchy behavior with a source event that passes normal policy or a bounded historical replay. |
| Locations | Administrative areas | `location` | Validated export | Source-backed state/province evidence exports with OpenCTI `x_opencti_location_type=Administrative-Area`; local OpenCTI validation materialized it as `Administrative-Area` instead of the generic country/city heuristic. MISP Galaxy meta aliases such as `targeted-state`, `target-state`, `targeted-province` and `target-province`, plus explicit OTX fields such as `targeted_state`, `target_state`, `targeted_province` and `target_province`, are accepted. | Validate real source payloads carrying administrative-area victimology and parent country/region context. |
| Locations | Cities | `location` | Validated export | Source-backed city evidence exports with OpenCTI `x_opencti_location_type=City`; local OpenCTI validation materialized it as `City` and created actor `targets` relationships. MISP Galaxy meta aliases such as `targeted-city` and `target-city`, plus explicit OTX fields such as `targeted_city`, `target_city`, `targeted_cities` and `target_cities`, are accepted. | Validate real source payloads carrying city-level victimology. |
| Locations | Positions | `location` with coordinates | Validated export | Source-backed coordinates export with OpenCTI `x_opencti_location_type=Position`, `latitude`, `longitude` and optional `precision`; local OpenCTI validation materialized coordinates as `Position` and created actor `targets` relationships. MISP Galaxy meta aliases such as `targeted-coordinate` and `target-position`, plus explicit OTX fields such as `targeted_coordinate`, `target_coordinate`, `targeted_position` and `target_position`, are accepted. | Validate real coordinate-bearing payloads and keep disabled for inferred positions. |

## Observations

| OpenCTI area | OpenCTI entry | NarrowCTI target | Current status | Current behavior | Next action |
| --- | --- | --- | --- | --- | --- |
| Observations | Observables | SCO values such as `ipv4-addr`, `domain-name`, `url`, `email-addr` | Validated export | Observable export and lookup are active for supported concrete values. The real MISP validation confirmed that a standalone IP indicator can be ingested as an Indicator/Observable without becoming Infrastructure. | Continue type normalization. When source-backed Infrastructure exists, relate IP/domain/CIDR/ASN evidence to it; otherwise keep raw IoCs out of Infrastructure. |
| Observations | Artifacts | STIX Artifact | Validated export | Controlled Artifact export is active only for explicit source-backed `artifact` observable candidates with artifact-level metadata. NarrowCTI requires a hash algorithm and hash value, can preserve optional `artifact_url`, `mime_type`, `payload_bin`, encryption metadata and provenance, and resolves existing Artifacts through `stixCyberObservables` by hash before creation. Live validation imported `NarrowCTI Matrix Artifact Builder Validation 20260626B` and OpenCTI returned exactly one `Artifact` with the expected SHA-256 `observable_value`. Generic file hashes still remain file observables or Indicators and are not promoted to Artifact automatically. | Expand source-specific mapping for feeds that provide sample/package metadata or binary artifact context, while keeping ordinary IoC hashes out of Artifact promotion. |
| Observations | Indicators | `indicator` | Validated export | Legacy indicator export remains active. Detection rules materialize as pattern-aware Indicators with canonical names such as `SIGMA: Suspicious PowerShell`, STIX `indicator_types=malicious-activity`, labels such as `narrowcti:detection-rule` and `rule-type:sigma`, source external references and source-backed descriptions when the rule type is OpenCTI-compatible. Real MISP validation confirmed YARA Indicators from event `849`, a Sigma Indicator from event `1027`, and YARA/Sigma Indicators from event `1649`, linked back to source context with author `MISP via NarrowCTI`. NarrowCTI now applies a stricter Sigma compatibility gate before Indicator export: Sigma rules need title, logsource, detection mapping, condition and at least one detection selection. Sigma rules that fail this gate are preserved as labeled Notes with the raw rule and compatibility reason instead of being discarded or retried through native Indicator creation. Snort, Suricata and PCRE also pass through the Note compatibility gate until OpenCTI-compatible Indicator validation exists for those rule types. Native GraphQL Indicator creation is limited to Sigma rules that pass the compatibility gate. Follow-up real OpenCTI API validation on MISP `event:1649` confirmed Sigma Indicators with detection-rule labels and four Snort rules preserved as Notes instead of native Indicators. | Validate Suricata/PCRE real-source payloads in OpenCTI UI/API when usable events are available. |
| Observations | Infrastructures | `infrastructure` | Validated export | Curated Infrastructure export is active for source-backed infrastructure. Validations cover actor infrastructure, MISP infrastructure objects and ASN/IP/CIDR relationships. Real MISP event `1649` materialized Infrastructure `MISP ip-port 137.184.181.252` with author `MISP via NarrowCTI`, linked it to IPv4 observable `137.184.181.252` with `consists-of`, and validated five IPv4 `belongs-to` ASN relationships to `DIGITALOCEAN-ASN` and `BL Networks`. Unit-level STIX builder coverage also confirms `IPv6-Addr -> belongs-to -> Autonomous-System` direction. Offline MISP IP-to-ASN enrichment now emits both `IP -> belongs-to -> ASN` and `Infrastructure -> consists-of -> ASN` when an explicit Infrastructure object anchors the IP. Raw IP indicators are intentionally not promoted into Infrastructure by themselves. | Validate the enriched Infrastructure -> IP -> ASN chain with real feed payloads and verify how OpenCTI displays it in Infrastructure, Knowledge and graph views after clean reloads. |

## Analysis And Context Objects

| OpenCTI area | OpenCTI entry | NarrowCTI target | Current status | Current behavior | Next action |
| --- | --- | --- | --- | --- | --- |
| Analyses | Reports | `report` | Validated export | Reports use deterministic IDs to reduce duplicate report rows. Source-aware authors follow `<logical source> via NarrowCTI`, such as `OTX AlienVault via NarrowCTI` and `MISP via NarrowCTI`, to preserve both upstream source and curation path. | Keep report hygiene validation active for repeated imports and apply the naming convention to every new connector. |
| Analyses | Notes | `note` | Validated export | Detection guidance and MISP EventReports can export as Notes. Detection-rule compatibility Notes now preserve Snort, Suricata, PCRE and Sigma rules that fail the OpenCTI Indicator compatibility gate, with raw rule content, compatibility reason, `narrowcti:detection-rule` and `rule-type:*` labels. Real MISP `event:1649` validation confirmed four Snort Notes authored by `MISP via NarrowCTI` with `rule-type:snort` labels. | Expand relationship targets for notes when the source context is precise and validate Suricata/PCRE Notes in real OpenCTI UI/API runs. |
| Knowledge | Semantic relationships | `relationship` | Validated export where endpoints resolve | ObjectReference and curated graph relationships export only when both endpoints are resolvable. Real MISP `event:1649` confirmed source-backed Infrastructure relationships such as `Infrastructure -> consists-of -> IPv4-Addr` and `IPv4-Addr -> belongs-to -> Autonomous-System`. Real MISP `event:5379` confirmed that Report-only victimology context materializes as Report `related-to` edges even when NarrowCTI proposes `targets`; this is intentional until a real semantic source endpoint exists. Follow-up unit validation now proves explicit MISP victimology can become semantic `targets`, and MISP Galaxy arsenal/ATT&CK can become semantic `uses`, when one trusted campaign/actor/intrusion-set anchor is present and unambiguous. | Continue strict endpoint resolution and relationship type validation. Validate source-anchored semantic edges with real actor/campaign/malware/infrastructure/victimology payloads. |
| Knowledge | Sightings | `sighting` | Validated export where target resolves | MISP sightings export only when the sighted value resolves to an Indicator SDO. Source `date_sighting` controls STIX `first_seen`/`last_seen`, source-backed confidence is preserved when MISP supplies it and non-positive MISP sighting types such as false positives are not emitted as positive STIX Sightings. | Validate richer real MISP sightings in OpenCTI UI/API and decide whether false-positive/expiration sightings should become separate analyst evidence later. |

Promoted graph objects now receive source-backed descriptions when the source
does not provide an explicit description but the NarrowCTI candidate has enough
provenance to explain the object. The fallback description records the logical
source and source field, for example `MISP via NarrowCTI at Galaxy.meta.channel`,
without inventing threat-intelligence content beyond the observed value and
relationship context.

## Knowledge Views

OpenCTI views such as Knowledge, Diamond, Timeline and Kill Chain are populated
by the objects and relationships that OpenCTI can materialize, not by a single
NarrowCTI flag.

| View | Current NarrowCTI support | Remaining gap |
| --- | --- | --- |
| Knowledge | Reports, indicators, observables, infrastructure, ASN/IP relationships, actor, arsenal, ATT&CK, sector and location links can feed Knowledge when source evidence supports them. | Broader source payload validation and object-specific relationship tests. |
| Diamond | Infrastructure and victimology facets are partially validated. Actor, capability, infrastructure and victimology relationships can be emitted when they are source-backed. | Campaign, organization, deeper location and richer capability relationships need expansion. |
| Timeline | Source created, modified, timestamp, date, first_seen, last_seen, valid_from and valid_until evidence can be preserved as `x_narrowcti_*` custom properties on promoted objects and relationships when the source candidate carries those fields. Event objects also preserve explicit `start_time` and `stop_time`. | Native OpenCTI Timeline rendering still needs live UI/API validation per object type and source. |
| Kill Chain | Canonical ATT&CK Attack Pattern objects carry kill-chain phases. NarrowCTI can link actors and infrastructure to those techniques. | More direct source-backed relationships are needed so each object view exposes ATT&CK context without relying on indirect traversal. |

## Backlog Order

1. Expand real feed validation for OTX and MISP payloads that carry actor,
   arsenal, ATT&CK, sector, location, infrastructure, ASN and victimology in the
   same source context. MISP event `1649` now validates the first rich
   Infrastructure/IP/ASN/Malware/CVE/ATT&CK chain; remaining work is broader
   source diversity, primary-IP ASN attachment and domain/netblock evidence.
   MISP event `5379` validates explicit target Organization extraction and
   OpenCTI materialization, but also shows that Report-only victimology remains
   Report `related-to` context until NarrowCTI has a safe actor/campaign/source
   endpoint for semantic `targets` relationships. Unit coverage now validates
   source-anchored `targets` and `uses` paths for a single explicit Campaign,
   Threat Actor or Intrusion Set source, and blocks ambiguous multi-anchor
   events.
2. Validate expanded source-backed Campaign mapping. MISP Galaxy, explicit MISP
   Attribute/Object campaign evidence and explicit OTX campaign/operation
   fields are implemented with IOC/provenance guardrails; the remaining work is
   live source-payload evidence. Campaign-backed target evidence is now the
   preferred real validation path for `Campaign -> targets ->
   Organization/Sector/Country` semantic edges.
3. Validate deeper Locations with real administrative-area, city and coordinate
   payloads in OpenCTI. Controlled OpenCTI import behavior is now validated,
   and MISP Galaxy plus explicit OTX location fields are implemented; the
   remaining gap is source-payload evidence from OTX/MISP or future feeds.
4. Expand real source mapping for Channels, Narratives, Events, Security
   Platforms and Systems. MISP Galaxy meta aliases and explicit OTX fields are
   now implemented with IOC/provenance guardrails and covered by unit tests;
   the remaining work is live source-payload evidence and conservative
   promotion policy tuning.
5. Continue detection-rule polish beyond the real MISP YARA/Sigma evidence.
   Event `849` validated YARA placement and Sigma guardrails for malformed
   source data. Event `1027` validated a Sigma Indicator linked to its Report,
   actor and victimology context. Event `1649` validated additional YARA/Sigma
   materialization but showed OpenCTI 6.9.4 rejecting Snort with
   `INCORRECT_INDICATOR_FORMAT` and rejecting some Sigma rules despite basic
   YAML validity. Unit coverage now preserves Snort/Suricata/PCRE-style rules
   and Sigma rules that fail the stricter OpenCTI compatibility gate as labeled
   Notes instead of native Indicators. Follow-up real OpenCTI API validation
   confirmed Snort Notes from MISP `event:1649`. Remaining work is
   Suricata/PCRE real evidence and broader UI confirmation that
   detection-rule Notes give analysts enough hunting context without polluting
   Indicator views.

## Guardrails

- Do not promote feed provenance, collectors, labels or markings as graph
  entities by default.
- Do not infer organizations, campaigns, channels or individuals from report
  titles alone.
- Do not create relationship-only evidence unless both endpoints resolve to
  graph objects.
- Do not duplicate OpenCTI canonical objects when lookup returns a valid
  `standard_id`.
- Do not overwrite non-empty OpenCTI descriptions during graph hydration.
  Existing-object description hydration is limited to NarrowCTI-owned objects,
  either by deterministic STIX id or by an OpenCTI author containing
  `NarrowCTI`.
- Do not fabricate object descriptions. If the feed has no description,
  NarrowCTI may add only a provenance-backed description that explains which
  source and field produced the promoted object.
- Do not treat raw IOCs as Infrastructure unless source metadata or review
  policy supports an infrastructure-level object.
- When a source-backed Infrastructure object exists, relate supported network
  observables such as IPs, CIDRs, domains and ASNs to it instead of leaving
  them as disconnected graph evidence.
- Keep unsupported but valuable metadata in audit, curation reports or
  quarantine so analysts can review it before graph promotion.
