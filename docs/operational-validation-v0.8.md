# v0.8 Operational Validation

## Purpose

This document defines the observable validation plan for the v0.8 graph
promotion gate.

v0.8 remains conservative. The goal is to prove that NarrowCTI can detect
canonical OpenCTI graph objects, record lookup evidence, summarize that evidence
for operators and keep graph promotion in dry-run until lab validation
explicitly allows controlled export.

No secrets should be recorded here. Local `.env` files remain unversioned.

## Safety Boundary

The default v0.8 validation posture is:

```text
NARROWCTI_DRY_RUN=true
NARROWCTI_GRAPH_EXPORT_MODE=dry-run
NARROWCTI_OPENCTI_GRAPH_LOOKUP=true
NARROWCTI_GRAPH_DEDUP_STATE_FILE=/app/state/graph_dedup.json
```

Expected safety result:

- OpenCTI indicator/report export follows existing dry-run behavior.
- Graph objects and relationships are not promoted unless
  `NARROWCTI_GRAPH_EXPORT_MODE=export` is explicitly enabled for a bounded lab
  import.
- OpenCTI graph lookup is read-only.
- Lookup errors fail open and are logged as evidence.
- Canonical graph matches are recorded in
  `graph_export_plan_lookup_matches`.
- The decision audit report aggregates lookup match counts in `graph_export`.
- OpenCTI Rules Engine validation is separate from NarrowCTI graph export
  validation. Inference rules should remain disabled until direct NarrowCTI
  graph relationships are clean and deterministic.

## Controlled Export Evidence

A bounded lab export can be used to validate a single OpenCTI tab mapping after
dry-run evidence is acceptable. The recommended pattern is:

```text
NARROWCTI_GRAPH_EXPORT_MODE=export
NARROWCTI_OPENCTI_GRAPH_LOOKUP=true
NARROWCTI_ALLOWED_GRAPH_ENTITY_TYPES=target_sector
MAX_PULSES_PER_QUERY=1
MAX_SEARCH_RESULTS_PER_QUERY=1
MAX_IOCS_PER_PULSE=10
```

Observed local validation for the OTX `lummac2` query created the curated
`Crypto` object in OpenCTI as `entity_type=Sector`, confirming that
`target_sector` metadata exported by NarrowCTI can populate
`Entities / Sectors`. This evidence should be repeated per source and per
entity class before enabling broader graph export allow-lists.

When ATT&CK candidates are included in a bounded export, validation should also
confirm whether `existing_reference_count` is greater than zero. That shows
NarrowCTI referenced canonical OpenCTI ATT&CK objects by `standard_id` instead
of creating duplicate `attack-pattern` objects.

OpenCTI Rules Engine should be tested only after the direct export result is
understood. The local OpenCTI 6.9.4 lab currently has the rule manager active,
no rule manager errors and all inference rules disabled. The recommended
validation sequence is to activate one rule at a time, validate inferred
relationships in OpenCTI Knowledge and graph views, then deactivate the rule if
the generated relationship volume or attribution quality is not acceptable.
The rule matrix and NarrowCTI boundary are tracked in
`docs/opencti-rules-engine-v0.8.md`.

When Arsenal candidates are included, validation should prefer a bounded
`malware` or `tool` allow-list and confirm whether the lookup matched an
existing OpenCTI object by `standard_id`, exact name or a curated alias group.
Broader fuzzy matching is not part of the current v0.8 export gate.

When Vulnerability candidates are included, validation should prefer a bounded
CVE-only export with OpenCTI lookup enabled. The expected result is that an
existing OpenCTI Vulnerability is referenced by `standard_id`, the export
summary shows `existing_reference_counts.vulnerability=1`, and the OpenCTI
Vulnerability count for that CVE does not increase.

When Intrusion Set or Threat Actor candidates are included, validation should
prefer one canonical object that already exists in OpenCTI and, when possible,
one source alias. The expected result is that the export summary shows
`existing_reference_counts.intrusion-set=1` or
`existing_reference_counts.threat-actor=1`, the validation Report references
the existing object, and the OpenCTI object count for the canonical name or
alias search does not increase.

Observed local validation for the OTX `lummac2` query with
`NARROWCTI_ALLOWED_GRAPH_ENTITY_TYPES=malware` and
`MAX_IOCS_PER_PULSE=10` ingested one curated report with 10 indicators. OpenCTI
GraphQL confirmed the report object references included `Malware` `LummaC2`
with `standard_id=malware--58dd33b2-647b-5c42-89e8-09b5f64b9469`. The decision
audit recorded `existing_reference_counts={"malware":1}`. Follow-up review
showed this was still not the desired canonical object because OpenCTI already
contained `Lumma Stealer` with alias `LummaStealer`.

The guardrail was tightened so future `LummaC2` candidates resolve to
`Lumma Stealer` by curated alias match when that canonical object is present.
The validation query returned `match_type=alias`, `name=Lumma Stealer` and
`standard_id=malware--961a6bc2-1b2e-5f56-ba42-4655b23fd730`.

Report hygiene must also be checked during repeated validation. Report STIX ids
are now deterministic from report name and description, so repeated export of
the same source report should update the same OpenCTI Report rather than create
another duplicate report row.

Observed repeated export validation confirmed the behavior: before the stable
Report id change, the lab had 5 duplicate OpenCTI Reports with the same LummaC2
title. The first run with deterministic Report ids created one stable Report
with `standard_id=report--d6555acf-74d4-5841-948b-4dde4c06cbe8`; a second
forced run with a fresh state file kept the count at 6 instead of creating a
seventh Report. The newest Report references `Malware` `Lumma Stealer` with
`standard_id=malware--961a6bc2-1b2e-5f56-ba42-4655b23fd730`.

Observed rich export activation validation on June 25, 2026 confirmed the next
bounded export set against local OpenCTI 6.9.4. The controlled report
`NarrowCTI clean export activation validation 20260625` imported one Indicator,
one Attack Pattern, one MITRE Data Source, one Note, one Sighting, one Report
and three relationships. The STIX preview summary had
`skipped_candidate_count=0`, object counts for `attack-pattern`, `note` and
`x-mitre-data-source`, and relationship counts for `detects`, `related-to` and
`sighting-of`.

The local import materialized `x-mitre-data-source` as an OpenCTI Data Source.
MITRE tactic/platform custom objects were intentionally held out of the default
export gate after lab validation showed they were not materialized as useful
first-class OpenCTI objects.

Observed MISP `ObjectReference` export validation used
`NarrowCTI object reference export validation 20260625`. OpenCTI imported one
Malware, one Infrastructure, one Report and three relationships. The semantic
`uses` relationship was exported only because both source and target UUIDs
resolved to graph objects in the bundle.

Observed Vulnerability export validation confirmed the same guarded promotion
model for CVEs. The lab used existing OpenCTI Vulnerability `CVE-2019-13939`
with `standard_id=vulnerability--00055e46-c19c-50c1-8d3b-58dd0a63a66e`.
NarrowCTI lookup returned one known entity, the export plan reported
`deduplicated_entity_count=1` and `would_create_object_count=0`, and the
curated bundle summary reported `existing_reference_counts.vulnerability=1`.
After real import, the validation Report was authored by `OTX AlienVault` and
referenced the existing CVE; the OpenCTI Vulnerability count for that search
remained unchanged.

Observed Intrusion Set export validation confirmed exact alias linking. The lab
used existing OpenCTI Intrusion Set `BlackTech` with alias `Palmerworm` and
`standard_id=intrusion-set--058f30a0-efd4-5d3a-aa39-a8dd414ba288`. NarrowCTI
lookup returned one known entity for source value `Palmerworm`, the export plan
reported `deduplicated_entity_count=1` and `would_create_object_count=0`, and
the curated bundle summary reported `existing_reference_counts.intrusion-set=1`.
After real import, the validation Report was authored by `OTX AlienVault` and
referenced the existing `BlackTech` object; the OpenCTI search counts for
`BlackTech` and `Palmerworm` remained unchanged.

Observed Country export validation confirmed deterministic graph object ids and
Location lookup. A controlled lab import created `Argentina` once in OpenCTI as
`entity_type=Country` with
`standard_id=location--a5c43e9c-7f5e-5fc2-b9eb-3c2eaf055301`. Repeating the
same import kept the exact `Argentina` Country count at `1`. A follow-up lookup
validation returned `known_entity_count=1`, `match_type=name`,
`plan_deduplicated_entity_count=1`, `plan_exported_object_count=0` and
`existing_reference_counts.location=1`. The validation Report
`NarrowCTI country lookup export live validation 20260625` was authored by
`OTX AlienVault` and referenced the existing `Argentina` object instead of
creating another Country.

Report hygiene validation confirmed that repeated imports with the same Report
name and description do not create another OpenCTI Report row. OpenCTI can still
hold separate Reports with the same title when the description differs, because
NarrowCTI intentionally derives the deterministic Report STIX id from
`name + description`.

Observed Infrastructure export validation confirmed controlled population of
`Observations / Infrastructures`. The lab imported
`NarrowCTI Validation Infrastructure 20260625` once as
`entity_type=Infrastructure` with
`standard_id=infrastructure--f5564d5a-ff0d-59cc-a79e-7d06c08e22bf`. Repeating
the same import kept the exact Infrastructure count at `1`. A follow-up lookup
validation returned `known_entity_count=1`, `match_type=name`,
`plan_deduplicated_entity_count=1`, `plan_exported_object_count=0` and
`existing_reference_counts.infrastructure=1`. The validation Reports were
authored by `OTX AlienVault`, and the repeated exact Report count for
`NarrowCTI infrastructure export live validation 20260625` remained `1`.

Observed matrix coverage validation on June 26, 2026 confirmed the newest
OpenCTI tab targets from `docs/opencti-coverage-matrix-v0.8.md`. The controlled
bundle `NarrowCTI Matrix Live 20260626 report` imported:

- `Campaign` `NarrowCTI Matrix Live 20260626 campaign`.
- `Sector` `NarrowCTI Matrix Live 20260626 energy sector`.
- `Organization` `NarrowCTI Matrix Live 20260626 target organization`.
- `Data-Source` `Process: Process Creation`.
- `Data-Component` `Process Creation`.
- `Course-Of-Action` `NarrowCTI Matrix Live 20260626 course of action`.

The bundle referenced existing canonical ATT&CK `T1059` through
`standard_id=attack-pattern--bab942ff-7c9c-5062-9e92-3392bfb2fd74` instead of
creating another Attack Pattern. The import summary recorded
`accepted_candidate_count=7`, `graph_object_count=6`,
`existing_reference_count=1`, `graph_relationship_count=7`,
`skipped_candidate_count=0`, relationship counts of `detects=2`,
`targets=2`, `related-to=3`, and object counts for `campaign`,
`course-of-action`, `identity`, `x-mitre-data-component` and
`x-mitre-data-source`.

Post-import GraphQL validation confirmed:

- `Campaign -> targets -> Organization`.
- `Campaign -> targets -> Sector`.
- `Data-Component -> detects -> Attack-Pattern T1059`.

This validates controlled population of Threats / Campaigns, Entities /
Organizations, Techniques / Courses of action and Techniques / Data components.

Follow-up OpenCTI API validation on June 26, 2026 confirmed the lookup surface
for the newly promoted Technique objects. Local OpenCTI 6.9.4 resolves
`Course-Of-Action` objects through `coursesOfAction`, `Data-Component` objects
through `dataComponents` and `Data-Source` objects through `dataSources`. The
same validation confirmed the canonical `standard_id` prefixes
`course-of-action--`, `data-component--` and `data-source--`; NarrowCTI accepts
those canonical OpenCTI references when export planning deduplicates existing
matrix objects.

The same API validation confirmed exact lookup surfaces for victimology
identities. Local OpenCTI 6.9.4 resolves target Organizations through
`organizations` and target Sectors through `sectors`, both using canonical
`identity--` ids. NarrowCTI uses these lookups only for target organization and
target sector candidates. Source identity, collector, author and feed
provenance identities remain outside automatic Organization lookup and graph
promotion.

Threat Actor taxonomy validation confirmed the OpenCTI lookup surfaces for the
two UI tabs: `threatActorsGroup` for group actors and
`threatActorsIndividuals` for individual actors. NarrowCTI uses the group lookup
for normal `threat_actor` candidates, records explicit individual evidence as
`threat_actor_individual`, and uses native export for individual actors so they
materialize in the correct OpenCTI Threat Actor Individual tab.

Controlled native Threat Actor Individual validation on June 26, 2026 used
`NarrowCTI Matrix Threat Actor Individual Native Validation 20260626B`. The
full `send_bundle` export path was executed twice for the same explicit
`threat_actor_individual` candidate. NarrowCTI imported the Report bundle,
skipped generic STIX `threat-actor` object creation for that candidate, queried
`threatActorsIndividuals`, created the missing native object with
`threatActorIndividualAdd(update=true)`, and linked it back to the imported
Report through OpenCTI `reportEdit.relationAdd` with relationship type
`object`. OpenCTI returned exactly one `Threat-Actor-Individual` named
`NarrowCTI Matrix Threat Actor Individual Native Validation 20260626B Actor`,
standard id `threat-actor--a4f6eca4-b097-5d33-83d2-cb33e22afdae`, alias
`NarrowCTI individual actor alias`, type `crime-syndicate`, confidence `66`,
one linked Report `report--58911a16-85f5-5f10-b03a-8f2d59d4fb25`, and lookup
evidence with `deduplicated_entity_count=1`, `would_create_object_count=0` and
no lookup error.

Real MISP ingestion validation on June 26, 2026 imported local MISP event
`1525` (`Trickbot to Ryuk in Two Hours`) as
`NarrowCTI real MISP ingestion validation 20260626`. The bounded bundle was
authored as `MISP via NarrowCTI`, exported 25 IoC indicators, accepted 24 graph
candidates, referenced seven existing ATT&CK objects through OpenCTI lookup and
created 23 report-to-ATT&CK relationships. The report was queryable in
OpenCTI and had 23 `related-to` relationships to `Attack-Pattern` objects.
Normal IoC indicator lookup was validated with `206.81.5.253`.

The same validation exposed a final-polish item: MISP detection-rule evidence
currently modeled as a graph `detection_rule` candidate with STIX `indicator`
output did not appear reliably when queried by detection-rule name or expected
STIX id. This does not block normal IoC or ATT&CK export, but detection-rule
promotion needs a dedicated OpenCTI placement review before production-ready
enablement. The polish pass should decide whether YARA, Sigma, Snort,
Suricata, PCRE and similar rules should remain Indicators with stricter
pattern typing or be represented through a more suitable OpenCTI object and
relationship model.

The controlled polish decision is to keep detection rules in the native
OpenCTI Indicator workflow for v0.8, but to make them richer and more
discoverable. Detection-rule Indicators now receive:

- Canonical names such as `SIGMA: Suspicious PowerShell`.
- STIX `indicator_types=malicious-activity`.
- Labels such as `narrowcti:detection-rule` and `rule-type:sigma`.
- Source-backed descriptions.
- External references for source identifiers such as MISP attribute UUID,
  OTX indicator id or object UUID when present.

This preserves native OpenCTI behavior and avoids a custom detection-rule SDO
before the UI/relationship model is proven. The next evidence step is real
OpenCTI UI/API validation that polished YARA, Sigma, Snort, Suricata and PCRE
Indicators are queryable by name, label and source reference.

The same real MISP ingestion also confirmed an important Infrastructure
boundary: the IP `206.81.5.253` was ingested and queryable as a normal
Indicator, but it was not related to an Infrastructure object because the
selected source event did not provide infrastructure object context. This is
expected graph hygiene. The next Infrastructure validation must use a
source-backed payload that carries infrastructure evidence and then confirm
that IP/domain/CIDR/ASN evidence is attached to that Infrastructure instead of
remaining disconnected.

Real MISP export validation on June 26, 2026 used local MISP event `1`
(`URLHaus Malware URLs feed`) through the rebuilt `narrowcti-gateway` container
with `NARROWCTI_GRAPH_EXPORT_MODE=export`, `MISP_DRY_RUN=false`,
`MISP_MAX_ATTRIBUTES_PER_EVENT=500` and `MISP_MAX_IOCS_PER_EVENT=10`. The event
had 22,732 attributes, so the attribute guardrail truncated processing to 500
attributes and the IoC guardrail exported 10 indicators. The candidate scored
70, was ingested, and OpenCTI created/updated the Report
`URLHaus Malware URLs feed` authored by `MISP via NarrowCTI`.

The same run accepted six source-backed Vulnerability candidates:
`CVE-2026-24061`, `CVE-2025-55182`, `CVE-2025-14847`, `CVE-2025-54424`,
`CVE-2026-20841` and `CVE-2025-66398`. OpenCTI lookup found existing
Vulnerability objects for all six CVEs, so the graph export did not create
duplicate vulnerability SDOs; it emitted report-context relationships to the
existing objects. Provenance-only candidates (`collector`, `source_identity`
and feed tag) were correctly held by the safe export gate.

This URLHaus validation is useful for volume controls, author naming,
Vulnerability lookup and report relationship hygiene. It is not sufficient for
actor, sector, infrastructure, location or Diamond/Kill Chain validation because
the selected event did not carry that source context.

For the next richer MISP validation, enable and fetch one MISP-format OSINT feed
that carries report-style events instead of only IOC blocklists. Preferred next
targets:

- CIRCL OSINT Feed: `https://www.circl.lu/doc/misp/feed-osint`
- Botvrij.eu OSINT feed: `https://www.botvrij.eu/data/feed-osint`

After import, pick one event that contains Galaxy clusters, malware/tool names,
attack-pattern tags, infrastructure objects or victimology metadata, then run
NarrowCTI against `MISP_QUERIES=event:<id>` with bounded IoC and attribute
limits.

After enabling MISP OSINT feeds, two richer real MISP validations were executed
on June 26, 2026:

- `event:14` (`OSINT - Packrat: Seven Years of a South American Threat Actor`)
  carried MISP Galaxy Threat Actor evidence for `Packrat` and targeted-sector
  metadata for `Activists`, `Journalist` and `Political party`. Because the
  event is historical, the validation used bounded historical-test overrides:
  `NARROWCTI_MIN_SCORE_TO_INGEST=50`, `NARROWCTI_MAX_DAYS_OLD=9999` and
  `MIN_SCORE_FOR_OLD_EVENT=50`. OpenCTI created the Report authored by
  `MISP via NarrowCTI`, materialized `Packrat` as a `Threat-Actor-Group`,
  materialized the three Sectors and created three semantic
  `Packrat -> targets -> Sector` relationships.
- `event:152` (`OSINT - APT Case RUAG Technical Report`) carried MISP Galaxy
  Tool evidence for `Turla` and `Wipbot`. The same bounded historical-test
  overrides were used. OpenCTI created the Report authored by
  `MISP via NarrowCTI`, materialized both Tools and created report-context
  `Report -> related-to -> Tool` relationships for `Turla` and `Wipbot`.

These validations prove that MISP Galaxy metadata can feed multiple OpenCTI
areas through NarrowCTI: Threats / Threat actors, Entities / Sectors, Arsenal /
Tools, Reports and Knowledge relationships. They also show the expected
historical-intelligence policy behavior: old OSINT reports are dropped by the
default score threshold unless the operator deliberately lowers the threshold
for a bounded replay.

Controlled custom SDO validation on June 26, 2026 confirmed the next matrix
targets for OpenCTI-native custom entities. Local OpenCTI accepted STIX `channel`,
`narrative` and `event` objects only when the bundle included the OpenCTI
`extension-definition` and each object carried the `new-sdo` extension marker.
Follow-up NarrowCTI unit validation confirmed that the graph builder now emits
that extension automatically when one of those SDOs is present.

The controlled builder validation covers:

- `Channel` with aliases and `channel_types`, for source-backed C2,
  marketplace, communication or delivery channel evidence.
- `Narrative` with aliases and `narrative_types`, for precise source-backed
  objective, motivation or campaign-story evidence.
- `Event` with aliases, `event_types`, `start_time` and `stop_time`, for true
  CTI events.

The matching OpenCTI lookup surface was also validated in tests: Channels use
`channels`, Narratives use `narratives` and Events use `events`. NarrowCTI
queries those collections before export planning creates a new object, so
repeated exports can reuse existing OpenCTI objects where a `standard_id` or
name match is available.

This does not change the MISP EventReport default. EventReports remain Reports
and Notes unless a source-specific mapper can prove that the upstream object is
a real CTI Event rather than feed/report bookkeeping. Real OTX/MISP payload
validation for these three object families remains pending.

Container-backed live validation then imported
`NarrowCTI Matrix Custom SDO Builder Validation 20260626C` through the local
OpenCTI API. OpenCTI created the Report plus three report-context
relationships and materialized:

- `NarrowCTI Matrix Channel Builder Validation 20260626C` as `Channel`, with
  alias `NarrowCTI validation channel` and channel types `c2` and `delivery`.
- `NarrowCTI Matrix Narrative Builder Validation 20260626C` as `Narrative`,
  with alias `NarrowCTI validation narrative` and narrative type `objective`.
- `NarrowCTI Matrix Event Builder Validation 20260626C` as `Event`, with alias
  `NarrowCTI validation event`, event type `cti-validation`, `start_time`
  `2026-06-26T12:30:00.000Z` and `stop_time`
  `2026-06-26T12:45:00.000Z`.

The saved evidence file is
`state/validation/custom-sdo-validation-20260626.json`. It contains no secrets
and records `accepted_candidate_count=3`, `graph_object_count=3`,
`graph_relationship_count=3`, `skipped_candidate_count=0` and OpenCTI
`standard_id` values for the three objects. A repeated validation with the same
deterministic names found exactly one matching Channel, one matching Narrative
and one matching Event in OpenCTI, confirming that the controlled import did
not leave duplicate same-name objects in the local lab.

Controlled identity-subtype validation on June 26, 2026 then checked the
remaining Entity matrix items for Systems and Security Platforms:

- STIX Identity with `identity_class=system` materialized correctly as OpenCTI
  `System`. The validation object was
  `NarrowCTI Matrix System Validation 20260626`, with standard id
  `identity--c4b52b57-ec9f-545c-950d-0538533d75c5`.
- STIX Identity with `identity_class=securityplatform` did not materialize as
  OpenCTI `SecurityPlatform`; it was imported as an `Organization`. A separate
  GraphQL mutation `securityPlatformAdd` did create
  `NarrowCTI Matrix Security Platform Mutation Validation 20260626` as
  `SecurityPlatform` with `security_platform_type=SIEM`, proving that the
  OpenCTI entity exists but should not be enabled through the normal STIX
  bundle path until a dedicated native export design or the correct STIX import
  marker is validated. The incorrectly materialized validation Organization was
  removed from the lab after the negative result was captured.

Based on that evidence, NarrowCTI enables controlled `target_system` export via
STIX Identity `system` and keeps Security Platform out of the STIX bundle path
to avoid polluting Organizations with platform objects.

Follow-up builder validation imported
`NarrowCTI Matrix System Builder Validation 20260626B` through the NarrowCTI
graph builder. OpenCTI returned exactly one System with standard id
`identity--388d5744-3ed2-525c-8737-bdcfc3dfb71f`, preserved the description
`Controlled source-backed target system validation.`, and created one
report-context relationship from the validation Report.

Controlled Individual validation on June 26, 2026 confirmed the Entities /
Individuals path. NarrowCTI exported an explicit `target_individual` candidate
as STIX Identity with `identity_class=individual`, using the validation report
`NarrowCTI Matrix Individual Builder Validation 20260626B`. The same export was
run twice. OpenCTI returned exactly one `Individual` named
`NarrowCTI Matrix Individual Builder Validation 20260626B Person`, standard id
`identity--d1d7c509-4854-5f51-8069-2eafb2c704e0`, confidence `65` and the
expected source-backed target individual description. The Individual retained one linked
Report, `report--9c22e42c-17a0-571e-91f5-b1371341c6e9`. Follow-up OpenCTI
graph lookup returned `deduplicated_entity_count=1`,
`would_create_object_count=0` and no lookup error, proving the `individuals`
lookup path can protect repeated exports from duplication.

Follow-up native export validation on June 26, 2026 enabled Security Platform
promotion through a dedicated OpenCTI GraphQL path. The controlled validation
used `NarrowCTI Matrix Security Platform Native Validation 20260626B` with
`stix_object_type=security-platform`, `entity_type=security_platform`,
description, confidence `72` and `security_platform_type=SIEM`. NarrowCTI
imported the normal Report bundle, skipped STIX Identity creation for this
candidate and then called `securityPlatformAdd(update=true)` only after
`securityPlatforms` lookup found no existing exact-name object.

The live OpenCTI query returned exactly one `SecurityPlatform` named
`NarrowCTI Matrix Security Platform Native Validation 20260626B`, with standard
id `identity--e8412cd2-f396-50bb-8d9a-63d7f805e6b5`, type `SIEM`,
description `Controlled native SecurityPlatform export validation for the
OpenCTI coverage matrix.` and confidence `72`. A repeated export plus lookup
validation returned `deduplicated_entity_count=1` and
`would_create_object_count=0`, confirming the native path does not duplicate
the same platform in the lab.

Additional native report-context validation on June 26, 2026 used
`NarrowCTI Matrix Security Platform Report Link Validation 20260626C`. The
validation called the full NarrowCTI `send_bundle` export path twice with the
same explicit Security Platform candidate. OpenCTI returned
`platform_exact_count=1`, `report_exact_count=1` and
`platform_report_link_count=1`. The resulting `SecurityPlatform` kept
`security_platform_type=SIEM`, confidence `72`, the expected
source-backed report-container description and standard id
`identity--b2adc1ce-93bd-5069-b1a7-183685e5f1ca`. The linked Report was
`report--daeda486-722c-567a-95bc-ef95aec5655a`, proving that native
Security Platform objects can retain Report/container context through
OpenCTI `reportEdit.relationAdd` with relationship type `object` without
creating a fake semantic edge.

Controlled Artifact validation on June 26, 2026 confirmed the Observations
matrix behavior for binary/package artifact metadata. NarrowCTI built a STIX
Artifact only from an explicit source-backed observable candidate with
`observable_type=artifact`, a SHA-256 hash, `artifact_url` and `mime_type`.
The local OpenCTI STIX importer requires Artifact hash material when a URL is
present, and OpenCTI exposes Artifacts through the generic
`stixCyberObservables` query surface instead of a root `artifacts` collection.

The live import used
`NarrowCTI Matrix Artifact Builder Validation 20260626B`. OpenCTI created one
`Artifact` with standard id
`artifact--ce5e8ca1-37ca-57e5-bc7a-6f0f1542b2ab` and `observable_value`
`0f1e2d3c4b5a69788796a5b4c3d2e1f00f1e2d3c4b5a69788796a5b4c3d2e1f0`.
The post-import query returned `exact_artifact_count=1`,
`graph_object_count=1`, `graph_relationship_count=1` and
`skipped_candidate_count=0`. Generic file hashes remain file observables or
Indicators unless source metadata explicitly supports Artifact promotion.
Follow-up OpenCTI lookup validation confirmed the graph plan can deduplicate
that same Artifact: the local OpenCTI value filter did not return Artifact
matches, so NarrowCTI uses an Artifact-only exact search fallback and accepts a
match only when `entity_type=Artifact` and `observable_value` equals the source
hash. The validation returned `deduplicated_entity_count=1` and
`would_create_object_count=0`.

## Required Lab Posture

Before live validation, confirm:

- Caddy, OpenCTI, MISP, RabbitMQ, Redis, MinIO and Elasticsearch are healthy.
- The official MITRE connector has populated canonical ATT&CK objects in
  OpenCTI.
- OTX and MISP source credentials are present only in local `.env` files.
- Source limits are bounded for the local machine.
- Dry-run is enabled for OTX and MISP unless a specific non-dry-run test is
  approved.
- The current NarrowCTI gateway image has been rebuilt from the working tree
  and a container is running on the same Docker network as OpenCTI before
  starting fidelity-sensitive ingestion tests.

## Container-Backed Fidelity Validation

The June 26, 2026 lab posture was validated with the rebuilt
`narrowcti/gateway:local` image and the `narrowcti-gateway` container attached
to the same Docker network as OpenCTI and MISP (`threat-net`). The local
container env was generated under `state/validation/gateway-fidelity.env`, which
is intentionally ignored by Git because it contains runtime secrets.

The container preflight returned `ok=true` with:

```text
ingestion_mode=misp-collector
enabled_sources=misp
dedup_mode=hybrid
opencti_dedup_lookup=true
graph_export_mode=audit
opencti_graph_lookup=true
distribution_model=open_source
open_source=true
```

The preflight emitted one non-blocking warning:
`mitre-cache-disabled`. This means ATT&CK cache enrichment records
missing-cache evidence unless `NARROWCTI_MITRE_CACHE_FILE` is configured.

A controlled container execution against `MISP_QUERIES=event:1525` confirmed
the full runtime path:

```text
MISP HTTP status: 200
MISP event exceeds IOC guardrail: event=1525 iocs=61 limit=25 action=truncate
MISP candidate: Trickbot to Ryuk in Two Hours age=2286d iocs=61 score=50
MISP drop: Trickbot to Ryuk in Two Hours score=50 reason=below minimum score
Gateway summary: sources=1 succeeded=1 failed=0 reviewed=1 ingested=0 dropped=1 errors=0
Gateway sleeping 3600s
```

This validates container DNS, OpenCTI API reachability, MISP API reachability,
guardrails and policy enforcement without creating another live ingestion.
Future fidelity-sensitive tests should use this container-backed path instead
of one-off helper scripts unless the test objective is explicitly unit-level or
offline bundle generation.

## Preflight

Run preflight before any source execution:

```powershell
python -m gateway.preflight
python -m gateway.preflight --json
```

The output must show:

```text
graph_export_mode=audit|dry-run|export
graph_dedup_state_file=(configured or disabled)
opencti_graph_lookup=true
```

If `opencti_graph_lookup=false`, the run can still validate local graph
deduplication and dry-run planning, but it does not validate canonical OpenCTI
graph lookup.

## Controlled OTX Validation

Use a bounded ATT&CK-rich OTX query or pulse sample.

Expected evidence:

- `otx_entities.attack_ids` contains at least one ATT&CK id.
- `mitre_attack.resolved` resolves the technique locally.
- `graph_candidates` contains an accepted `attack_pattern` candidate.
- `graph_export_plan` marks the matching entity as deduplicated when OpenCTI
  already contains the canonical ATT&CK object.
- `graph_export_plan_lookup_matches` includes the OpenCTI `opencti_id`,
  `standard_id`, `entity_type`, `name`, `x_mitre_id`, `match_type` and
  `match_value`.
- `gateway.decisions` report shows `lookup_matches` greater than zero.
- For Arsenal validation, `graph_export_plan_lookup_matches` can include
  existing `Malware` or `Tool` objects matched by `standard_id`, exact name or
  curated alias group.

## Controlled MISP Validation

Use a bounded MISP event with galaxy or ATT&CK evidence.

Expected evidence:

- MISP galaxy/cluster or tag metadata is converted into graph evidence.
- ATT&CK candidates are looked up against canonical OpenCTI attack-patterns.
- Lookup matches are recorded without creating duplicate attack-pattern
  objects.
- Large events remain guarded by `MISP_MAX_EVENTS_PER_RUN`,
  `MISP_MAX_ATTRIBUTES_PER_EVENT`, `MISP_MAX_IOCS_PER_EVENT` and
  `MISP_OVERSIZED_EVENT_ACTION`.

## Decision Audit Report

After a dry-run, summarize decision audit evidence:

```powershell
python -m gateway.decisions `
  --file state\audit\otx_decisions.jsonl `
  --output-file state\reports\otx-decision-audit.txt

python -m gateway.decisions `
  --file state\audit\misp_decisions.jsonl `
  --output-file state\reports\misp-decision-audit.txt
```

For v0.8, the `graph_export` section should include:

```text
lookup_matches=<count>
lookup_objects=attack-pattern:<count>
lookup_match_types=mitre_attack_id:<count>
```

This proves that canonical OpenCTI graph lookup is visible to operators and
future enterprise CTI reports.

## Operational Validation Checklist

v0.8 also provides a read-only checklist command that consolidates preflight and
decision-audit evidence into pass/fail/needs-evidence status:

```powershell
python -m gateway.operational_validation `
  --decision-path state\audit `
  --required-sources otx,misp
```

After repository validation, OpenCTI UI review and local resource review are
completed, record those manual lab checks explicitly:

```powershell
python -m gateway.operational_validation `
  --decision-path state\audit `
  --required-sources otx,misp `
  --full-validation-passed `
  --opencti-ui-no-duplicate `
  --resource-posture-ok
```

Manual lab checks can also be recorded in a local JSON evidence file. This is
the recommended path for repeatable compose `ops` runs because the file can live
in the local state volume without changing the compose command:

```json
{
  "full_validation_passed": true,
  "opencti_ui_no_duplicate": true,
  "opencti_ui_duplicate_found": false,
  "resource_posture_ok": true,
  "resource_posture_unhealthy": false,
  "resource_posture": {
    "docker_stats_captured": true,
    "docker_stats_command": "docker stats --no-stream",
    "docker_system_df_captured": true,
    "docker_system_df_command": "docker system df",
    "containers_healthy": true,
    "disk_posture_ok": true,
    "notes": "Captured after bounded OTX/MISP validation."
  }
}
```

`resource_posture_ok=true` remains supported for quick manual checks. The
structured `resource_posture` block is preferred because it documents what was
actually reviewed: live container resource usage, Docker disk posture, container
health and whether disk pressure is acceptable for the lab. If
`containers_healthy=false`, `disk_posture_ok=false` or `status=unhealthy`, the
check fails even when the old boolean is omitted.

Then run:

```powershell
python -m gateway.operational_validation `
  --decision-path state\audit `
  --required-sources otx,misp `
  --evidence-file state\operational-validation-evidence.json
```

If the evidence file is missing, the checklist remains read-only and treats
manual checks as `needs-evidence`. If the file exists, it must contain a JSON
object.

JSON output is available for attaching evidence to release notes:

```powershell
python -m gateway.operational_validation `
  --decision-path state\audit `
  --required-sources otx,misp `
  --format json `
  --output-file state\reports\v0.8-operational-validation.json
```

HTML output is available for local review or support-safe evidence packages:

```powershell
python -m gateway.operational_validation `
  --decision-path state\audit `
  --required-sources otx,misp `
  --format html `
  --output-file state\reports\v0.8-operational-validation.html
```

Text output can also be written as a local evidence artifact:

```powershell
python -m gateway.operational_validation `
  --decision-path state\audit `
  --required-sources otx,misp `
  --output-file state\reports\v0.8-operational-validation.txt
```

Checklist status meanings:

- `pass`: evidence is present and satisfies the v0.8 criterion.
- `warn`: the run is not blocked, but controls are incomplete.
- `fail`: validation found an unsafe or blocking condition.
- `needs-evidence`: the criterion cannot be closed from local evidence yet.

The checklist does not call source APIs, query OpenCTI or mutate state. It reads
existing preflight settings and decision audit records, then leaves UI duplicate
checks and resource posture as explicit operator-recorded evidence.

## Pass Criteria

The v0.8 graph lookup gate is acceptable when:

- Full validation passes with `.\scripts\validate-v0.6.ps1`.
- Gateway preflight reports graph lookup controls.
- OTX and MISP bounded dry-runs complete without graph writes.
- At least one ATT&CK candidate is matched to a canonical OpenCTI object.
- Decision metadata includes bounded lookup match evidence.
- Decision report aggregates lookup evidence.
- No duplicate ATT&CK attack-pattern object is created in OpenCTI.

## Stop Criteria

Stop validation and keep graph promotion blocked if:

- OpenCTI lookup causes repeated runtime errors.
- Lookup results are ambiguous or point to the wrong canonical object.
- Dry-run plans imply large graph growth outside configured limits.
- Elasticsearch, RabbitMQ or OpenCTI queue pressure becomes unhealthy.
- MISP events exceed local resource guardrails.

## Remaining Evidence To Capture

- Resource posture after bounded runs on the local lab.

Resource posture still needs a clean numeric capture. On June 25, 2026, after
the bounded export validations, `docker stats --no-stream`, `docker system df`
and `docker inspect` did not return through Docker Desktop in this shell and
the CLI processes had to be stopped without touching running containers. This
does not invalidate the graph export evidence, but the release checklist should
capture CPU, memory, disk and container health from a responsive Docker CLI or
Docker Desktop view before final v0.8 closure.

## Captured ATT&CK Lookup Evidence

Real OTX ATT&CK-rich dry-run evidence was captured from
`state/real-feed-validation-otx-lazarus-infra-20260625/otx_lazarus_decisions_dryrun.jsonl`.
The Lazarus validation record carried 10 ATT&CK attack-pattern candidates, one
Intrusion Set candidate, one Infrastructure candidate, 12 observable candidates
and one target-sector candidate. OpenCTI lookup returned 11 canonical matches:
the existing `Intrusion-Set` `Lazarus Group` by alias plus 10 existing
ATT&CK `Attack-Pattern` objects by `mitre_attack_id`. The STIX preview showed
`existing_reference_counts.attack-pattern=10`,
`existing_reference_counts.intrusion-set=1`, `graph_relationship_count=26` and
`relationship_counts` including `uses`, `targets`, `consists-of` and
`related-to`.

Real MISP ATT&CK/Galaxy evidence was captured from
`state/real-feed-validation-misp-redbanc-20260625/direct_misp_decisions.jsonl`.
The REDBANC validation record carried eight ATT&CK attack-pattern candidates,
one detection-rule candidate and source metadata. OpenCTI lookup returned
seven to eight canonical ATT&CK matches by `mitre_attack_id`, including
`T1199`, `T1064` and `T1053`. The final observed plan reported
`deduplicated_entity_count=8`, `existing_reference_counts.attack-pattern=8`
and a preview with 11 graph relationships.

These records satisfy the v0.8 evidence requirement for source-backed
ATT&CK-rich dry-runs with canonical OpenCTI matches and decision-audit lookup
counters. Duplicate ATT&CK object prevention is evidenced by the lookup-backed
preview referencing existing canonical `standard_id` values instead of
creating new ATT&CK objects.

## Captured Object Description Hydration Evidence

On June 26, 2026, a controlled replay of MISP `event:14`
(`OSINT - Packrat: Seven Years of a South American Threat Actor`) validated the
object-description polish path against the local OpenCTI lab.

Before the replay, OpenCTI returned `description=null` for `Packrat` and for the
Sector objects `Activists`, `Journalist` and `Political party`. A bounded replay
was then executed with graph export enabled, OpenCTI graph lookup enabled,
local artifact deduplication disabled only for the replay, and
`MISP_MAX_IOCS_PER_EVENT=5`.

The replay ingested successfully with `reviewed=1`, `ingested=1`,
`skipped=0`, `errors=0`. Post-run OpenCTI API validation confirmed:

- `Packrat` now has the source-provided MISP Galaxy description.
- `Activists` has `Source-backed target sector observed by misp-galaxy:
  Packrat targets Activists.`
- `Journalist` has `Source-backed target sector observed by misp-galaxy:
  Packrat targets Journalist.`
- `Political party` has `Source-backed target sector observed by misp-galaxy:
  Packrat targets Political party.`
- The three Sector objects remain authored by `MISP via NarrowCTI`.

The implementation does not rely on STIX import update behavior for existing
objects. After bundle import, NarrowCTI uses OpenCTI `fieldPatch` only when the
current description is empty and the matched object is NarrowCTI-owned, either
by deterministic STIX id or by an OpenCTI author containing `NarrowCTI`. This
protects canonical third-party objects and analyst-maintained descriptions.

## Captured Deep Location Export Evidence

On June 26, 2026, controlled matrix validation was executed against the local
OpenCTI lab for deeper Location objects. The first import proved that generic
STIX Location fields alone can be accepted by OpenCTI but may be classified by
heuristic: administrative-area evidence was materialized as `Country`, and
coordinate evidence with city context was materialized as `City`.

NarrowCTI was then updated to emit OpenCTI's `x_opencti_location_type` hint for
source-backed location candidates:

- `target_region` -> `Region`
- `target_country` -> `Country`
- `target_administrative_area` -> `Administrative-Area`
- `target_city` -> `City`
- `target_position` -> `Position`

A second controlled import used
`NarrowCTI Matrix Location Type Validation 20260626B`. The STIX preview had
`accepted_candidate_count=5`, `graph_object_count=5`,
`graph_relationship_count=5`, `semantic_relationship_count=4` and object counts
of four `location` objects plus one `threat-actor`.

Post-import OpenCTI API validation confirmed:

- `NarrowCTI Matrix Region 20260626B` materialized as `Region`.
- `NarrowCTI Matrix Admin Area 20260626B` materialized as
  `Administrative-Area`.
- `NarrowCTI Matrix City 20260626B` materialized as `City`.
- `NarrowCTI Matrix Position 20260626B` materialized as `Position` with
  `latitude=-23.5505`, `longitude=-46.6333` and `precision=10`.
- The validation actor had four semantic `targets` relationships, one to each
  Location subtype above.

This closes controlled OpenCTI import behavior for the deeper Location tabs.
The remaining evidence gap is real source-payload validation from OTX/MISP or
future feeds carrying administrative-area, city or coordinate victimology.

On June 26, 2026, controlled unit validation expanded OTX location extraction
to explicit deeper victimology fields. The tested OTX-shaped pulse carried:

- `targeted_regions=South America`
- `targeted_state=Sao Paulo`
- `targeted_city=Sao Paulo`
- `targeted_coordinate=-23.5505,-46.6333`

The OTX extraction layer produced Region, Administrative Area, City and
Position graph records and anchored them to the single source adversary when
available. Coordinate parsing preserves comma-separated latitude/longitude as a
single value so the STIX builder can materialize it as an OpenCTI Position. A
negative guardrail test confirmed that non-coordinate text is ignored for
Position promotion.

## Captured MISP Operational Meta Mapping Evidence

On June 26, 2026, controlled unit validation expanded the v0.8 matrix backlog
for source-backed MISP Galaxy metadata. The tested path covers:

- `MISP event -> decision_metadata -> graph_evidence -> graph_candidates`.
- Channel promotion from explicit fields such as `c2-channel`.
- Narrative promotion from explicit fields such as `objective`.
- Event promotion from explicit fields such as `incident-name`.
- Security Platform promotion from explicit fields such as `security-platform`.
- System promotion from explicit fields such as `targeted-system`.

The validation used a campaign Galaxy cluster carrying:

- `c2-channel=Telegram`
- `objective=Credential theft`
- `incident-name=Observed phishing wave`
- `security-platform=Microsoft Defender for Endpoint`
- `targeted-system=Windows Workstations`

The graph pipeline produced one Campaign candidate plus one candidate each for
Channel, Narrative, Event, Security Platform and System. It preserved contextual
type metadata such as `channel_types=c2`, `narrative_types=objective`,
`event_types=incident` and `security_platform_type=Detection Platform`.

Guardrail validation also confirmed that IOC-like values are rejected for these
operational meta fields. Values shaped as URLs, domains, CVEs or ATT&CK ids do
not become Channel, Narrative, Security Platform or System graph entities.

This is not yet live OpenCTI ingestion evidence. The next operational step is a
controlled real MISP or OTX payload carrying these explicit fields, followed by
OpenCTI UI/API verification that the objects land in the expected tabs and keep
their Report context.

## Captured OTX Operational Field Mapping Evidence

On June 26, 2026, controlled unit validation added the same operational graph
coverage for explicit OTX pulse fields. The tested path covers:

- Channel promotion from explicit OTX fields such as `c2_channels`.
- Narrative promotion from explicit fields such as `objective`.
- Event promotion from explicit fields such as `incident_name`.
- Security Platform promotion from explicit fields such as `security_platform`
  and typed fields such as `siem`.
- System promotion from explicit fields such as `targeted_system`.

The validation used an OTX-shaped pulse carrying:

- `adversary=APT Example`
- `c2_channels=Telegram`
- `objective=Credential theft`
- `incident_name=Observed phishing wave`
- `security_platform=Microsoft Defender for Endpoint`
- `siem=Splunk Enterprise Security`
- `targeted_system=Windows Workstations`

The OTX extraction layer produced Channel, Narrative, Event, Security Platform
and System records. It preserved type hints where the source field was
specific, including `channel_types=c2`, `narrative_types=objective`,
`event_types=incident` and `security_platform_type=SIEM`, and anchored the
records to the single source adversary when available.

Guardrail validation confirmed that IOC-like values in these OTX operational
fields are ignored. Domains, URLs, CVEs, ATT&CK ids, numeric-only values and
known provenance names are not promoted as operational graph entities.

## Captured Campaign Mapping Expansion Evidence

On June 26, 2026, controlled unit validation expanded Campaign mapping beyond
MISP Galaxy. The tested path covers:

- Explicit MISP Attribute evidence such as `type=campaign-name` with
  `value=Operation Example`.
- Explicit MISP Object evidence such as `Object.name=campaign` with
  `object_relation=operation-name`.
- Explicit OTX fields such as `campaign`, `campaign_name`, `operation` and
  `operation_name`.

The MISP validation produced Campaign candidates for `Operation Example` and
`Operation Backup`, preserved source metadata such as attribute UUID, object
UUID, attribute type, category and tags, and rejected IOC-like campaign values
such as domains. The OTX validation produced Campaign records from explicit
campaign and operation fields and anchored them to the single source adversary
when present.

This intentionally does not infer Campaign objects from MISP event titles, OTX
pulse names, report titles or feed names. The remaining evidence step is live
OpenCTI validation using a real MISP or OTX payload that carries explicit
campaign or operation fields.
