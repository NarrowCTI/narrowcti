# NarrowCTI v0.8.0 Development Notes

## Status

`v0.8.0-dev` is the active graph promotion, analyst review and product
operations development track.

`v0.7.0` remains the latest stable foundation release. It closed the audit-first
graph enrichment layer, MITRE-aware curation posture, graph STIX preview,
contextual scoring evidence and local graph deduplication planning.

## Purpose

v0.8 should move NarrowCTI from graph-aware preview into controlled graph
promotion readiness. The release must keep OpenCTI graph hygiene as the primary
boundary: no graph entity or relationship should be promoted until source
evidence, policy, deduplication, canonical lookup and audit requirements are
satisfied.

The graph promotion design is tracked in `docs/graph-promotion-v0.8.md`.
The v0.8 architecture supplement is tracked in `docs/architecture-v0.8.md`.
Operational validation is tracked in `docs/operational-validation-v0.8.md`.
Deployment operations are tracked in `docs/deployment-operations-v0.8.md`.
Analyst review design is tracked in `docs/analyst-review-v0.8.md`.
Curation reporting is tracked in `docs/curation-reporting-v0.8.md`.
Support diagnostics are tracked in `docs/support-diagnostics-v0.8.md`.
Infrastructure ASN/IP correlation is tracked in
`docs/infrastructure-correlation-v0.8.md`.
OpenCTI post-ingestion reasoning alignment is tracked in
`docs/opencti-rules-engine-v0.8.md`.
OpenCTI tab/export coverage is tracked in
`docs/opencti-coverage-matrix-v0.8.md`.

## Initial Scope

- Add read-only OpenCTI graph lookup for supported graph candidates.
- Resolve ATT&CK candidates against canonical OpenCTI attack-pattern objects
  before any future graph promotion.
- Keep graph export in dry-run/audit until OpenCTI lab validation proves import
  behavior.
- Prepare graph promotion metadata so exported entities and relationships can be
  marked in the local graph deduplication state after successful import.
- Define analyst review expectations for graph candidates, quarantine release
  and policy tuning.
- Prepare enterprise reporting evidence for what was ingested, held, enriched,
  deduplicated and promoted.
- Start product operations hardening for installation, upgrade, configuration
  defaults and deployment templates.
- Provide a read-only support diagnostic snapshot for preflight, evidence and
  curation state.

## Implemented Foundation

- Created `core/opencti_graph_lookup.py` as a read-only OpenCTI graph lookup
  adapter.
- Added `docs/graph-promotion-v0.8.md` to document the graph promotion boundary,
  canonical MITRE linking model and validation path.
- Added `docs/operational-validation-v0.8.md` as the runbook for bounded
  OpenCTI/MISP/OTX lab validation of the read-only graph lookup gate.
- Added ATT&CK attack-pattern lookup by `x_mitre_id` first, then by STIX
  `standard_id` when a MITRE technique id is not available.
- Made the lookup compatible with the existing `graph_export_plan` known-key
  interface so OpenCTI-known entities can be treated as deduplicated planning
  evidence before export.
- Wired OTX and MISP runtimes to optionally combine local graph deduplication
  with read-only OpenCTI graph lookup through
  `NARROWCTI_OPENCTI_GRAPH_LOOKUP`.
- Added bounded lookup match evidence in `graph_export_plan_lookup_matches` so
  OpenCTI canonical graph matches are visible to analysts and future reports.
- Extended the decision audit report graph export summary with OpenCTI lookup
  match counters by object type, match type and canonical entity type.
- Added deterministic STIX ids for graph SDOs created by NarrowCTI, reducing
  duplicate graph entities across repeated exports when the same normalized
  object type, identity class and value/name are promoted again.
- Extended OpenCTI graph lookup to Location objects so country/location
  candidates can reference existing OpenCTI Locations by `standard_id` or exact
  name before controlled graph promotion creates anything new.
- Added controlled STIX `infrastructure` promotion and OpenCTI Infrastructure
  lookup so explicit infrastructure evidence can populate
  `Observations / Infrastructures` without turning every raw observable into
  graph infrastructure.
- Validated controlled Country export against OpenCTI: `Argentina` was created
  once as `entity_type=Country`, repeated import kept the count at one, and the
  follow-up lookup export referenced the existing
  `location--a5c43e9c-7f5e-5fc2-b9eb-3c2eaf055301` object with
  `existing_reference_counts.location=1`.
- Validated controlled Infrastructure export against OpenCTI:
  `NarrowCTI Validation Infrastructure 20260625` was created once as
  `entity_type=Infrastructure`, repeated import kept the count at one, and the
  follow-up lookup export referenced
  `infrastructure--f5564d5a-ff0d-59cc-a79e-7d06c08e22bf` with
  `existing_reference_counts.infrastructure=1`.
- Validated ASN/IP infrastructure correlation against OpenCTI:
  `Autonomous-System` imports as a `stixCyberObservable`, Infrastructure can
  `consists-of` ASN/IP/CIDR, and IP/CIDR can `belongs-to` ASN. The controlled
  bundle for `AS64512 NarrowCTI Validation ASN`, `203.0.113.10` and
  `203.0.113.0/24` reimported without duplicating the controlled objects.
- Enabled native NarrowCTI graph export support for `autonomous-system`
  candidates and exact OpenCTI observable lookup for supported observables such
  as `ipv4-addr`, `ipv6-addr`, `domain-name`, `url` and `email-addr`.
  OpenCTI lookup now treats ASN and generic observables as
  `stixCyberObservables` and can reference their real STIX ids, such as
  `autonomous-system--...` or `ipv4-addr--...`, from a generic NarrowCTI
  `observable` candidate without recreating the object.
- Tightened graph relationship deduplication so semantic edges with the same
  target and relationship type remain distinct when they have different source
  anchors. This is required for infrastructure intelligence such as
  `203.0.113.11 -> belongs-to -> AS64513` and
  `203.0.113.0/25 -> belongs-to -> AS64513` to coexist.
- Validated native NarrowCTI ASN/IP/CIDR graph export against OpenCTI with the
  controlled report `NarrowCTI native ASN graph validation 20260625`. The
  final lookup-backed export found 4 existing graph entities, exported 0 new
  graph objects, referenced 1 Infrastructure, 1 Autonomous-System and 2
  Observables, and imported 6 relationships. OpenCTI returned exactly 1
  Infrastructure, 1 ASN, 1 IP, 1 CIDR and 1 Report, with queryable
  `Infrastructure -> consists-of -> ASN`, `Infrastructure -> consists-of -> IP`,
  `Infrastructure -> consists-of -> CIDR`, `IP -> belongs-to -> ASN` and
  `CIDR -> belongs-to -> ASN` relationships.
- Added OTX adversary hygiene for graph promotion. OTX `adversary` now maps to
  `intrusion_set` so group-style source values can resolve to canonical ATT&CK
  Intrusion Set objects instead of creating duplicate generic Threat Actor
  objects.
- Added a curated Intrusion Set alias group for `Lazarus` so OTX source values
  resolve to existing OpenCTI `Lazarus Group` when the MITRE connector has
  already populated that object.
- Added OTX source hygiene to suppress `malware_families` values that equal the
  adversary name, preventing noisy source metadata from creating incorrect
  Arsenal entries such as `Malware Lazarus`.
- Added OTX inferred infrastructure promotion for bounded, source-backed cases:
  when an OTX pulse has exactly one adversary and at least one network
  observable, NarrowCTI creates a curated Infrastructure candidate and links
  network observables to it with `consists-of`.
- Added direct OTX inferred-infrastructure TTP relationships: when the same
  single-adversary pulse provides ATT&CK ids, NarrowCTI now exports
  `Infrastructure -> related-to -> Attack Pattern` relationships so the OpenCTI
  Infrastructure view can receive curated ATT&CK context. Local OpenCTI 6.9.4
  rejects `Infrastructure -> uses -> Attack Pattern`, so `related-to` is used
  for this object pair.
- Tightened graph candidate fingerprints so the same ATT&CK technique can keep
  distinct actor-anchored and infrastructure-anchored relationships without one
  export action shadowing the other.
- Stopped promoting OTX author/source provenance as a graph `Organization`
  object. The provenance remains visible through report author/audit metadata,
  while Organizations stay reserved for meaningful CTI entities such as
  victimology or source-backed targets.
- Validated a real OTX actor-infrastructure export against OpenCTI using pulse
  `61f9392ac64510da57b9cdf9`. The import referenced the existing
  `Intrusion-Set Lazarus Group`, created `Infrastructure Lazarus OTX observed
  infrastructure 61f9392a`, linked it to `markettrendingcenter.com` and
  `lm-career.com`, linked Lazarus Group to sector `Defense`, and referenced 10
  canonical ATT&CK techniques with kill-chain phase coverage.
- Revalidated the same OTX infrastructure object after OpenCTI rejected
  `Infrastructure -> uses -> Attack Pattern`. The final compatible import
  created 10 queryable `Infrastructure -> related-to -> Attack Pattern`
  relationships with kill-chain phase metadata on the canonical ATT&CK
  targets.
- Cleaned the prior validation Report association that had promoted OTX pulse
  author `hitip_forever` as an `Organization` object. The final Report object
  set contains the expected Sector `Defense` and keeps `OTX AlienVault` only as
  report author metadata.
- Documented Report hygiene evidence: deterministic Report ids prevent another
  row when name and description are unchanged; a changed description is treated
  as a distinct report by design.
- Added OTX source-provided ASN/netblock extraction. OTX indicators with
  `ASN`/`AS` values now produce `autonomous_system` graph candidates, and
  `CIDR`/`netblock` style indicators are normalized as IP observables with
  CIDR values. When the pulse has one adversary, these source-backed network
  objects attach to the inferred Infrastructure with `consists-of`; without a
  single adversary they remain related evidence and are not attributed to an
  Infrastructure object.
- Added `docs/opencti-rules-engine-v0.8.md` to document the difference between
  NarrowCTI pre-ingestion curation and OpenCTI post-ingestion inference rules.
  The local OpenCTI 6.9.4 lab has the rule manager active, no manager errors
  and all 20 inference rules disabled. The documented posture is to activate
  rules one at a time after NarrowCTI graph export evidence is clean.
- Added MISP infrastructure object extraction for `asn`, `netblock`,
  `domain-ip` and `ip-port` objects. These now produce graph candidates for
  Infrastructure, Autonomous-System and concrete network Observables with
  source-backed `Infrastructure -> consists-of -> Observable/ASN` and
  `IP/CIDR -> belongs-to -> ASN` relationships when the MISP object carries
  the required metadata.
- Added direct MISP event lookup for bounded validation through
  `MISP_QUERIES=event:<id>`, `event-id:<id>`, `id:<id>` or `uuid:<uuid>`.
  This avoids broad `events/restSearch` scans when an operator needs to
  validate one curated event or replay a known MISP object payload.
- Validated controlled MISP infrastructure export against OpenCTI using local
  MISP event `4390`
  (`NarrowCTI MISP infrastructure export validation 1782423797`). The local
  MISP dataset did not contain real feed samples with `asn`, `netblock`,
  `domain-ip` or `ip-port` objects in the first 250 reviewed events, so the
  validation event used official MISP object templates for `asn`, `domain-ip`
  and `ip-port`.
- The MISP validation imported two Infrastructure objects, one
  `Autonomous-System`, one domain observable, three IPv4 observables, and
  queryable `Infrastructure -> consists-of -> Observable/ASN` plus
  `IP/CIDR -> belongs-to -> ASN` relationships. The Report object refs stayed
  limited to graph intelligence objects; MISP source provenance remained
  report author/audit metadata and was not promoted as an Organization object.
- Added safe graph export defaults for real `export` mode. When no operator
  allow-list is provided, NarrowCTI now accepts source-backed CTI objects such
  as infrastructure, ASN, observables, sector/location, arsenal, ATT&CK and
  reports, while holding feed bookkeeping candidates such as `collector`,
  `source_identity`, labels and markings out of automatic graph promotion.
  Audit and dry-run remain broad for visibility, and explicit allow-lists can
  still override the default.
- Added decision audit report file output and an `ops` profile service so
  graph lookup and curation decision evidence can be archived from the gateway
  state volume.
- Added artifact correlation report file output and an `ops` profile service
  so cross-source deduplication evidence can be archived from the gateway state
  volume.
- Extended gateway preflight output with v0.8 graph controls:
  `NARROWCTI_GRAPH_EXPORT_MODE`, `NARROWCTI_GRAPH_DEDUP_STATE_FILE` and
  `NARROWCTI_OPENCTI_GRAPH_LOOKUP`.
- Added a safe `mark_exported_plan` path to the local graph deduplication index
  for future post-export state marking. It ignores dry-run `would_create`
  actions and only records actions explicitly marked as `exported`.
- Added fail-open behavior for OpenCTI graph lookup errors. Lookup failures are
  logged and do not block the existing audit/dry-run plan.
- Added unit coverage for MITRE attack-pattern lookup, fail-open behavior,
  STIX-id fallback, unsupported candidate handling and composite lookup
  merging.
- Added the open source capability inventory foundation through
  `NARROWCTI_CAPABILITIES` and preflight reporting. This is observable
  product-operations plumbing only; it is not runtime commercial activation
  blocking.
- Added distribution posture and capability visibility to preflight output so
  operators can see `distribution_model=open_source`, enabled capabilities,
  declared capabilities and unknown capability declarations.
- Added the first v0.8 deployment operations package:
  `deployment/docker-compose.narrowcti-gateway.yml`,
  `deployment/gateway.env.example` and
  `docs/deployment-operations-v0.8.md`.
- Added `ops` profile services to the deployment compose template for
  repeatable preflight, curation report and support diagnostic runs without
  starting continuous gateway ingestion.
- Added an `ops` profile service for operational validation so deployments can
  generate `/app/state/operational-validation.html` from the same image,
  environment and state volume used by the gateway.
- Added optional JSON manual evidence loading to `gateway.operational_validation`
  so repeatable ops runs can record repository validation, OpenCTI duplicate
  review and resource posture checks without changing CLI flags.
- Added `gateway.review.AnalystReviewService` as the internal analyst review
  API for quarantine list, summary, release, partial release, reject, export
  dry-run and audit-event reads. The CLI now delegates review operations to
  this service.
- Added `gateway.curation_report` as the first analyst-facing curation report
  model. It consolidates gateway run summaries, decision audit, analyst review
  status and graph readiness evidence into text or JSON output.
- Added an explicit `curation-report/v0.8` schema version to the curation
  report contract so JSON, text, HTML and support diagnostics can be archived
  and compared consistently.
- Added HTML output for the curation report through
  `python -m gateway.curation_report --html-file ...`, keeping the report
  read-only and evidence-driven.
- Added text and JSON curation report file output through `--output-file` and
  `--json-file`, and updated the `ops` compose service to persist
  `/app/state/curation-report.txt`, `/app/state/curation-report.json` and
  `/app/state/curation-report.html` from the same evidence snapshot.
- Added aggregated analyst review action feedback to the curation report. It
  summarizes release, reject and export audit events without exposing detailed
  queue records, preparing the later policy tuning workflow.
- Added per-source curation summaries to the report so analysts can compare
  operational health, decisions, pending review and release/reject feedback per
  source.
- Added source-level policy insights to the curation report. The report now
  highlights repeated release/reject patterns that may indicate noisy source
  scope, permissive policy or overly strict quarantine thresholds.
- Added top analyst review reasons to curation policy insights so release and
  reject patterns carry the operator evidence that drove the tuning signal.
- Added source score summaries to curation policy insights so tuning evidence
  includes scored record count, min/max score, average score and low-score
  volume per source.
- Added graph evidence density to curation policy insights so analysts can see
  graph candidate volume, lookup matches and relationship-ready evidence per
  source before any graph promotion.
- Added graph type composition to curation policy insights and support
  diagnostics so source-level reports show top accepted object types, accepted
  relationship types, lookup object types and STIX preview object/relationship
  types.
- Added context-quality metrics to curation policy insights so analyst reports
  show contextual scoring volume, score delta and top CTI categories per source
  without applying contextual score to final ingest decisions.
- Added the first evidence-driven context narrative over decision
  `graph_evidence` so curation reports and support diagnostics can show top
  ATT&CK techniques, arsenal, threat actors/intrusion sets and target sectors
  per source without inventing missing context.
- Added structured curation report context sections for ATT&CK, arsenal,
  threat actors/intrusion sets and target sectors. These sections aggregate top
  entities and source-level observations from existing graph evidence without
  creating OpenCTI entities or inferring unsupported context.
- Added source-level quarantine reason rollups to policy insights so repeated
  hold conditions from decision audit are visible next to analyst release/reject
  feedback.
- Aligned curation executive graph-readiness counters with the current
  `graph_stix_preview` audit schema so STIX bundle, graph-object and
  graph-relationship totals no longer report zero when preview evidence is
  present.
- Added a `support` redaction profile to `gateway.curation_report` so
  standalone curation reports can be shared with aggregate evidence while
  removing detailed failures, queries and quarantined-candidate lists.
- Added `gateway.diagnostics` as the first read-only support diagnostic
  snapshot. It combines preflight state, configured evidence inventory,
  curation report output and deterministic support warnings.
- Added the first support-safe diagnostic redaction profile. Operators can use
  `python -m gateway.diagnostics --redaction-profile support` to mask local
  paths and customer identifiers while preserving aggregate support evidence.
- Added an `external` redaction profile for curation reports and support
  diagnostics so customer-safe report delivery can reuse the conservative
  aggregate-only redaction model without exposing raw local evidence.
- Added explicit curation report redaction policy metadata. JSON, text, HTML
  and embedded diagnostics now show the selected report profile, intended
  audience, raw-evidence posture and detailed fields removed by shared
  profiles.
- Added `reports.support_diagnostics` to the preflight-visible capability
  inventory so the support snapshot is represented in the product operations
  model.
- Added support-safe diagnostic bundle generation through
  `python -m gateway.diagnostics --redaction-profile support --bundle-file ...`.
  The zip contains only redacted JSON, text and HTML snapshots plus a manifest;
  raw evidence files are deliberately excluded.
- Added standalone HTML diagnostic output through
  `python -m gateway.diagnostics --html-file ...` for local support review and
  shareable redacted snapshots.
- Added rendered source posture to support diagnostics text, HTML and bundle
  output so support can spot source-level attention areas without opening raw
  evidence.
- Added rendered policy insights to support diagnostics text, HTML and bundle
  output so support can identify source-level tuning signals from aggregate
  release/reject evidence.
- Added `gateway.operational_validation` as a read-only v0.8 validation
  checklist. It consolidates preflight and decision-audit evidence into
  `pass`, `warn`, `fail` and `needs-evidence` checks for graph lookup, bounded
  source dry-runs, canonical ATT&CK matching, OpenCTI duplicate review and
  local resource posture.
- Added text/JSON file output for the operational validation checklist so v0.8
  evidence can be archived under `state\reports` and attached to release
  validation notes.
- Added HTML output for the operational validation checklist so operators and
  support can review v0.8 graph-promotion evidence in a local browser without
  opening raw decision audit files.
- Added source-aware author identity hygiene for exported STIX bundles. New
  exports use the `<logical upstream source> via NarrowCTI` convention, such as
  `OTX AlienVault via NarrowCTI` and `MISP via NarrowCTI`, as OpenCTI Author
  values. NarrowCTI provenance remains in audit metadata and graph custom
  properties. Author identities are deterministic to avoid creating duplicate
  OpenCTI identity objects for repeated exports.
- Added `reports.operational_validation` to the preflight-visible capability
  inventory so the v0.8 validation checklist is represented in product
  operations and support diagnostics.
- Added operational validation status to support diagnostics text, HTML, JSON
  and bundle output so support can see which v0.8 validation criteria have
  passed, failed or still need lab evidence.
- Added support diagnostics integration with the operational validation manual
  evidence file so support bundles can reflect operator-recorded lab checks.
- Added support warnings for failed or incomplete v0.8 operational validation
  so support bundles can immediately show whether graph promotion must remain
  blocked.
- Added gateway operational report file output and an `ops` profile service so
  run, source, quarantine and value-metric evidence can be archived from the
  gateway state volume.
- Added the first controlled graph promotion export gate. When
  `NARROWCTI_GRAPH_EXPORT_MODE=export` is explicitly enabled, OTX and MISP send
  accepted graph candidates in the STIX bundle with the legacy report and
  indicators, allowing supported OpenCTI tabs such as Sectors, Malware,
  Vulnerabilities, Attack patterns, Threat actors, Intrusion sets, Countries,
  Indicators and Observables to be populated when source metadata supports
  them.
- Added guarded graph export state marking after successful OpenCTI import so
  local graph deduplication reflects only objects and relationships that were
  actually promoted.
- Added canonical existing-object references for known OpenCTI graph keys with
  valid STIX `standard_id` values, so the graph promotion gate can link reports
  and curated relationships to canonical ATT&CK objects without recreating
  them.
- Extended read-only OpenCTI graph lookup to existing `Malware` and `Tool`
  objects by canonical `standard_id` or exact name. Alias/fuzzy matching remains
  outside the v0.8 safety boundary.
- Validated a bounded real OTX graph export for Arsenal/Malware with the
  `lummac2` query. The run ingested a curated report with 10 indicators and
  referenced the existing OpenCTI `Malware` object `LummaC2` instead of creating
  a duplicate malware entity.
- Added CVE-aware OpenCTI graph lookup for Vulnerability promotion. The lookup
  prefers canonical Vulnerability `standard_id` and then matches `CVE-*` values
  against OpenCTI Vulnerability names.
- Validated a bounded real Vulnerability export against existing OpenCTI
  `CVE-2019-13939`. The export plan deduplicated the CVE, the curated bundle
  referenced the existing Vulnerability object, and OpenCTI did not create a
  duplicate Vulnerability.
- Added conservative Threat Actor and Intrusion Set OpenCTI lookup by
  canonical `standard_id`, exact name and exact alias search.
- Validated a bounded real Intrusion Set export with source value `Palmerworm`.
  The export resolved the alias to existing OpenCTI `BlackTech`, referenced the
  canonical Intrusion Set in the validation Report and did not create a
  duplicate actor object.
- Tightened Arsenal hygiene after lab review showed that `LummaC2` and
  `Lumma Stealer` can exist as separate OpenCTI malware objects. The lookup now
  supports conservative curated alias groups so future `LummaC2` candidates
  resolve to the existing canonical `Lumma Stealer` object when present.
- Added deterministic STIX Report ids based on report name and description so
  repeated export of the same source report updates the same OpenCTI Report
  instead of creating another duplicate report row.
- Validated repeated real OTX exports with fresh state files. The first stable
  Report-id run created one canonical Report for the already-duplicated LummaC2
  title, and the second run kept the OpenCTI Report count unchanged while
  linking the Report to canonical `Malware` `Lumma Stealer`.
- Finished the next graph export activation layer for accepted rich context:
  MITRE data-source candidates now materialize as OpenCTI Data Source objects;
  detection guidance and MISP EventReports materialize as Notes; detection
  rules materialize as pattern-aware Indicators; MISP `ObjectReference` entries
  materialize as STIX Relationships when both UUID endpoints resolve to graph
  objects; and MISP sightings materialize as STIX Sightings when the sighted
  value resolves to an Indicator. MITRE tactic and platform candidates remain
  preserved as curated evidence/context but are held out of the default export
  gate because local OpenCTI import validation did not materialize them as
  useful first-class objects. Unresolved relationship-only evidence remains
  skipped rather than creating unsafe graph edges.
- Validated the rich export activation layer against local OpenCTI 6.9.4 with
  `NarrowCTI clean export activation validation 20260625` and
  `NarrowCTI object reference export validation 20260625`. OpenCTI accepted the
  Data Source, Note, Sighting, Indicator, Malware, Infrastructure, Report and
  relationship outputs from the controlled bundles.
- Consolidated real ATT&CK lookup evidence for the v0.8 operational checklist:
  the OTX Lazarus validation produced canonical matches for `Lazarus Group` and
  10 ATT&CK techniques, while the MISP REDBANC validation produced canonical
  ATT&CK matches for seven to eight techniques depending on the replay state.
  The decision-audit records show lookup-backed `existing_reference_counts`
  instead of new duplicate ATT&CK objects.
- Added the OpenCTI coverage matrix for v0.8. The matrix maps Threats,
  Arsenal, Techniques, Entities, Locations, Observations, Reports, Notes,
  Relationships, Sightings and knowledge views to current NarrowCTI export
  status, guardrails and backlog order.
- Added controlled deep Location export support. Source-backed region,
  administrative-area, city and coordinate evidence can now become native STIX
  `Location` fields (`region`, `country`, `administrative_area`, `city`,
  `latitude`, `longitude`, `precision`). MISP Galaxy meta aliases for
  state/province, city and coordinates are accepted, but real OpenCTI UI
  validation is still required before marking those tabs as validated exports.
- Added source-backed Campaign support from MISP Galaxy evidence. Campaign
  candidates now enter the safe export allow-list, can be emitted as STIX
  `campaign` objects, query OpenCTI by name before creation and can anchor
  relationships such as `Campaign -> targets -> Sector` when the Galaxy meta
  fields support victimology.
- Added victimology-grade target Organization support from explicit MISP Galaxy
  metadata such as `targeted-organization` and `victim-organization`. These
  values are exported as Organization-class Identity objects only when they are
  target metadata; feed authors, collectors and source provenance remain held
  out of graph promotion by default.
- Added MITRE Data Component support from source-backed ATT&CK data source
  strings such as `Process: Process Creation`. NarrowCTI now emits
  `x-mitre-data-component` candidates and `Data Component -> detects -> Attack
  Pattern` relationships when the source string contains component-level
  detail; strings without a component remain Data Source-only.
- Added source-backed Course of Action support for explicit MISP Galaxy
  `course-of-action` evidence. Free-form detection guidance still exports as
  Notes instead of being promoted as mitigation objects without source support.
- Validated the newest matrix export targets against local OpenCTI 6.9.4 with
  `NarrowCTI Matrix Live 20260626 report`. OpenCTI materialized Campaign,
  target Sector, target Organization, MITRE Data Source, MITRE Data Component
  and Course of Action objects, referenced existing canonical ATT&CK `T1059`
  instead of creating a duplicate Attack Pattern, and exposed queryable
  `Campaign -> targets -> Organization`, `Campaign -> targets -> Sector` and
  `Data Component -> detects -> Attack Pattern` relationships.
- Extended read-only OpenCTI graph lookup to matrix Technique objects:
  `Course-Of-Action` through `coursesOfAction`, `Data-Component` through
  `dataComponents` and `Data-Source` through `dataSources`. Export planning now
  accepts OpenCTI canonical `data-component--` and `data-source--` references
  for NarrowCTI `x-mitre-*` candidates, reducing duplicate Technique context in
  repeated graph exports.
- Expanded controlled Organization victimology mapping for MISP Galaxy metadata.
  Source-backed fields such as `targeted-company`, `targeted-entity`,
  `victim-org`, `victim-company`, `victim`, `affected-organization` and
  `impacted-company` can now promote target Organization candidates. Guardrails
  reject feed/provenance values, URLs, domains, emails, ATT&CK ids and CVEs as
  target Organizations.
- Extended read-only OpenCTI graph lookup to target identities: target
  Organizations resolve through `organizations`, target Sectors resolve through
  `sectors`, target Individuals resolve through `individuals`, and source
  identity or collector provenance remains outside automatic Organization
  lookup.
- Added controlled target Individual export for explicit victimology/person
  evidence such as `targeted-person`, `target-individual`, `victim-individual`,
  `affected-person` and `impacted-person`. NarrowCTI emits STIX Identity
  objects with `identity_class=individual`, rejects unsafe provenance,
  observable-like or numeric-only values, and keeps this separate from Threat
  Actor Individual taxonomy. Live validation with
  `NarrowCTI Matrix Individual Builder Validation 20260626B` produced exactly
  one OpenCTI `Individual`, one Report link and a deduplicated follow-up lookup
  with `would_create_object_count=0`.
- Added explicit Threat Actor group/individual taxonomy for MISP Galaxy
  evidence. Default MISP threat-actor evidence is tagged as
  `threat_actor_class=group` and uses OpenCTI `threatActorsGroup` lookup.
  Explicit individual actor evidence is classified as `threat_actor_individual`
  with `threat_actor_class=individual`, uses `threatActorsIndividuals` lookup,
  is excluded from generic STIX `threat-actor` bundle import and is exported
  through native OpenCTI `threatActorIndividualAdd(update=true)`. Live
  validation with
  `NarrowCTI Matrix Threat Actor Individual Native Validation 20260626B`
  produced exactly one OpenCTI `Threat-Actor-Individual`, one Report link and a
  deduplicated follow-up lookup with `would_create_object_count=0`.
- Added the first offline IP-to-ASN enrichment provider interface for MISP
  infrastructure evidence. `NARROWCTI_IP_ASN_ENRICHMENT_FILE` can point to a
  local CSV, JSON, JSONL or `records`/`prefixes` JSON file with CIDR and ASN
  metadata. The provider uses longest-prefix matching and emits explicit
  `IP/CIDR -> belongs-to -> ASN` evidence with enrichment provenance; it is
  disabled by default and does not invent actor or Infrastructure attribution.
- Validated a controlled real MISP ingestion against OpenCTI using local MISP
  event `1525` (`Trickbot to Ryuk in Two Hours`). The import created the report
  `NarrowCTI real MISP ingestion validation 20260626` authored by
  `MISP via NarrowCTI`, exported 25 IoC indicators, accepted 24 graph
  candidates, referenced seven existing ATT&CK objects and created 23
  report-to-ATT&CK relationships. The validation also identified a final
  polish item: detection-rule evidence exported as a generic STIX Indicator
  needs OpenCTI placement review before production-ready enablement.
- The same real MISP validation confirmed that standalone IP IoCs remain
  normal Indicators/Observables unless source-backed Infrastructure evidence is
  present. The IP `206.81.5.253` was queryable as an Indicator and was not
  attached to Infrastructure because that source event did not provide
  infrastructure context.
- Rebuilt and started the `narrowcti/gateway:local` container on the same Docker
  network as OpenCTI and MISP for fidelity-sensitive validation. A controlled
  MISP `event:1525` container run confirmed OpenCTI health check, MISP HTTP 200
  access, IOC guardrail enforcement and policy drop behavior without creating a
  new live ingestion. The next real export evidence should use an
  infrastructure-bearing payload where IP/domain/CIDR/ASN evidence attaches to
  Infrastructure through OpenCTI-compatible relationships.
- Ran a bounded real MISP export through the rebuilt gateway using local MISP
  `event:1` (`URLHaus Malware URLs feed`). The event had 22,732 attributes; the
  run truncated processing to 500 attributes and exported 10 IoC indicators.
  The candidate scored 70 and ingested successfully. OpenCTI contains the
  Report `URLHaus Malware URLs feed` authored by `MISP via NarrowCTI`.
  Vulnerability lookup found existing OpenCTI objects for
  `CVE-2026-24061`, `CVE-2025-55182`, `CVE-2025-14847`, `CVE-2025-54424`,
  `CVE-2026-20841` and `CVE-2025-66398`, so NarrowCTI emitted report-context
  relationships without duplicating those Vulnerability objects. Collector,
  source identity and feed tag candidates were held by policy as expected.
- After enabling MISP OSINT feeds, validated richer MISP Galaxy exports with
  bounded historical replay settings. `event:14` (`OSINT - Packrat: Seven Years
  of a South American Threat Actor`) materialized `Packrat` as an OpenCTI
  `Threat-Actor-Group`, created Sectors for `Activists`, `Journalist` and
  `Political party`, and created three `Packrat -> targets -> Sector`
  relationships. `event:152` (`OSINT - APT Case RUAG Technical Report`)
  materialized Arsenal Tools `Turla` and `Wipbot` and linked the Report to both
  Tools. Both reports were authored as `MISP via NarrowCTI`.
- Added source-backed description preservation and safe existing-object
  description hydration for graph exports. Source-provided descriptions are
  included in promoted STIX objects when feeds provide them. Target-context
  objects without native descriptions receive short provenance-backed
  descriptions, for example `Packrat targets Activists`, and existing objects
  are patched through OpenCTI only when their description is empty and they are
  NarrowCTI-owned. A controlled MISP `event:14` replay confirmed that `Packrat`
  received its MISP Galaxy description and that `Activists`, `Journalist` and
  `Political party` received target-sector provenance descriptions without
  changing non-empty analyst-maintained descriptions or canonical third-party
  ownership. Follow-up controlled validation expanded the same provenance
  description fallback to Campaign, Channel, Event, Course of Action, native
  Security Platform, native Threat Actor Individual, MITRE Data Source and
  MITRE Data Component objects so their OpenCTI Overview pages explain the
  source and relationship context even when feeds do not provide native
  descriptions. The same graph promotion path now preserves source-backed
  temporal evidence as `x_narrowcti_*` custom properties on objects and
  relationships, covering source created/modified/timestamp/date, first_seen,
  last_seen, valid_from and valid_until values when candidates provide them.
  OTX graph evidence now carries pulse lifecycle and aggregate indicator
  observation-window timestamps into promoted records so source-created,
  source-modified, first-seen and last-seen values survive the full graph
  promotion path. MISP graph evidence now carries event created, event
  timestamp or publish timestamp, and event date into source-backed graph
  records when available. Attribute-level MISP `first_seen` and `last_seen`
  values now override those event defaults for precise Vulnerability, Campaign,
  Detection Rule, Infrastructure, Observable and ASN evidence.
- Tightened MISP Sighting export semantics. Positive MISP sightings now preserve
  `date_sighting` as STIX Sighting `first_seen`/`last_seen`, carry source
  confidence when supplied and avoid exporting non-positive MISP sighting types
  such as false positives as positive STIX Sightings.
- Added a detection-rule compatibility gate for OpenCTI export hygiene. YARA
  and Sigma remain pattern-aware Indicator evidence when compatible, while
  Snort, Suricata and PCRE are preserved as labeled Notes with source
  references and raw rule content until OpenCTI-compatible Indicator
  validation exists for those rule types. Native GraphQL Indicator creation is
  now limited to Sigma instead of retrying pattern types already rejected by
  the local OpenCTI lab.
- Tightened Sigma compatibility handling. MISP Sigma rules must now include a
  title, logsource, detection mapping, condition and at least one detection
  selection before NarrowCTI treats them as OpenCTI Indicator-compatible.
  Sigma rules that fail this gate are preserved as labeled Notes with the raw
  rule and compatibility reason, and the native OpenCTI Indicator path skips
  them instead of retrying a known-bad materialization.
- Added follow-up live OpenCTI validation for the detection-rule compatibility
  gate using MISP `event:1649`. The rebuilt gateway container ran a controlled
  real export against local OpenCTI with graph lookup enabled. OpenCTI API
  validation confirmed four Snort rules preserved as Notes with author
  `MISP via NarrowCTI` and labels `narrowcti:detection-rule` plus
  `rule-type:snort`, while compatible Sigma rules remained labeled Indicators.
  The same run reconfirmed Infrastructure/IP/ASN graph relationships and
  canonical lookup reuse for ATT&CK, Malware, Vulnerability, Location,
  Infrastructure and Observable objects.
- Expanded offline MISP IP-to-ASN enrichment graph output. When an explicit
  source-backed Infrastructure object anchors an enriched IP, NarrowCTI now
  emits both `IP -> belongs-to -> ASN` and
  `Infrastructure -> consists-of -> ASN`, preserving enrichment provenance and
  keeping raw standalone IP indicators out of Infrastructure promotion.
- Expanded curation reporting for infrastructure intelligence. Decision-audit
  graph evidence now feeds an `Infrastructure and ASNs` context section with
  top infrastructure entities, ASN concentration, shared entities across
  sources and overlap counters such as threat+infrastructure,
  arsenal+infrastructure and threat+arsenal+infrastructure.
- Validated the Dockerized curation report after the controlled MISP
  `event:1649` export. The generated text, JSON and HTML reports surfaced
  `AS14061 DIGITALOCEAN-ASN`, `AS399629 BL Networks`, the infrastructure IP
  `137.184.181.252`, and overlap counters including
  `arsenal_infrastructure` and `ttp_infrastructure`.
- Added conservative target-sector synonym normalization for graph evidence.
  Clear aliases such as `Financial Services` -> `Finance` and `Defence` ->
  `Defense` deduplicate before export while preserving the source value in
  candidate provenance. Source-specific sector confidence weighting now favors
  explicit MISP `targeted-sector` victimology and structured OTX `industries`
  over generic sector evidence.
- Added conservative target-country normalization for common source aliases and
  ISO-style values such as `AR` -> `Argentina`, `BR` -> `Brazil` and `US` ->
  `United States`, preserving the original feed value in provenance. Explicit
  MISP `targeted-*` geography and structured OTX `targeted_*` geography now
  receive source-specific confidence weighting. Common region aliases such as
  `APAC`, `LATAM` and `EMEA` now normalize to canonical region names while
  preserving the source value.
- Added conservative Intrusion Set alias normalization for validated aliases,
  including `Lazarus` -> `Lazarus Group` and `Palmerworm` -> `BlackTech`, with
  source-value provenance and confidence boost limited to curated alias matches.
- Added conservative Malware alias normalization for validated duplicate-prone
  family names, including `LummaC2` -> `Lumma Stealer`, with source-value
  provenance and confidence boost limited to curated alias matches.
- Added source-backed MITRE mitigation relationships for Courses of Action.
  When a MISP Galaxy course-of-action cluster explicitly carries a mitigated
  ATT&CK technique such as `T1059`, NarrowCTI now emits
  `Course of Action -> mitigates -> Attack Pattern` with relationship
  provenance instead of relying only on Report context.
- Added unit-level IPv6 infrastructure relationship coverage. The STIX builder
  now has regression coverage for `IPv6-Addr -> belongs-to -> Autonomous-System`
  so future clean OpenCTI validation can focus on UI/API rendering rather than
  relationship direction.
- Added OpenCTI Location subtype hints for graph exports. NarrowCTI now emits
  `x_opencti_location_type` for `target_region`, `target_country`,
  `target_administrative_area`, `target_city` and `target_position` so OpenCTI
  materializes source-backed geography as the intended UI object instead of
  relying on generic STIX Location heuristics. Controlled validation with
  `NarrowCTI Matrix Location Type Validation 20260626B` confirmed `Region`,
  `Administrative-Area`, `City` and `Position` objects plus four actor
  `targets` relationships. `Position` preserved latitude, longitude and
  precision. The remaining gap is validating the same path with real OTX/MISP
  payloads that carry deeper victimology geography.
- Added controlled OpenCTI custom SDO export for matrix Channels, Narratives
  and Events. NarrowCTI now emits the required OpenCTI `extension-definition`
  when `channel`, `narrative` or `event` candidates are accepted, preserves
  aliases and type-specific fields such as `channel_types`, `narrative_types`,
  `event_types`, `start_time` and `stop_time`, and queries OpenCTI `channels`,
  `narratives` and `events` before creating new objects. MISP EventReports
  still remain Reports/Notes by default until a source-specific mapper proves a
  real CTI Event. Live validation with
  `NarrowCTI Matrix Custom SDO Builder Validation 20260626C` materialized one
  Channel, one Narrative and one Event in OpenCTI with the expected aliases,
  type fields and Event timestamps.
- Added controlled System export for source-backed `target_system` candidates.
  NarrowCTI emits STIX Identity objects with `identity_class=system` and
  resolves existing OpenCTI Systems through `systems` lookup.
- Added controlled native Security Platform export for explicit
  `security_platform` candidates. NarrowCTI keeps Security Platform out of the
  STIX Identity bundle path because `identity_class=securityplatform`
  materialized as Organization in the local lab. Instead, export mode queries
  `securityPlatforms` and creates missing objects with
  `securityPlatformAdd(update=true)`. Live validation with
  `NarrowCTI Matrix Security Platform Native Validation 20260626B` materialized
  exactly one OpenCTI `SecurityPlatform` with type `SIEM`, and repeated export
  deduplicated through OpenCTI lookup. Follow-up validation with
  `NarrowCTI Matrix Security Platform Report Link Validation 20260626C`
  confirmed that the full export path links native Security Platforms back to
  the imported Report through OpenCTI `reportEdit.relationAdd(object)`; two
  exports produced one platform, one report and one report-context link.
- Added controlled Artifact export for explicit artifact metadata. NarrowCTI
  now emits STIX Artifact observables only when the candidate is explicitly
  typed as `artifact` and provides a hash algorithm/value, preserves optional
  URL and MIME metadata, and resolves existing OpenCTI Artifacts through
  `stixCyberObservables` by hash. Live validation with
  `NarrowCTI Matrix Artifact Builder Validation 20260626B` materialized exactly
  one OpenCTI `Artifact`; generic file hashes remain file observables or
  Indicators and are not promoted as Artifacts automatically.
- Added Kill Chain preservation for fallback Attack Pattern export. When
  NarrowCTI must create an `attack-pattern` because canonical OpenCTI ATT&CK
  lookup has no match, the STIX builder now carries source-backed
  `kill_chain_phases` from the graph candidate. The production recommendation
  remains to load ATT&CK through the official MITRE connector and let
  NarrowCTI link curated source evidence to those canonical objects.

## Promotion Boundary

The v0.8 default remains read-only, but `NARROWCTI_GRAPH_EXPORT_MODE=export`
now enables the first controlled graph promotion gate. This should stay
disabled in production-like environments until source-specific validation,
OpenCTI duplicate review and rollback evidence are available.

The correct sequence remains:

```text
graph candidate
  -> policy
  -> local graph deduplication
  -> OpenCTI canonical graph lookup
  -> dry-run/audit evidence
  -> lab import validation
  -> controlled graph promotion
  -> post-export state marking
```

The export gate intentionally avoids recreating known graph keys returned by
local deduplication or OpenCTI lookup. When a lookup match includes a canonical
STIX `standard_id`, NarrowCTI references that existing object in the curated
bundle and can create report-context or semantic relationships to it.

## Product Operations Boundary

The v0.8 capability inventory foundation is intentionally non-invasive.
`gateway.preflight` reports `distribution_model=open_source`,
`open_source=true`, declared capabilities, unknown declarations and active
capability inventory so support and deployment teams can verify product state
before a run. Source runtime blocking by capability is not enabled in this
release.

The deployment template is also conservative by design. It uses dry-run,
run-once and audit graph mode defaults, joins an existing OpenCTI Docker network
and persists gateway evidence in a dedicated volume. It is a repeatable pilot
template, not a managed installer.

The analyst review foundation is similarly conservative. It introduces a stable
Python service boundary for future API/UI work, but no HTTP server or browser UI
is enabled in v0.8.

The curation report foundation is read-only and evidence-driven. It prepares the
enterprise reporting model without generating PDFs, mutating review state or
calling external APIs.

The support diagnostics foundation is also read-only. It inventories configured
local evidence paths and summarizes preflight and curation posture without
collecting secrets, calling OpenCTI or changing runtime state.

The `support` and `external` redaction profiles are intentionally conservative.
They preserve aggregate counts and graph-readiness evidence, but remove detailed
lists that can expose local paths, customer identifiers or sensitive queue
context.

## Validation

Current validation command:

```text
.\scripts\validate-v0.6.ps1
```
