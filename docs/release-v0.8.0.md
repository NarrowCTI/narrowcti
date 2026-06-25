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
- Documented Report hygiene evidence: deterministic Report ids prevent another
  row when name and description are unchanged; a changed description is treated
  as a distinct report by design.
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
- Added the first license and feature gate inventory foundation through
  edition/capability defaults, `NARROWCTI_LICENSE_*` settings and preflight
  reporting. This is observable product-operations plumbing only; runtime
  entitlement blocking remains pending.
- Added disabled-capability visibility to feature gate state and preflight
  output so support can see which known product capabilities are outside the
  declared edition or explicit override.
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
- Added source-aware author identity hygiene for exported STIX bundles. OTX and
  MISP exports now use upstream source identities such as `OTX AlienVault` and
  `MISP` as OpenCTI Author values, while NarrowCTI provenance remains in audit
  metadata and graph custom properties. Author identities are deterministic to
  avoid creating duplicate OpenCTI identity objects for repeated exports.
- Added `reports.operational_validation` to the preflight-visible capability
  inventory so the v0.8 validation checklist is represented in product
  operations and future licensing controls.
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

The v0.8 license and feature gate foundation is intentionally non-invasive.
`gateway.preflight` reports edition, customer id, license-file configuration,
active capabilities and strict-gate status so support and deployment teams can
verify product state before a run. If `NARROWCTI_FEATURE_GATES_ENFORCED=true`
is configured without `NARROWCTI_LICENSE_FILE`, preflight fails. Source runtime
blocking by capability is not enabled in this release.

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
