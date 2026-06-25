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
Operational validation is tracked in `docs/operational-validation-v0.8.md`.
Deployment operations are tracked in `docs/deployment-operations-v0.8.md`.
Analyst review design is tracked in `docs/analyst-review-v0.8.md`.
Curation reporting is tracked in `docs/curation-reporting-v0.8.md`.
Support diagnostics are tracked in `docs/support-diagnostics-v0.8.md`.

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

## Promotion Boundary

The v0.8 first cut is still read-only. It does not import graph objects into
OpenCTI and does not mark graph objects as exported.

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
