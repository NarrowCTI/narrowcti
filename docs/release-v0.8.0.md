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
- Added the first v0.8 deployment operations package:
  `deployment/docker-compose.narrowcti-gateway.yml`,
  `deployment/gateway.env.example` and
  `docs/deployment-operations-v0.8.md`.
- Added `gateway.review.AnalystReviewService` as the internal analyst review
  API for quarantine list, summary, release, partial release, reject, export
  dry-run and audit-event reads. The CLI now delegates review operations to
  this service.
- Added `gateway.curation_report` as the first analyst-facing curation report
  model. It consolidates gateway run summaries, decision audit, analyst review
  status and graph readiness evidence into text or JSON output.
- Added `gateway.diagnostics` as the first read-only support diagnostic
  snapshot. It combines preflight state, configured evidence inventory,
  curation report output and deterministic support warnings.

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

## Validation

Current validation command:

```text
.\scripts\validate-v0.6.ps1
```
