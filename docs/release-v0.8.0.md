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

## Implemented Foundation

- Created `core/opencti_graph_lookup.py` as a read-only OpenCTI graph lookup
  adapter.
- Added `docs/graph-promotion-v0.8.md` to document the graph promotion boundary,
  canonical MITRE linking model and validation path.
- Added ATT&CK attack-pattern lookup by `x_mitre_id` first, then by STIX
  `standard_id` when a MITRE technique id is not available.
- Made the lookup compatible with the existing `graph_export_plan` known-key
  interface so OpenCTI-known entities can be treated as deduplicated planning
  evidence before export.
- Added fail-open behavior for OpenCTI graph lookup errors. Lookup failures are
  logged and do not block the existing audit/dry-run plan.
- Added unit coverage for MITRE attack-pattern lookup, fail-open behavior,
  STIX-id fallback and unsupported candidate handling.

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

## Validation

Current validation command:

```text
.\scripts\validate-v0.6.ps1
```
