# NarrowCTI Gateway Runtime - v0.5.0

## Purpose

The v0.5.0 track should introduce the first unified NarrowCTI Gateway runtime.
The goal is to move from source-specific container execution toward one gateway
process that can orchestrate enabled sources while preserving source-level
isolation, safety limits, state and audit evidence.

v0.4 proves that OTX and MISP can use the same feed contract and decision
foundation. v0.5 should turn that foundation into the runtime shape of the
product.

## Product Standard

v0.5 must keep NarrowCTI positioned as a professional CTI gateway, not as a
collection of feed connectors. The runtime should make the product feel like a
curation and decision layer for analysts, hunters and platform teams:

- Feed data is normalized before it becomes OpenCTI graph data.
- Every decision remains explainable and auditable.
- Risky sources remain controlled through dry-run, run-once and guardrail limits.
- Source provenance is preserved so analysts can understand collector context and
  original intelligence origin.
- Runtime summaries should help operators understand value, noise reduction and
  source behavior.

## Target Runtime Model

```text
NarrowCTI Gateway entrypoint
  -> gateway settings
  -> source registry
  -> source runtime for OTX
  -> source runtime for MISP
  -> shared scoring, policy, audit and deduplication services
  -> source-scoped state and artifact indexes
  -> OpenCTI export service
  -> source and gateway operational summaries
```

The gateway process decides which sources are enabled, builds each source
runtime from external configuration, executes each source safely and reports a
combined gateway run summary.

## Architecture Continuity

The v0.5 runtime must preserve the architecture established from v0.2 through
v0.4:

- Source packages own source-specific API access and normalization.
- `core` owns shared feed contracts, policy, scoring, state and decision audit.
- `exporters` own STIX and OpenCTI export concerns.
- Gateway orchestration must compose these pieces instead of moving feed-specific
  behavior into a monolithic process.

## Container Strategy

The v0.4 model intentionally keeps runtime containers split by source:

```text
connector-narrowcti       OTX reference runtime
connector-narrowcti-misp  MISP dry-run/backfill runtime
```

The v0.5 model should add a gateway container as the default product runtime:

```text
narrowcti-gateway
  enabled sources: otx,misp
```

Source-specific commands should remain available for debugging, validation and
bounded backfills. The MISP path in particular must remain opt-in and guarded
until repeated local validations show stable OpenCTI, queue and Elasticsearch
behavior.

## Configuration Direction

Gateway-level configuration should describe runtime behavior that applies across
sources:

```text
NARROWCTI_MODE=gateway
NARROWCTI_ENABLED_SOURCES=otx,misp
NARROWCTI_DRY_RUN=true
NARROWCTI_RUN_ONCE=true
NARROWCTI_SOURCE_INTERVAL_SECONDS=300
NARROWCTI_STATE_DIR=/app/state
NARROWCTI_DECISION_AUDIT_DIR=/app/state/audit
NARROWCTI_DEDUP_MODE=hybrid
NARROWCTI_OPENCTI_DEDUP_LOOKUP=false
NARROWCTI_DEDUP_STATE_FILE=/app/state/dedup_index.json
```

Source-specific configuration should remain source-specific:

```text
OTX_API_KEY=...
OTX_QUERIES=...

MISP_URL=...
MISP_KEY=...
MISP_QUERIES=...
MISP_MAX_EVENTS_PER_RUN=1
MISP_MAX_ATTRIBUTES_PER_EVENT=1000
MISP_OVERSIZED_EVENT_ACTION=skip
```

The gateway must not force OTX and MISP to share processing state. Shared
services are acceptable; source state and audit context must remain clearly
scoped.
The detailed parameter reference for curation filters, policy thresholds,
guardrails, source-specific controls and target gateway variables is maintained
in `docs/configuration-reference-v0.5.md`.

## Decision Engine Scope

The decision engine remains part of v0.5, but it should be implemented as a
gateway service rather than as source-specific logic.

The v0.5 decision layer should improve:

- Source-specific weighting.
- Age, confidence, indicator type and operational relevance scoring.
- Policy reasons and evidence attached to every decision.
- Quarantine reporting and operator review data.
- Per-source and aggregate run summaries.

## Deduplication and Graph Hygiene

Deduplication is a product-level curation capability, not just a local runtime
optimization. NarrowCTI should prevent unnecessary OpenCTI graph growth while
preserving the intelligence value of repeated sightings across sources.

The current implementation has two deduplication layers:

- Source-item state prevents the same OTX pulse or MISP event from being
  reprocessed after a successful export.
- STIX bundle construction removes repeated indicator patterns inside the same
  export bundle.

The v0.5 gateway should evolve this into layered pre-export deduplication:

- Source-item deduplication uses `source_key + external_id` to avoid repeated
  processing of the same upstream object.
- Artifact deduplication builds normalized fingerprints such as
  `indicator_type + normalized_value` before export.
- Optional OpenCTI lookup can check whether the indicator or observable already
  exists before import. This must be configurable because it adds API cost and
  operational coupling to OpenCTI.
- Cross-source matches should enrich provenance, confidence and audit evidence
  instead of creating duplicate graph objects.
- Deduplication decisions should be visible in audit records and summaries as
  skipped, already-known or correlated outcomes.

The target behavior is graph hygiene with analyst value: repeated sightings are
not noise, but they should become context rather than duplicate objects.

## Guardrails

The v0.5 runtime must preserve the safety posture established in v0.4:

- Default dry-run for risky or newly enabled sources.
- Run-once support for controlled validation.
- Per-source state files or namespaced state keys.
- Per-source audit records with collector and original-source provenance.
- Per-source circuit breakers for max events, max attributes and max IoCs.
- A source failure must be reported without stopping other enabled sources.
- MISP historical backfill must stay bounded, explicit and opt-in.

## Non-Goals

- Removing the direct OTX runtime.
- Removing the MISP validation/backfill runtime.
- Building a customer-facing admin UI.
- Running broad MISP historical backfill by default.
- Adding technical license enforcement.
- Replacing MISP or OpenCTI.

## Implementation Plan

1. Add a neutral gateway entrypoint outside the OTX and MISP packages.
2. Add a source registry that maps source keys to runtime factories.
3. Register OTX and MISP using the existing adapters, processors and settings.
4. Add gateway settings for enabled sources, dry-run, run-once and intervals.
5. Add a gateway loop that executes each enabled source and isolates failures.
6. Add layered deduplication services for source items, artifact fingerprints and
   optional OpenCTI lookup.
7. Add aggregate runtime summaries while keeping per-source summaries intact.
8. Add Docker and Compose guidance for the `narrowcti-gateway` service.
9. Keep source-specific entrypoints for troubleshooting and safe backfills.

## Success Criteria

- One gateway command can run OTX and MISP in dry-run mode.
- A failing source does not prevent another enabled source from running.
- OTX and MISP keep separate state and audit evidence.
- Dry-run mode exports nothing to OpenCTI.
- Duplicate source items and duplicate artifact fingerprints do not create
  duplicate OpenCTI imports.
- OpenCTI-side deduplication lookup is configurable and audited when enabled.
- Cross-source matches preserve provenance instead of creating graph noise.
- Source-specific guardrails remain enforced inside the gateway runtime.
- Unit tests cover source registry behavior, gateway settings, isolated source
  failures and aggregate summaries.
