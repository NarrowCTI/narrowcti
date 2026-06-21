# NarrowCTI Gateway Runtime - v0.5.0

## Purpose

The v0.5.0 track should introduce the first unified NarrowCTI Gateway runtime.
The goal is to move from source-specific container execution toward one gateway
process that can orchestrate enabled sources while preserving source-level
isolation, safety limits, state and audit evidence.

v0.4 proves that OTX and MISP can use the same feed contract and decision
foundation. v0.5 should turn that foundation into the runtime shape of the
product.

## Target Runtime Model

```text
NarrowCTI Gateway entrypoint
  -> gateway settings
  -> source registry
  -> source runtime for OTX
  -> source runtime for MISP
  -> shared scoring, policy, audit and export services
  -> source-scoped state and operational summaries
```

The gateway process decides which sources are enabled, builds each source
runtime from external configuration, executes each source safely and reports a
combined gateway run summary.

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

## Decision Engine Scope

The decision engine remains part of v0.5, but it should be implemented as a
gateway service rather than as source-specific logic.

The v0.5 decision layer should improve:

- Source-specific weighting.
- Age, confidence, indicator type and operational relevance scoring.
- Policy reasons and evidence attached to every decision.
- Quarantine reporting and operator review data.
- Per-source and aggregate run summaries.

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
6. Add aggregate runtime summaries while keeping per-source summaries intact.
7. Add Docker and Compose guidance for the `narrowcti-gateway` service.
8. Keep source-specific entrypoints for troubleshooting and safe backfills.

## Success Criteria

- One gateway command can run OTX and MISP in dry-run mode.
- A failing source does not prevent another enabled source from running.
- OTX and MISP keep separate state and audit evidence.
- Dry-run mode exports nothing to OpenCTI.
- Source-specific guardrails remain enforced inside the gateway runtime.
- Unit tests cover source registry behavior, gateway settings, isolated source
  failures and aggregate summaries.
