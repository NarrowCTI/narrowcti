# NarrowCTI Multi-Feed Expansion - v0.4.0

## Purpose

The v0.4.0 track starts the transition from a single reference OTX adapter to
a reusable multi-feed gateway. The goal is to prove that NarrowCTI can evaluate
intelligence from at least two real sources through the same feed contract,
policy layer, decision audit and OpenCTI export path.

## Initial Feed Direction

MISP is the preferred second adapter for this track. The product should treat
MISP as an operational IoC and event hub, not as a replacement for NarrowCTI.
MISP centralizes events and indicators; NarrowCTI decides what should reach
OpenCTI and why.

Recommended flow for environments that already centralize AlienVault OTX in
MISP:

```text
AlienVault OTX and other feeds
  -> MISP
  -> NarrowCTI Gateway
  -> OpenCTI
```

The existing direct OTX adapter remains useful for labs, environments without
MISP and adapter contract validation.

## v0.4.0 Scope

- Define the MISP adapter contract mapping.
- Preserve source provenance, including collector and original source when
  available.
- Reuse the v0.3 feed contract instead of creating MISP-specific pipeline
  behavior.
- Keep OpenCTI export behavior consistent across OTX and MISP candidates.
- Add focused tests that prove two feed adapters can use the same decision
  foundation.

## Non-Goals

- Replacing MISP.
- Removing the direct OTX adapter.
- Building a customer-facing admin UI.
- Adding advanced correlation before the second adapter is stable.
- Adding runtime license enforcement.


## Runtime Validation Findings

A local runtime validation was performed on 2026-06-21 with OpenCTI 6.9.4,
MISP and `opencti/connector-misp:6.9.4`.

Key findings:

- MISP event shape is event-centric, with `Event`, `Attribute`, `Object`, `Tag`,
  `Galaxy`, `Org` and `Orgc` fields.
- One MISP event can be tiny or enormous. The local MISP returned one URLHaus
  event with 16922 attributes and one small OSINT event with 10 attributes.
- The official OpenCTI MISP connector does not support `MISP_IMPORT_LIMIT` in
  version 6.9.4. Its client hardcodes a page limit of 10 and paginates until no
  more matching events are returned.
- The official connector is useful as a reference and for OpenCTI-native import,
  but it is not enough for NarrowCTI's controlled curation/backfill model.

Detailed evidence is documented in `docs/misp-validation-v0.4.md`.

The first local MISP dry-run runtime validation succeeded on 2026-06-21 with
`MISP_MAX_EVENTS_PER_RUN=1`. Default policy quarantined the sampled event,
and a policy-relaxed validation reached `dry_run=1` without OpenCTI export or
persistent state marking. Runtime provenance validation also confirmed audit
metadata with collector, original source, MISP IDs, tags and guardrail context.

## MISP Adapter Guardrails

The NarrowCTI MISP adapter must enforce controls before exporting to OpenCTI:

Implemented foundation controls:

- `MISPAdapterLimits.max_events_per_run` limits search normalization scope.
- `MISPAdapterLimits.max_attributes_per_event` blocks oversized events before
  IoC normalization.
- `oversized_event_action="skip"` is the default safety behavior.
- `oversized_event_action="truncate"` keeps a bounded sample and records
  `narrowcti_controls` in raw candidate context.
- MISP search uses metadata mode first so attribute counts can be checked before
  full enrichment.
- `MISPSettings` externalizes required MISP connection, query, timeout and
  safety-limit configuration.
- `MISPEventStateRepository` keeps MISP event state separate from OTX pulse
  state while preserving the shared repository pattern.
- `MISPProcessor` wires MISP search, enrichment, state, policy, decision
  audit and OpenCTI export through a dedicated runtime path.
- `FeedRunSummary` now tracks skipped, error and dry-run outcomes for
  multi-feed operational summaries.
- `MISP_DRY_RUN=true` is the default validation mode; it records the
  would-ingest decision without exporting to OpenCTI or marking state.
- MISP decision audit metadata captures collector, original source, MISP event
  identifiers, event tags and guardrail context.
- Attribute normalization covers direct IoCs plus safe composite values such as
  IP/port, host/port, domain/IP, filename/hash and `malware-sample`.
- Safe historical backfill controls are externalized through run-once execution,
  dry-run mode, date filters, tag filters and published-only filtering.
- An opt-in `connector-narrowcti-misp` Docker Compose service/profile validates
  the MISP runtime separately from the OTX reference runtime.
- MISP operational summaries count adapter-level guardrail skips before event
  enrichment, making oversized backfill attempts visible as skipped work.
- MISP decision audit metadata records IoC truncation when
  `MISP_MAX_IOCS_PER_EVENT` limits the export payload.

Remaining controls before broader runtime use:

- Keep the MISP runtime opt-in and dry-run by default while progressively
  widening backfill windows on resource-limited labs.
- Promote scheduled MISP execution only after queue, Elasticsearch and OpenCTI
  worker behavior remain stable across multiple bounded runs.

## Success Criteria

- OTX and MISP can both produce normalized feed candidates.
- The processor can evaluate candidates without source-specific branching.
- Decision audit records include enough source context for analyst review.
- Tests cover the shared multi-feed behavior.
- Documentation explains when to use direct OTX versus MISP-backed ingestion.
