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

## MISP Adapter Guardrails

The NarrowCTI MISP adapter must enforce controls before exporting to OpenCTI:

- Maximum events per run.
- Maximum attributes per event.
- Oversized event skip or quarantine behavior.
- Explicit source provenance for collector and original source.
- Attribute-level normalization based on `type`, `category`, `to_ids`, tags and
  first/last seen fields.

## Success Criteria

- OTX and MISP can both produce normalized feed candidates.
- The processor can evaluate candidates without source-specific branching.
- Decision audit records include enough source context for analyst review.
- Tests cover the shared multi-feed behavior.
- Documentation explains when to use direct OTX versus MISP-backed ingestion.
