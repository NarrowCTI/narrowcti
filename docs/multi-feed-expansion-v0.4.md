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

## Success Criteria

- OTX and MISP can both produce normalized feed candidates.
- The processor can evaluate candidates without source-specific branching.
- Decision audit records include enough source context for analyst review.
- Tests cover the shared multi-feed behavior.
- Documentation explains when to use direct OTX versus MISP-backed ingestion.
