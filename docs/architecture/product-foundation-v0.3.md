# NarrowCTI Product Foundation - v0.3.0

## Purpose

The v0.3.0 track moves NarrowCTI from a single functional OTX connector toward an
open source gateway product foundation.

The v0.3.0 naming decision is explicit: the product is NarrowCTI Gateway, while
OTX is only the first reference feed adapter. The v0.2 line can still be described
as an OTX connector foundation, but v0.3 is the product identity transition.

The product vision is not to replace OpenCTI. NarrowCTI is designed to sit in
front of OpenCTI as a pre-ingestion intelligence decision layer. Its purpose is
to reduce analyst workload by ensuring that raw feeds are enriched, scored,
deduplicated and evaluated before they enter the OpenCTI graph.

## Product Thesis

Threat intelligence teams often centralize feeds in a TIP, but still spend too
much time validating low-context indicators, removing duplicates, pivoting
manually and deciding whether a pulse, event or indicator deserves operational
attention.

NarrowCTI addresses this gap by controlling the ingestion path:

```text
External and internal feeds
  -> NarrowCTI
  -> enrichment, scoring, policy and deduplication
  -> OpenCTI
  -> analyst-ready intelligence
```

The product promise:

```text
Curated intelligence before it reaches your graph.
```

## Market Position

The market already has threat intelligence platforms, feed providers and
automation tools. NarrowCTI should be positioned more specifically:

```text
An OpenCTI-native intelligence gateway for teams that need better control over
what enters their threat intelligence graph.
```

This keeps the product complementary to OpenCTI instead of competing with it.

## Target Audience

- CTI analysts who need cleaner intelligence for investigation.
- Threat hunters who need better pivots and less low-value feed noise.
- SOC teams that want OpenCTI ingestion to be policy-driven.
- MSSPs that need repeatable feed governance across customer environments.
- Security platform owners responsible for OpenCTI operations.

## Core Value

NarrowCTI should deliver value through:

- Pre-ingestion decisions before OpenCTI is polluted by low-value data.
- Explainable drop, quarantine and ingest outcomes.
- Source-specific scoring and policy.
- Persistent deduplication across runs.
- Consistent STIX export into OpenCTI.
- Multi-feed architecture using a shared decision model.
- Operational evidence that shows how much noise was reduced.

## v0.3.0 Scope

This version should establish:

- Product positioning and documentation in English.
- Apache-2.0 open source licensing foundation.
- Third-party dependency notice tracking.
- Shared feed contract for future connectors.
- OTX feed adapter as the reference implementation of the shared contract.
- Structured decision audit records for ingest, drop, quarantine and skip
  outcomes.
- Per-query operational summaries for feed-noise reduction review.
- Product path from the foundation to a production-ready open source release.
- Runtime, Compose service and documentation naming aligned to NarrowCTI Gateway.
- OTX remains the reference implementation, not the product name.

## Non-Goals

This version should not rush into:

- A full MISP connector before the feed contract is stable.
- A customer-facing admin interface.
- Commercial activation or paid feature blocking in the core gateway.
- Online activation or hosted licensing service.
- Advanced correlation that has not yet been modeled or tested.

## Success Criteria

v0.3.0 is successful when:

- The repository clearly communicates product direction.
- The licensing posture is explicit enough for open source adoption and future
  optional services planning.
- Future feeds have a common contract to implement.
- OTX has an adapter that maps source data into the common feed model.
- Decisions can be captured as structured operational evidence.
- Query summaries show reviewed, ingested, dropped, quarantined, skipped and
  failed candidates.
- The NarrowCTI Gateway runtime with the OTX adapter still passes all validation.
- The next feed can be added without copying OTX-specific pipeline assumptions.
- Operators see NarrowCTI Gateway as the connector/runtime identity in OpenCTI and Compose.
