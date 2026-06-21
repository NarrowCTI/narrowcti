# NarrowCTI Roadmap

## Branching And Release Model

NarrowCTI uses this flow:

```text
work branch -> dev -> main -> version tag
```

`dev` is the integration branch. `main` is the stable branch. Official versions
are marked with tags.

## v0.2.0 - Modular OTX Foundation

Status: released.

Purpose:

- Establish a modular OTX connector foundation.
- Split settings, OTX API access, processing, policy, state and STIX export.
- Validate the connector through Docker build, syntax checks and unit tests.
- Provide safe environment configuration examples.

## v0.3.0 - Product Foundation

Status: released.

Purpose:

- Define product positioning and commercial direction.
- Add initial proprietary licensing foundation.
- Track third-party dependency notices.
- Introduce a shared feed contract for multi-feed development.
- Add an OTX feed adapter as the reference contract implementation.
- Add structured decision audit records for operational review.
- Add per-query operational summaries for reviewed and handled candidates.
- Rename runtime identity from OTX-specific naming to NarrowCTI Gateway.
- Keep OTX as the reference adapter while preparing for additional feeds.

Expected outcomes:

- The project reads as NarrowCTI Gateway, not an OTX custom connector.
- Licensing and distribution boundaries are explicit.
- Future feed adapters have a stable contract to follow.
- The OTX feed can be normalized through the shared feed contract.
- Ingest, drop, quarantine and skip outcomes can be audited.
- Query execution can report reviewed, ingested, dropped, quarantined, skipped
  and failed candidates.

## v0.4.0 - Multi-Feed Expansion

Status: in development.

Purpose:

- Add a second real feed, with MISP as the likely candidate.
- Prove that NarrowCTI Gateway is a reusable multi-feed intelligence gateway.
- Reuse the shared feed contract instead of duplicating OTX-specific logic.

Expected outcomes:

- At least two feeds use the same decision foundation.
- MISP payload and official connector behavior are validated against real local data.
- Feed-specific scoring inputs are normalized.
- MISP runtime foundation uses shared state, policy, audit and export paths.
- Local MISP dry-run validation proves search, enrichment, policy and audit
  without OpenCTI export.
- OpenCTI export remains consistent across sources.

## v0.5.0 - Intelligence Decision Engine

Purpose:

- Improve scoring beyond the current basic model.
- Add source-specific weighting.
- Expand policy reasons and evidence.
- Improve quarantine behavior and reporting.

Expected outcomes:

- Every ingestion decision is explainable.
- Analysts can understand why intelligence was dropped, quarantined or ingested.
- The gateway can prioritize intelligence based on source, age, confidence,
  indicator type and operational relevance.

## v0.6.0 - Operational Layer

Purpose:

- Add operational metrics and clearer runtime reporting.
- Add dry-run mode.
- Improve health checks.
- Produce value metrics such as reviewed, ingested, dropped and quarantined
  intelligence by source.

Expected outcomes:

- Operators can tune the gateway safely.
- Customers can see measurable feed-noise reduction.
- Runtime behavior is easier to support.

## v0.7.0 - Commercial Licensing

Purpose:

- Add technical license enforcement.
- Support offline signed license files.
- Track customer id, expiration and enabled features.
- Introduce feature gates by feed, environment or capability.

Expected outcomes:

- Product use can be controlled without requiring internet access.
- Commercial packaging has a technical foundation.
- Support teams can identify customer and entitlement state.

## v0.8.0 - Deployment Package

Purpose:

- Provide a cleaner installation and upgrade path.
- Add deployment templates.
- Harden configuration defaults.
- Document customer installation procedures.

Expected outcomes:

- The product can be deployed repeatably outside the lab.
- Upgrade steps are clear.
- Customer onboarding becomes predictable.

## v1.0.0 - Commercial-Ready Release

Purpose:

- Ship a stable, documented and installable product.
- Finalize commercial license and support terms.
- Provide validated deployment guidance.
- Maintain a clear changelog and upgrade path.

Expected outcomes:

- NarrowCTI is ready for controlled commercial delivery.
- Product, engineering, licensing and operations are aligned.
