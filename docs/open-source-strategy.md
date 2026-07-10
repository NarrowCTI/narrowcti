# NarrowCTI Open Source Strategy

## Purpose

This document defines NarrowCTI's open source product direction.

NarrowCTI core is intended to remain an open, Apache-2.0 licensed CTI curation
gateway for OpenCTI. The project should build trust by keeping the core value
visible, auditable, extensible and free to run without commercial activation.

This is not legal advice. Before selling services, managed deployments or
separate commercial modules around NarrowCTI, review the final packaging and
customer terms with qualified legal counsel.

## Open Source Posture

The core repository is licensed under Apache-2.0.

The open source core includes the product's essential intelligence workflow:

- Feed ingestion adapters.
- Normalization and source-specific metadata extraction.
- Contextual scoring and explainable policy.
- Deduplication and OpenCTI graph hygiene.
- Quarantine, release and audit evidence.
- MITRE ATT&CK context enrichment.
- STIX generation and OpenCTI export controls.
- Operational reports and support diagnostics.

This avoids turning the main value proposition into a closed activation gate.
The core should be strong enough for analysts, hunters and CTI teams to trust,
inspect and improve.

## Capability Inventory

NarrowCTI still exposes a capability inventory in preflight and diagnostics.
That inventory is not a license enforcement mechanism. It exists so operators
can see which runtime surfaces are available in a deployment and which
capabilities were intentionally declared in configuration.

Current capability identifiers:

```text
source.otx
source.misp
enrichment.otx_entities
enrichment.mitre_attack
quarantine.review
reports.operational
reports.operational_validation
reports.support_diagnostics
graph.export.audit
graph.export.dry_run
graph.lookup.opencti
graph.export.controlled
deployment.templates
mssp.multi_environment
```

The preflight report should identify:

- `distribution_model=open_source`
- `open_source=true`
- available capabilities
- enabled capabilities
- declared capabilities from `NARROWCTI_CAPABILITIES`
- unknown declared capabilities that may indicate configuration drift

## Future Commercial Options

Future monetization, if needed, should sit around the open source core rather
than weakening it.

Good candidates:

- Managed SaaS or hosted private deployment.
- Enterprise support and response-time commitments.
- Professional services for deployment, tuning and integration.
- Training and operational enablement.
- Customer-specific connectors or playbooks.
- Separate optional modules with their own license, when the separation is
  technically and legally clean.

The core gateway should remain usable without a paid license or internet
activation.

## Required Review Before Paid Offerings

Before offering paid services, managed deployments or separate paid modules,
review:

- Apache-2.0 obligations for the core repository.
- Third-party dependency notices.
- Docker base image terms.
- OpenCTI client and API usage terms.
- OTX, MISP and other feed provider API terms.
- Support, warranty and service-level language.
- Trademark and branding usage.
- Separation between open source core and any optional commercial module.

## Repository Controls

The repository should maintain:

- `LICENSE` for the Apache-2.0 project license.
- `THIRD_PARTY_NOTICES.md` for dependency and platform notice tracking.
- `.env.example` files without secrets.
- No committed customer paths, usernames, tokens or lab-specific secrets.
- Clear docs separating lab deployment from product deployment.

## v0.8.0 Direction

For v0.8.0, the open source alignment includes:

- Apache-2.0 license in the repository.
- Capability inventory instead of commercial activation inventory.
- No runtime commercial activation parsing.
- No feature blocking by edition.
- Preflight and diagnostics showing open source distribution posture.
- Deployment compose templates without license volumes.
