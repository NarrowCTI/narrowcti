# NarrowCTI Licensing Strategy

## Purpose

This document defines the initial licensing direction for NarrowCTI as it moves
toward commercial distribution.

It is not a final EULA and it is not legal advice. It is a product and
engineering baseline that should be reviewed by qualified legal counsel before
the product is sold, distributed or deployed for customers.

## Licensing Posture

NarrowCTI is being prepared as proprietary commercial software.

The current repository license notice is intentionally restrictive:

```text
All rights reserved unless a separate written agreement states otherwise.
```

This protects the product while the commercial model, customer terms and
technical entitlement model are being designed.

## Why Licensing Starts In v0.3.0

Licensing should influence architecture before the project grows into multiple
feeds and operational modules.

Starting now helps avoid future rework around:

- Module boundaries.
- Feature gating.
- Distribution packaging.
- Customer-specific entitlements.
- Documentation and support terms.
- Separation between product code, examples and local lab assets.

## Commercial Packaging Direction

Potential editions:

- Evaluation: limited-time trial for lab validation.
- Professional: single OpenCTI environment with selected feed adapters.
- Enterprise: multiple environments, advanced policy and operational reporting.
- MSSP: multi-customer deployment model with stronger tenant boundaries.

These edition names are placeholders. They should be validated against product
strategy before customer-facing use.

## Technical Enforcement Foundation

The recommended licensing model is offline-first:

```text
signed license file
  -> customer id
  -> expiration
  -> enabled features
  -> allowed feeds
  -> environment limits
```

Offline-first licensing is better aligned with security environments where
internet access may be restricted.

The v0.8 foundation introduces preflight-visible feature gate inventory, not
full runtime entitlement blocking. The gateway can now report:

- Declared product edition.
- Optional customer or environment id.
- Whether a signed license file path is configured.
- Whether strict feature gate validation is enabled.
- Which capabilities are active for the declared edition or explicit override.

Runtime enforcement remains a later hardening step after legal review, license
format selection and customer deployment validation. Until then, the foundation
is designed for observability, supportability and low-risk product operations.

## Feature Gate Candidates

Potential licensed capabilities:

- Number of enabled feed adapters.
- MISP connector.
- Commercial feed connectors.
- Advanced decision engine.
- Operational metrics and reports.
- Dry-run comparison reports.
- Multi-environment support.
- MSSP-oriented controls.

Current v0.8 technical capability identifiers:

```text
source.otx
source.misp
enrichment.otx_entities
enrichment.mitre_attack
quarantine.review
reports.operational
graph.export.audit
graph.export.dry_run
graph.lookup.opencti
graph.export.controlled
deployment.templates
mssp.multi_environment
```

## Required Legal Review

Before commercial distribution, review:

- Final proprietary license or EULA.
- Third-party dependency licenses.
- Docker base image terms.
- OpenCTI client and API usage terms.
- OTX and other feed provider API terms.
- Support and warranty language.
- Restrictions around managed service use.

## Repository Controls

The repository should maintain:

- `LICENSE` for the current project license notice.
- `THIRD_PARTY_NOTICES.md` for dependency notice tracking.
- `.env.example` files without secrets.
- No committed customer paths, usernames, tokens or lab-specific secrets.
- Clear docs separating lab deployment from product deployment.

## v0.3.0 Deliverables

For v0.3.0, licensing work is limited to:

- Initial proprietary license notice.
- Third-party notice tracking.
- Product roadmap alignment.
- Documentation of future license enforcement requirements.

No runtime license enforcement is expected in v0.3.0.

## v0.8.0 Deliverables

For v0.8.0, licensing work is limited to:

- Edition and capability inventory in code.
- Offline license file path configuration.
- Preflight reporting for license and feature gate state.
- Strict preflight error when feature gates are marked enforced but no license
  file path is configured.
- Documentation of known capability identifiers.

v0.8.0 does not parse signed license files and does not block source runtimes by
capability yet.
