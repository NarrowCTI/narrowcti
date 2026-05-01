# CTI Gateway Licensing Strategy

## Purpose

This document defines the initial licensing direction for CTI Gateway as it moves
toward commercial distribution.

It is not a final EULA and it is not legal advice. It is a product and
engineering baseline that should be reviewed by qualified legal counsel before
the product is sold, distributed or deployed for customers.

## Licensing Posture

CTI Gateway is being prepared as proprietary commercial software.

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

## Future Technical Enforcement

The recommended v0.7.0 licensing model is offline-first:

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
