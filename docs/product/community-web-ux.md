# Community Web experience and information architecture

This document describes the current Community Web navigation and the safe data
contracts used by its server-rendered pages. It is subordinate to the
[architecture overview](../architecture/overview.md), the accepted ADRs and
the Community Web product specification.

## Navigation

The authenticated Community workspace groups pages into:

- **Overview** — current bounded source, review and decision summaries.
- **Intelligence** — Sources, Explorer and Decisions.
- **Review** — Quarantine, using the established `/review` route.
- **Evidence** — Decision Audit, Operational Evidence and current-state
  Operational Validation.
- **Reports** — the existing one-shot Ops report inventory.
- **System** — current Health/Preflight, Providers and Community Capabilities.
- **My Account** — the signed-in operator's account and password controls.

Navigation may hide links according to current Community capability and
operator permissions, but it is not an authorization boundary. Every route and
action enforces authorization server-side. The shell is server-rendered and
works without JavaScript; the responsive sidebar uses native browser controls
and local CSS.

## Evidence and status semantics

Decisions and Decision Audit reuse the bounded `WebEvidenceService` projection
and do not parse DecisionRecord files independently. Operational Evidence,
Health/Preflight and Operational Validation expose allowlisted current-state
projections only. The Web never renders `PreflightReport.to_dict()` or
`OperationalValidationReport.to_dict()` directly; paths, settings, free-text
diagnostics and report evidence payloads are withheld.

Operational Validation uses the existing `OperationalValidationReport`
contract and the same configured `NARROWCTI_OPERATIONAL_VALIDATION_SOURCES`
value as the Gateway/Ops validator. The Gateway/Ops preflight workflow
publishes a separate bounded Preflight snapshot. The
`python -m gateway.operational_validation` workflow publishes a separate
bounded Operational Validation snapshot after consuming the supported manual
and relationship evidence inputs and bounded DecisionRecord evidence. Web
reads both snapshots from the shared runtime-state volume; it does not load
Gateway settings, recompute preflight/MITRE/decision validation, or run a CLI or
subprocess. Each snapshot includes its capture time; snapshots older than 15
minutes are shown as stale with operator refresh guidance, never as current
Gateway state. Missing/invalid snapshots are shown as unavailable. “Needs
evidence” is shown as such and is not represented as a failed release gate.

`ProviderDescriptor.available` means configured/available to the Explorer; it
does not mean the upstream provider was contacted or is healthy. “Healthy” or
“Reachable” is reserved for a real bounded probe. Worker health is not inferred
from missing errors, jobs or container state.

The authenticated Providers page offers an explicit, bounded live readiness
check. It reports the fixed provider-readiness taxonomy with a capture time and
safe operator guidance; it is not run on ordinary page GETs and does not alter
`/healthz`. The Ops `narrowcti-provider-readiness` command uses the same
application contract. See
[`community-deployment-readiness.md`](community-deployment-readiness.md) for
the Compose and local-lab contract.

Reports is a product-facing inventory of Community operational reports.
Community Web does not generate report files, expose internal module command
names, accept output paths or schedule reports.
Overview and empty states never invent activity, metrics or history. Job pages
show only the existing authorized job contract; they are not a historical
operations dashboard.

MISP Explorer detail is a bounded event/attribute projection and does not
issue an authoritative source fingerprint. Preview establishes that revision
in the Worker from the same single full-document fetch it evaluates; later
Dry-run/Run-once actions must present that Worker-issued revision and fail
closed if the source changed. See the
[`Community MISP Explorer search contract`](community-misp-explorer-search.md)
for provider routes, response bounds and minimum MISP version.

## Route compatibility

The existing `/`, `/explorer`, `/review`, `/evidence`, `/reports`, `/account`,
`/login`, `/logout`, `/healthz` and `/api/v1/review/*` contracts remain. The
additive page routes are `/sources`, `/decisions`, `/evidence/operational`,
`/evidence/validation`, `/system/health`, `/system/providers` and
`/system/capabilities`. Sidebar “Quarantine” points to `/review`; no
`/quarantine` route is defined.

## Security and editions

Local operator sessions, Argon2id password storage, the separate auth
database, `auth_revision`, CSRF, CSP, TrustedHost, bounded requests, rate
limits, provider credential separation and bearer API isolation remain
unchanged. HTML errors use autoescaped templates while retaining the original
status and headers.

This information architecture presents only Community capabilities. It does
not add a Scheduler, saved/recurring searches, pause/resume, backfill, replay,
historical operational dashboards, visual policy management, scheduled
reporting, SSO/OIDC/SAML, advanced RBAC, HA, multi-environment, tenancy or MSSP
functions.
