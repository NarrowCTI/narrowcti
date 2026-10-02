# MIG-ADR-020 — Shared Web Architecture, Community Basic UI, Source Explorer & Web Security

- Status: accepted for W8 / PR-24
- Date: 2026-09-27
- Scope: Community Basic Web UI, Source Explorer and secure Web foundation
- Dependencies:
  - current Review API, runtime-role, capability and Web security characterization
  - MIG-ADR-003
  - MIG-ADR-011
  - MIG-ADR-012
  - MIG-ADR-016
  - MIG-ADR-018
  - MIG-ADR-019
  - MIG-ADR-022
  - MIG-ADR-023
  - MIG-ADR-024
  - MIG-ADR-025
- Related ADRs: MIG-ADR-002, MIG-ADR-004, MIG-ADR-014, MIG-ADR-015

## Context

The Community distribution already has a Web/API runtime, a Worker, one-shot
Ops roles, a Review API, capability contracts, a local job repository and
approved NarrowCTI brand assets. It does not yet provide the shared browser UI
or provider-aware Source Explorer described by the v0.7 Blueprint. Browser
features must reuse application behavior without creating a second ingestion
runtime, exposing provider credentials, weakening API compatibility or
introducing commercial control-plane scope.

## Decision

### Shared Web architecture and product boundary

- Keep one canonical Web/API process, `python -m narrowcti.cli.web`, in the
  same package, wheel and image as Worker and Ops.
- Use FastAPI/Starlette, server-rendered Jinja2 and locally vendored HTMX only
  as progressive enhancement. No Node.js/npm runtime, frontend build pipeline,
  mandatory CDN, second HTTP service or browser-to-provider connection is
  introduced.
- Community includes Basic UI, transient Source Explorer search/detail,
  preview, bounded dry-run, bounded manual run-once and basic quarantine/review.
- The server-rendered Community shell includes Overview, Sources / Explorer,
  Review / Quarantine, Evidence / Decisions and Reports. Navigation is derived
  from Community capabilities and principal permissions, has an explicit
  current-page marker, and keeps core content usable without JavaScript.
- Overview reports provider availability and review counts only from bounded
  current service projections; unavailable/error states remain explicit.
  Evidence reads at most 100 recent local decision records through a bounded
  application projection and exposes only allowlisted fields. Reports lists
  existing one-shot Ops report commands as available/not generated; Web does
  not generate report files or schedule them.
- Professional begins with operational lifecycle control around these
  capabilities: saved/recurring searches, scheduling, pause/resume, bounded
  backfill, governed replay, richer history, advanced dashboards, visual
  policy management and scheduled reporting.
- Preview and dry-run are Community capabilities; the Blueprint §10.1 table is
  not an exclusive entitlement statement. The authoritative boundary is
  Blueprint §§8.2, 8.4 and 21.1.

### Source Explorer and credentials

- Source Explorer uses an application service and a narrow
  `SourceExplorerProvider` port. Each provider adapter owns only its own
  descriptor, search and detail behavior; an application registry aggregates
  configured providers. The ingestion `SourceRegistry` is not a query engine.
- Search and detail are synchronous, transient, bounded and read-only from the
  NarrowCTI product perspective. They do not create jobs, change `.env` or
  persistent source configuration, mutate ingestion state, advance
  checkpoints or export to OpenCTI. Filters remain provider-specific; no
  universal CTI query DSL or invented pagination is added.
- MISP and OTX Explorer credentials are a distinct class of server-side Web
  credentials. They are separately configured and never fall back to, copy or
  expose Worker ingestion credentials. Missing Explorer configuration marks
  that provider unavailable without failing Web startup. MISP should use a
  dedicated read-only integration identity. OTX uses a dedicated Explorer key
  where operationally possible; no unsupported provider-side ACL guarantee is
  claimed.
- Provider endpoints are administrator-configured and are the trust anchor.
  Browser input cannot choose URL, host, scheme, port, proxy or arbitrary path.
  Explorer adapters disable redirects and ambient proxy behavior, verify TLS
  by default, enforce bounded time/response/result limits and return
  secret-free errors. Private provider endpoints remain supported.

### Preview, dry-run and run-once

- Preview is an in-memory simulation of the existing governed decision path.
  It does not persist a DecisionRecord, quarantine record, artifact mark,
  checkpoint, graph mark or job result containing raw intelligence. The
  coordination job metadata may exist in `runtime.db`. Preview reuses current
  policy/scoring/TLP behavior through no-op or non-persistent collaborators;
  it does not duplicate decision rules.
- Dry-run executes the existing governed dry-run path without downstream
  target mutation. Existing allowed local evidence semantics remain: a
  DecisionRecord and, where policy currently quarantines, a quarantine record
  may be written. It does not perform real OpenCTI export, mark a successful
  real artifact export or advance a successful ingestion checkpoint.
- Preview, dry-run and run-once are explicit bounded Worker job types:
  `ingestion.preview`, `ingestion.dry_run` and `ingestion.run_once`. Search and
  detail do not use jobs. Job payloads contain bounded identity/intent only,
  never raw provider documents, provider credentials or arbitrary commands.
- Duplicate HTTP delivery of the same request returns the same job. At most
  one active `ingestion.run_once` job exists globally in Community. Preview
  and dry-run submissions are rate-limited and bounded; no scheduler, general
  job-control plane, cancellation, rich history or job pruning feature is
  introduced.
- An initial run-once claim (`attempt == 1`) may execute. A reclaimed stale
  claim (`attempt > 1`) fails closed with stable error code
  `execution_ambiguous`; the Worker never automatically repeats provider or
  downstream effects. Preview/dry-run use similarly conservative recovery.
  Automatic retry is prohibited for ingestion jobs; a new explicit operator
  request gets a new request id. Existing quarantine-export reconciliation is
  unchanged.
- Persist only bounded job identity, requester, timestamps, attempt, status,
  summary counts and bounded error/result projections. No complete event/pulse
  document is stored in `runtime.db`. Existing runtime DB schema v1 is
  preserved unless a separately demonstrated structural need makes migration
  unavoidable.

### Browser identity and security

- Existing Review API bearer authentication, routes, permissions, payloads
  and status behavior remain unchanged. API endpoints remain bearer-only and
  do not accept browser session cookies.
- Community browser identity uses deployment-provisioned local operator
  accounts. The login form accepts username and password and verifies the
  password with Argon2id through `LocalOperatorStore`; it never accepts a
  Review API bearer token as a human login credential.
- Review API bearer authentication remains an independent, backward-compatible
  API/automation channel using `ReviewCredentialStore`. Browser sessions do not
  authenticate `/api/v1/review/*`, and bearer tokens do not establish Web
  sessions.
- Operator identity is stored in a dedicated versioned SQLite auth database
  (`NARROWCTI_AUTH_DB`, Compose default `/app/auth/auth.db`) on a named
  `narrowcti-auth` volume. It is separate from `NARROWCTI_RUNTIME_DB`, which
  remains job, lease and process-coordination state. Worker has no auth-volume
  mount. A one-shot Ops helper provisions accounts through
  `python -m narrowcti.cli.auth`.
- The first operator must be an admin; the store refuses to disable or demote
  the last enabled admin. There are no default credentials or self-registration.
  Account administration is deployment-managed through CLI commands; the
  browser exposes only the signed-in operator's My Account and own-password
  change surface. Community does not add SSO/OIDC/SAML, MFA or graphical IAM.
- Passwords use the directly declared `argon2-cffi` dependency with Argon2id
  parameters `m=19456 KiB`, `t=2`, `p=1`, 32-byte output and 16-byte salt,
  selected from current OWASP password-storage guidance and maintained
  `argon2-cffi` parameter guidance. PHC hashes support rehash-on-success when
  parameters change; transparent parameter-only rehash does not increment
  `auth_revision`.
- Successful local authentication creates a separate opaque in-memory
  server-side session. Passwords and hashes never enter sessions, cookies,
  HTML, URLs, logs or browser storage. Password, role or enabled-state changes
  increment `auth_revision`; authenticated requests load the current operator,
  reject stale/disabled identities and derive current roles.
- Login uses the same public error for unknown, wrong-password and disabled
  accounts, dummy Argon2 verification for unknown/malformed hashes, bounded
  password input, process-local throttling and bounded concurrent KDF work.
  Failed attempts reuse the anonymous CSRF session; successful authentication
  rotates it.
- Sessions use cryptographically random identifiers, bounded in-memory
  storage, absolute and idle expiry, session rotation after login, logout
  deletion, operator auth-revision validation and session-bound CSRF material.
  Web restart invalidates all sessions. No session SQLite database or
  `runtime.db` session data is introduced.
- Production cookie defaults are `HttpOnly`, `Secure`, `SameSite=Lax`,
  `Path=/`, no `Domain` and bounded `Max-Age`. Secure-cookie disablement is an
  explicit local-HTTP development override only. Production uses the
  `__Host-narrowcti_session` name; insecure local development uses a
  non-`__Host-` name.
- Every unsafe browser request, including login, HTMX and review/export
  actions, requires session-bound CSRF validation, constant-time token
  comparison, same-origin `Origin` validation when supplied and Fetch Metadata
  checks as defense in depth. Capability and permission enforcement is
  repeated server-side; hidden UI controls are not authorization.
- Strict same-origin CSP and security headers cover HTML, fragments, API
  responses, errors and redirects. No `unsafe-eval`, mandatory remote assets
  or inline event handlers are permitted. Jinja autoescape remains enabled;
  source CTI is untrusted and is never rendered with `|safe`.
- Web requests receive actual streaming body-size enforcement, including
  requests without `Content-Length`. Provider requests enforce configured
  endpoint-only SSRF protections, TLS, redirect/proxy controls, timeouts,
  response bytes, result counts, query/filter lengths and per-session rates.
- Login attempts and preview, dry-run and run-once submissions use separate
  bounded process-local rate limits. Client identity is taken from the direct
  ASGI peer only; arbitrary forwarded headers do not influence login limits.
  Provider concurrency is one active call per provider with immediate
  `provider_busy` response and no unbounded waiter queue.
- The shared Web `/healthz` keeps the established Review API JSON payload and
  outer security headers. When Review API docs are enabled, `/openapi.json` and
  `/docs` remain mounted at their existing paths. Web settings accept legacy
  Review API host/body-size variables as fallbacks, with Web-specific names
  taking precedence.

### Capabilities, brand assets and supply chain

- The existing future Community capabilities become implemented/entitled
  only when their feature is present: `ui.basic`, `source.explorer` and
  `ingestion.run_once`. Preview uses `source.explorer`; dry-run uses its
  explicit permission and existing Community UI capability. No edition
  conditionals or new preview/search capability aliases are introduced.
- Canonical identity remains `docs/product/brand-guidelines.md` and
  `docs/assets/brand/`. Expanded header uses the approved horizontal logo;
  browser identity uses the canonical favicon. No asset is redrawn, recolored
  or independently edited.
- Brand assets are deterministically projected at build time into the
  installed Web package, with canonical source bytes included in source
  distributions and SHA-256 equality validated. Runtime does not generate
  assets or require `docs/` in the image. Jinja2 is a direct declared
  dependency. HTMX is locally vendored, version/hash/license recorded and
  configured to disable unused dynamic script/eval behavior.

### Runtime, validation and rollback

- Community continues to support one active Worker. Search/detail are direct
  bounded Web calls; evaluation and real ingestion are Worker-owned. No broker,
  Postgres, multi-worker support or paid operational lifecycle is added.
- Preserve the current Review API and quarantine/review/export service
  behavior through direct service/router composition; Web never calls its own
  HTTP API.
- Required validation includes full tests, boundary tests, Ruff, Bandit,
  pip-audit, compile validation, wheel/installed-resource validation,
  container role smoke, SBOM/image scan, existing API DAST and new
  authenticated UI DAST. DAST uses synthetic credentials and fake providers.
- Rollback is additive: disable/unmount the UI and new capabilities or revert
  PR-24; existing API bearer routes, Worker ingestion, JSON/JSONL business
  state and quarantine export remain usable. No migration of source business
  state is performed.

## Alternatives considered

- A separate frontend framework and Node build: rejected for Community because
  it adds a second runtime/build supply chain without a requirement.
- Browser-to-provider requests: rejected because they expose credentials and
  provider topology.
- Reusing Worker ingestion credentials for Explorer: rejected because
  read-only query and ingestion authority are distinct.
- Sending interactive search through the Worker job queue: rejected because
  search/detail are transient synchronous operations and are not ingestion.
- Direct Web execution for preview, dry-run or real run-once: rejected because
  it bypasses the Worker mutation owner and makes decision/evidence behavior
  inconsistent.
- Signed-cookie-only session state, a SQLite session DB or storing sessions
  in runtime.db: rejected for the one-process Community Web baseline.
- Generic command registry, Scheduler, cancellation, arbitrary query jobs or
  broad job history: deferred to later operational-control work.

## Consequences

- Community gains an integrated Basic UI and Source Explorer while preserving
  a single modular monolith and runtime package.
- The Web process receives distinct optional Explorer credentials and a
  bounded in-memory session store; restart invalidates browser sessions.
- Failed logins reuse the existing anonymous session instead of allocating a
  new one, and are rate-limited with a generic error response. The temporary
  session's CSRF state remains server-side; submitted tokens are not persisted
  or re-emitted.
- Preview, dry-run and run-once have distinct evidence and mutation semantics
  that must be visible in UI and operator documentation.
- Run-once jobs can become explicitly ambiguous after Worker reclaim; an
  operator must submit a new request rather than relying on automatic replay.
- The wheel and candidate image include governed UI assets and vendored HTMX,
  with additional package and authenticated DAST validation.
- Professional may add saved/recurring searches, schedules, run control,
  richer history and advanced operational dashboards in a later wave.

## Target Wave

W8 / PR-24 — Community Basic Web UI / Source Explorer.

## PR-27A addendum — bounded detail and Worker-issued revision

PR-27A refines the existing Explorer-to-Worker freshness contract without
changing the ownership boundary: Web detail is an upstream-bounded projection,
while the Worker remains authoritative for the full source revision used by
governed ingestion.

- MISP detail uses sequential `GET /events/view2/{id}.json` and
  `POST /events/viewAttributes/{id}.json` requests with `page=1` and
  `limit=101`, an aggregate deadline, at most two upstream requests and the
  existing 1,000,000-byte per-response cap. It never falls back to
  `/events/view`, performs no further pagination and renders at most 100
  bounded attributes. The response total determines truncation; malformed or
  inconsistent identity/count data fails closed.
- This bounded MISP detail does not issue a `revision_fingerprint`. OTX detail
  retains its existing full-document fingerprint behavior.
- Preview may be submitted without an expected fingerprint. The Worker fetches
  the full source document once, calculates `source_document_fingerprint()`
  from that document, normalizes/processes that same raw document through the
  existing source-specific path, and returns the authoritative fingerprint
  in the bounded Preview result. Preview remains free of durable candidate
  effects.
- Dry-run and Run-once still require the fingerprint issued by Preview. The
  Worker refetches the full document and compares its digest before
  normalization or processing; mismatch remains `candidate_changed` and fails
  closed. Each follow-up action has a fresh request ID.
- Bounded MISP Explorer detail requires MISP `>= 2.5.35`. A 404 is not by
  itself treated as proof of an unsupported server: bounded version discovery
  occurs only when needed to distinguish an unsupported detail endpoint from a
  missing event. There is no full-event detail fallback.

The addendum does not change MISP/OTX runtime processor behavior, the normal
Worker ingestion path, readiness semantics, or the separate follow-on PR-27B
and PR-28 scopes.
