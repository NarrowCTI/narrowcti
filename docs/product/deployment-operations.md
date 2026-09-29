# Deployment Operations

This is the current public deployment entry point for NarrowCTI Community
Edition.

The v0.8 detailed deployment snapshot is `docs/product/deployment-operations-v0.8.md`.
Versioned deployment files remain available as release history; operators
should link to this unversioned document for the current deployment path.

## Current Deployment Model

The v1.0 deployment model keeps the same conservative, audit-first flow:

```text
safe template
  -> preflight
  -> dry-run and run-once
  -> evidence review
  -> bounded continuous operation
  -> controlled graph export only after validation
```

Use:

```text
deployment/docker-compose.narrowcti-gateway.yml
deployment/gateway.env.example
```

The public template uses the normal Compose default network and does not
require an external OpenCTI network. Configure `OPENCTI_URL` and `MISP_URL`
with routed or remote endpoints as needed. When OpenCTI/MISP containers share
an externally managed network, apply the optional override:

```powershell
$env:NARROWCTI_DOCKER_NETWORK = "threat-net"
```

```powershell
docker compose `
  -f deployment\docker-compose.narrowcti-gateway.yml `
  -f deployment\docker-compose.narrowcti-shared-network.yml config
```

The override retains both the default egress network and the selected external
integration network, so mixed topologies remain supported. Use the network name
returned by the target OpenCTI Compose project when selecting shared mode.

The Compose template builds `Dockerfile.gateway` and stores runtime evidence in
a Docker volume. The image runs as UID/GID `10001:10001`; new volumes inherit
the prepared ownership. Existing root-owned volumes require an explicit,
backed-up ownership migration before starting the new image.

## Community runtime roles

The same image exposes explicit role entry points. Run exactly one Worker for a
state volume; its SQLite lease prevents a second Worker from processing the same
runtime at the same time. The Web role serves the browser UI and bearer API in
one endpoint-driven process; the Ops role is reserved for bounded one-shot
commands:

```text
Worker: python -m narrowcti.cli.worker
Web:    python -m narrowcti.cli.web
Ops:    python -m gateway.preflight (or another documented one-shot command)
```

Set `NARROWCTI_RUNTIME_DB` to a path on the shared `narrowcti-state` volume (the
default is `/app/state/runtime.db`). It contains only job, lease and
cross-process mutation-coordination metadata. Existing JSON/JSONL checkpoints,
quarantine records, artifact indexes and audit evidence remain authoritative and
retain their historical formats. The `web` profile starts the shared UI/API
process. There is no separate Review API service or second HTTP process.

The bounded Community Web Preflight and Operational Validation views consume a
safe snapshot published by the Gateway/Ops preflight command. Run the one-shot
preflight after Gateway configuration changes; Web does not load Gateway
configuration or recompute MITRE/preflight/decision validation. The snapshot is
stored beside `runtime.db` on the shared state volume, contains only allowlisted
status fields, and expires from the Web read view after 15 minutes. If no fresh
snapshot is available, the pages report the state as unavailable. Gateway
credentials and environment files are not mounted into the Web container.

The browser identity is separate from Review API bearer credentials. Its
versioned local SQLite database defaults to `NARROWCTI_AUTH_DB=/app/auth/auth.db`
and is persisted in the dedicated `narrowcti-auth` volume. The Worker does not
mount or require this volume. `NARROWCTI_RUNTIME_DB` remains separate and
contains runtime coordination only.

For local validation, the default image is `narrowcti/gateway:local`. The latest
published stable release is v1.0. For release deployments, use a pinned
published image such as:

```text
NARROWCTI_GATEWAY_IMAGE=ghcr.io/narrowcti/narrowcti-gateway:1.0.0
```

Do not use `latest` for production-like environments unless you intentionally
want the newest stable `main` image. The image tagging policy is documented in
`container-images.md`.

## First Run

```powershell
Copy-Item deployment\gateway.env.example deployment\gateway.env
$env:NARROWCTI_GATEWAY_ENV_FILE = "./gateway.env"

docker compose -f deployment\docker-compose.narrowcti-gateway.yml build narrowcti-gateway
docker compose -f deployment\docker-compose.narrowcti-gateway.yml --profile ops run --rm narrowcti-preflight
docker compose -f deployment\docker-compose.narrowcti-gateway.yml run --rm narrowcti-gateway
```

Keep the first run dry-run, run-once and audit-first. Review reports before any
continuous execution or graph export.

For the Community browser UI, provision the first local administrator through
the one-shot Ops helper. It uses the same image and auth volume as Web:

```powershell
docker compose -f deployment\docker-compose.narrowcti-gateway.yml --profile web --profile ops up -d --build narrowcti-web
docker compose -f deployment\docker-compose.narrowcti-gateway.yml --profile ops run --rm --no-deps narrowcti-operator-auth create-operator --username fagner --role admin
```

The CLI prompts for a password and confirmation without terminal echo. The
first account must be an admin; there is no default account or password. For
automation, use `--password-stdin` and pipe one line from a protected secret
source—never put the password in a command-line argument. Then open
`http://127.0.0.1:8081` and sign in with the local username and password. API
bearer tokens remain exclusively for API clients and do not work as browser
credentials. The one-shot helper also supports `list-operators`,
`set-password`, `set-roles`, `enable` and `disable`; the last enabled admin
cannot be disabled or demoted.

## Community Web UI, Source Explorer and Review API

The `web` Compose profile starts the server-rendered Community UI, Source
Explorer and existing bearer Review API together in `narrowcti-web`. Browser
HTML routes use in-memory server-side sessions; `/api/v1/review/*` remains
bearer-only and preserves its existing contract. See
[`web-source-explorer.md`](web-source-explorer.md) for credentials, permissions,
provider overlays, evaluation jobs and browser security.

Create a hashed credential file before starting it. The versioned example is
deliberately unusable.

```powershell
python -m gateway.review_auth
Copy-Item deployment\web.env.example deployment\web.env
Copy-Item deployment\review-api-credentials.example.json deployment\review-api-credentials.json
```

Replace the example principal, roles and token hash. The credentials source is
a Compose host interpolation, so set it in the shell and start the service:

```powershell
$env:NARROWCTI_REVIEW_API_CREDENTIALS_SOURCE = "./review-api-credentials.json"
$env:NARROWCTI_WEB_ENV_FILE = "./web.env"
$env:NARROWCTI_WEB_PUBLISHED_PORT = "8081"
docker compose -f deployment\docker-compose.narrowcti-gateway.yml --profile web up -d --build narrowcti-web
```

Keep real export disabled until preview and deduplication checks pass. The Web
service and API share credential hashes but not an authentication mechanism:
browser pages require a session plus CSRF, while API routes require a bearer
header.

The Web shell includes Overview, Sources / Explorer, Review / Quarantine,
Evidence / Decisions and Reports. The evidence view is a bounded, redacted
projection of configured local decision JSONL; report inventory does not write
files or schedule jobs. Failed login attempts and each ingestion operation
have separate process-local rate limits. Provider calls reject immediately
with a stable busy result rather than growing an unbounded wait queue.

## State Backup And Restore

NarrowCTI stores source checkpoints, deduplication indexes, quarantine records,
decision audit and generated reports in the `narrowcti-state` Docker volume.
Stop the gateway before taking a backup so no state file is being updated:

```powershell
docker compose -f deployment\docker-compose.narrowcti-gateway.yml stop narrowcti-gateway
docker run --rm -v narrowcti-state:/state -v "${PWD}:/backup" alpine sh -c "tar czf /backup/narrowcti-state-backup.tgz -C /state ."
```

Verify that the archive exists and store it with the deployment version. To
restore, stop the gateway, keep a copy of the current volume, and extract the
approved archive into the same volume:

```powershell
docker compose -f deployment\docker-compose.narrowcti-gateway.yml stop narrowcti-gateway
docker run --rm -v narrowcti-state:/state -v "${PWD}:/backup" alpine sh -c "tar xzf /backup/narrowcti-state-backup.tgz -C /state"
docker compose -f deployment\docker-compose.narrowcti-gateway.yml up -d narrowcti-gateway
```

The state repositories use atomic replacement for JSON checkpoints and indexes.
An interrupted write therefore leaves the previous complete file in place;
restore still requires an operator-approved backup when the volume itself is
lost or intentionally rolled back.

## Upgrade And Restart Recovery

For the v0.9 to v1.0 upgrade, back up `narrowcti-state`, review the new
configuration reference, build or pull the pinned image, run preflight, and
perform one bounded dry-run before enabling continuous operation. Do not delete
the state volume during an upgrade. Restarting after an interrupted run is
safe: completed source items remain checkpointed, deduplication indexes remain
available, and replay is governed by the existing source and artifact keys.

If a run fails, inspect the gateway summary, decision audit and preflight output
before retrying. Keep the source bounded until the failure cause and resource
posture are understood.

## Current Operational References

## Supported deployment topology matrix

The gateway and its dependencies may be colocated or routed independently.
Interoperability means a reachable URL with working DNS/routing, TLS,
authentication/authorization and a supported API/protocol; the same host,
network or platform is not required.

| Topology | OpenCTI | MISP | Supported posture |
| --- | --- | --- | --- |
| A | remote/routed | remote/routed | both services reached through configured endpoints |
| B | shared Docker network | shared Docker network | services share a controlled Docker network |
| C | separate Compose stack | separate Compose stack | optional shared integration network |
| D | shared | remote/routed | local OpenCTI with routed MISP |
| E | remote/routed | shared | routed OpenCTI with local MISP |
| F | VM/bare metal endpoint | VM/bare metal endpoint | endpoints exposed by the host network |
| G | Kubernetes endpoint | Kubernetes endpoint | service DNS and TLS route to both APIs |
| H | reverse proxy/load balancer | reverse proxy/load balancer | proxy terminates or routes TLS and auth policy |

NarrowCTI does **not** require direct access to OpenCTI Elasticsearch,
RabbitMQ, Redis or PostgreSQL, nor to MISP databases or Redis. Only the
supported OpenCTI and MISP APIs/protocols are part of the deployment contract.

- `docs/product/environment-profiles.md`: safe profiles for lab, validation, continuous
  operation and controlled graph export.
- `docs/product/configuration-reference.md`: configuration variable reference.
- `docs/product/product-reference.md`: current product, version and decision contract.
- `docs/product/opencti-coverage-matrix.md`: current graph coverage and evidence boundary.
- `docs/product/analyst-review-api.md`: authenticated review API operations and security.
- `docs/product/curation-decision-reference.md`: decision behavior reference.
- `docs/product/support-diagnostics-v0.8.md`: support bundle and redaction behavior.
