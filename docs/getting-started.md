# Getting Started

This guide is the shortest safe path to evaluate NarrowCTI Community Edition.

Use the full deployment runbook in `docs/deployment-operations.md` for
production-like upgrades, controlled graph export and operational handoff.

## Prerequisites

- Docker with Compose v2.
- Access to an OpenCTI instance.
- OpenCTI API token for connector import.
- At least one source credential, such as OTX or MISP.
- A Docker network that can reach OpenCTI. The deployment template defaults to
  `opencti_default`.

## Clone and Review

```powershell
git clone <repository-url> NarrowCTI
cd NarrowCTI
```

Review the public entry points:

```text
README.md
docs/README.md
docs/deployment-operations.md
docs/configuration-reference.md
```

## Create Local Configuration

Copy the deployment environment template and keep the real file untracked:

```powershell
Copy-Item deployment\gateway.env.example deployment\gateway.env
$env:NARROWCTI_GATEWAY_ENV_FILE = "./gateway.env"
```

Set at least:

```text
OPENCTI_URL
OPENCTI_TOKEN
OTX_API_KEY
MISP_URL
MISP_KEY
NARROWCTI_ENABLED_SOURCES
```

Keep the first run safe:

```text
NARROWCTI_DRY_RUN=true
NARROWCTI_RUN_ONCE=true
NARROWCTI_GRAPH_EXPORT_MODE=audit
OTX_DRY_RUN=true
MISP_DRY_RUN=true
MISP_MAX_EVENTS_PER_RUN=1
MISP_MAX_ATTRIBUTES_PER_EVENT=1000
MISP_MAX_IOCS_PER_EVENT=1000
```

Do not commit `deployment/gateway.env` or any other file containing secrets.
Keep `NARROWCTI_GATEWAY_ENV_FILE` set in the shell session when running Compose
commands, or define it in your local environment.

## Build the Gateway Image

```powershell
docker compose -f deployment\docker-compose.narrowcti-gateway.yml build narrowcti-gateway
```

## Run Preflight

Preflight checks runtime posture without calling source APIs or mutating
OpenCTI:

```powershell
docker compose -f deployment\docker-compose.narrowcti-gateway.yml --profile ops run --rm narrowcti-preflight
```

Treat errors as blockers. Warnings usually mean an optional capability, cache or
evidence file is not configured yet.

## First Controlled Run

Run once in dry-run mode:

```powershell
docker compose -f deployment\docker-compose.narrowcti-gateway.yml run --rm narrowcti-gateway
```

Then review operator evidence:

```powershell
docker compose -f deployment\docker-compose.narrowcti-gateway.yml --profile ops run --rm narrowcti-gateway-report
docker compose -f deployment\docker-compose.narrowcti-gateway.yml --profile ops run --rm narrowcti-decision-report
docker compose -f deployment\docker-compose.narrowcti-gateway.yml --profile ops run --rm narrowcti-curation-report
```

The reports are written under the `narrowcti-state` Docker volume.

## Controlled Graph Export

Do not start with broad graph export. The safe sequence is:

1. Keep `NARROWCTI_GRAPH_EXPORT_MODE=audit`.
2. Review graph candidates, held reasons and source evidence.
3. Enable `NARROWCTI_OPENCTI_GRAPH_LOOKUP=true` after OpenCTI is reachable.
4. Use bounded sources or direct replay, such as `MISP_QUERIES=event:<id>`.
5. Move to `NARROWCTI_GRAPH_EXPORT_MODE=export` only for a controlled test.
6. Run operational validation and relationship audit before expanding scope.

The current graph promotion design is in `docs/graph-promotion-v0.8.md`.

## State And Recovery

The gateway keeps checkpoints, deduplication indexes, quarantine records and
reports in the `narrowcti-state` volume. Do not remove that volume when
restarting or upgrading. Use the backup and restore procedure in
`docs/deployment-operations.md` before changing the image or widening source
scope.

State JSON files are written atomically. A process interruption during a
checkpoint update leaves the last complete state available for restart-safe
replay.

## Next Reading

- `docs/deployment-operations.md`
- `docs/configuration-reference.md`
- `docs/curation-decision-reference.md`
- `docs/environment-profiles.md`
- `docs/opencti-coverage-matrix-v0.8.md`
- `docs/infrastructure-correlation-v0.8.md`
- `docs/support-diagnostics-v0.8.md`
