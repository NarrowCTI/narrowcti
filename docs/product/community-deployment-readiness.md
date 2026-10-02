# Community Deployment Bootstrap & Provider Readiness

This is the current Community deployment-readiness companion to the
[architecture overview](../architecture/overview.md),
[deployment operations](deployment-operations.md), and accepted
[MIG-ADR-026](../architecture/adr/MIG-ADR-026.md). It defines the PR-26 local
lab path; versioned deployment documents remain historical context.

## Keep the runtime roles separate

- **Web** serves UI/API and bounded read-only MISP/OTX Source Explorer access
  with dedicated Web credentials. Explorer calls are transient and never start
  a Worker, container, consumer or ingestion cycle.
- Bounded MISP Explorer detail requires MISP `>= 2.5.35`; the Web detail path
  uses bounded event-shell and attribute endpoints and does not fall back to a
  full event response.
- **Worker** continuously polls the configured sources independently of the
  browser. Preview, dry-run and run-once requests are bounded jobs claimed by an
  already-running Worker using its own Gateway credentials.
- **Ops** owns one-shot static preflight, provider-readiness diagnostics,
  operational validation, reports and authoritative snapshot publication.

Web liveness is not Worker, MISP, OTX, OpenCTI or snapshot readiness. Static
preflight is network-free. Live provider readiness is an explicit bounded
check. Operational snapshots are captured evidence; Web only reads them. An
absent snapshot remains unavailable and an old snapshot remains stale.

## Compose layers for a shared integration network

From the repository root, select the base role file plus the optional shared
network file and only the provider secret overlays that will be used. The
following PowerShell example describes a separate NarrowCTI stack and
pre-existing MISP/OpenCTI stacks on an already-created external network:

```powershell
Push-Location deployment
$env:NARROWCTI_GATEWAY_ENV_FILE = "./gateway.env"
$env:NARROWCTI_WEB_ENV_FILE = "./web.env"
$env:NARROWCTI_REVIEW_API_CREDENTIALS_SOURCE = "./review-api-credentials.json"
$env:NARROWCTI_DOCKER_NETWORK = "threat-net"
$env:NARROWCTI_WEB_MISP_KEY_SOURCE = "../.local-secrets/web-misp-readonly-key.txt"
$env:NARROWCTI_WEB_OTX_KEY_SOURCE = "../.local-secrets/web-otx-explorer-key.txt"

$compose = @(
  "-f", "docker-compose.narrowcti-gateway.yml",
  "-f", "docker-compose.narrowcti-shared-network.yml",
  "-f", "docker-compose.narrowcti-web-misp.yml",
  "-f", "docker-compose.narrowcti-web-otx.yml"
)

docker compose @compose --profile web --profile ops config
docker compose @compose --profile web up -d --build narrowcti-gateway narrowcti-web
```

Omit either provider overlay and its source-path variable if that Web Explorer
provider is not being enabled. The MISP and OTX overlays mount only their
dedicated key files, read-only, into Web and the explicit Ops readiness command.
They do not mount `gateway.env` into Web. Keep `.env`, `*.env`, credentials,
private keys and secret files outside commits and Docker build context.

The external network must already exist, and the MISP/OpenCTI Compose owners
must declare membership in it themselves. NarrowCTI retains its default network
as well as the optional external network for routed/mixed topologies. The
NarrowCTI Compose project never recreates third-party volumes/databases and
never uses imperative `docker network connect` as persistent bootstrap.

When running the commands from PowerShell, return to the repository root after
validation:

```powershell
Pop-Location
```

## One-shot operations and snapshots

With the same selected Compose layers, run the offline Gateway preflight:

```powershell
docker compose @compose --profile ops run --rm narrowcti-preflight
```

It validates configured structure/state and publishes the safe Preflight
snapshot. It makes no provider network request.

Run bounded live Explorer-provider checks separately:

```powershell
docker compose @compose --profile ops run --rm narrowcti-provider-readiness
```

This reports only provider key, one of the documented readiness states,
capture time and fixed safe operator guidance. Exit zero means the diagnostic
completed and reported the outcomes; it does not mean every optional provider
is ready. The same check is available as an explicit, CSRF-protected and
rate-limited action on the authenticated Providers page. `/healthz` does not
invoke any of these probes.

Refresh Operational Validation only when its real supported inputs exist on
the shared state volume. Configure the normal Gateway paths in `gateway.env`
and place the manual evidence and relationship-audit files at the configured
paths, then run:

```powershell
docker compose @compose --profile ops run --rm narrowcti-operational-validation
```

The authoritative workflow consumes those files and bounded DecisionRecord
evidence, creates the report and publishes its separate safe snapshot. Do not
create placeholder evidence to populate the Web page. Web never loads
`gateway.env`, executes a CLI/subprocess, recomputes MITRE/validation, or writes
these snapshots. Captured time and stale/unavailable status remain explicit.

## Proxy, TLS and CSRF

TLS trust and browser Origin validation are different controls. Behind a local
Caddy/TLS-terminating proxy, configure the exact public origin in `web.env`,
for example `NARROWCTI_WEB_PUBLIC_ORIGIN=https://<exact-public-origin>`. Keep
Origin validation, `Sec-Fetch-Site` checks and session-bound CSRF validation
enabled. `Origin: null` is not globally trusted. Local certificates, private
keys and host-specific proxy configuration remain local-only.

## Run-once and continuous Worker behavior

- `python -m narrowcti.cli.worker` with run-once enabled exits 0 only when all
  enabled source executions succeed, 2 when the bounded cycle reports a source
  failure, and 75 if the Worker lease is unavailable.
- Continuous Worker operation records transient source failures and continues
  polling; the one-cycle process status does not terminate it.

The structured Gateway summary remains the source-level evidence. Web requests
only enqueue jobs and cannot start or stop the Worker.
