# Deployment Operations - v0.8.0

## Purpose

This document defines the first repeatable deployment and upgrade path for the
NarrowCTI gateway runtime. It is intended for controlled lab, pilot and early
customer-style deployments where OpenCTI already exists and NarrowCTI is added
as a curation gateway.

This is the authoritative deployment and upgrade document for v0.8. README and
older release documents should point here instead of duplicating the current
procedure.

The deployment posture remains conservative:

```text
safe config template
  -> preflight
  -> dry-run/run-once
  -> evidence review
  -> bounded continuous operation
```

## Deployment Assets

The v0.8 deployment template lives in:

```text
deployment/docker-compose.narrowcti-gateway.yml
deployment/gateway.env.example
```

The compose template builds `Dockerfile.gateway`, joins an existing OpenCTI
Docker network and persists gateway evidence under `/app/state`. The env
template keeps `NARROWCTI_DRY_RUN=true`, `NARROWCTI_RUN_ONCE=true`,
`OTX_DRY_RUN=true` and `MISP_DRY_RUN=true` so first execution is observable and
bounded.

The compose template also provides an `ops` profile for read-only operational
commands:

| Service | Purpose |
| --- | --- |
| `narrowcti-preflight` | Runs `python -m gateway.preflight`. |
| `narrowcti-gateway-report` | Builds `/app/state/gateway-operational-report.txt` from gateway run and quarantine evidence. |
| `narrowcti-curation-report` | Writes `/app/state/curation-report.txt`, `/app/state/curation-report.json` and `/app/state/curation-report.html`, including relationship-audit graph validation when `/app/state/opencti-relationship-audit.json` exists. |
| `narrowcti-decision-report` | Builds `/app/state/decision-audit-report.txt` from `/app/state/audit`. |
| `narrowcti-correlation-report` | Builds `/app/state/artifact-correlation-report.txt` from the local artifact deduplication index. |
| `narrowcti-operational-validation` | Builds `/app/state/operational-validation.html` from preflight, decision audit and optional manual evidence. |
| `narrowcti-support-diagnostics` | Builds a support-redacted HTML snapshot and support bundle under `/app/state`. |
| `narrowcti-opencti-relationship-audit` | Runs a read-only OpenCTI relationship audit for one target object. |

These services reuse the same image, env file, state volume and OpenCTI network
as the gateway runtime. They do not start continuous ingestion by themselves.

## Installation Procedure

1. Confirm the target OpenCTI stack is running and identify its Docker network.
   For a default local compose stack this is often `opencti_default`.
2. Build the NarrowCTI gateway image from this repository.
3. Copy `deployment/gateway.env.example` to `deployment/gateway.env`, which is
   ignored by git.
4. Fill only the source credentials and URLs needed for the intended source
   set.
5. Keep dry-run and run-once enabled for the first validation run.
6. Run `gateway.preflight` through the `ops` profile.
7. Start one dry-run execution.
8. Review preflight output, gateway logs, decision audit, quarantine repository,
   graph export plan metadata, curation report and support diagnostics before
   enabling continuous operation.

Example controlled validation:

```powershell
cd <path-to-NarrowCTI>
docker compose -f deployment\docker-compose.narrowcti-gateway.yml config
$env:NARROWCTI_GATEWAY_ENV_FILE = "./gateway.env"
docker compose -f deployment\docker-compose.narrowcti-gateway.yml build narrowcti-gateway
docker compose -f deployment\docker-compose.narrowcti-gateway.yml --profile ops run --rm narrowcti-preflight
docker compose -f deployment\docker-compose.narrowcti-gateway.yml up --force-recreate narrowcti-gateway
docker compose -f deployment\docker-compose.narrowcti-gateway.yml logs --tail 120 narrowcti-gateway
docker compose -f deployment\docker-compose.narrowcti-gateway.yml --profile ops run --rm narrowcti-gateway-report
docker compose -f deployment\docker-compose.narrowcti-gateway.yml --profile ops run --rm narrowcti-decision-report
docker compose -f deployment\docker-compose.narrowcti-gateway.yml --profile ops run --rm narrowcti-correlation-report
$env:NARROWCTI_OPENCTI_AUDIT_TYPE = "infrastructure"
$env:NARROWCTI_OPENCTI_AUDIT_SEARCH = "MISP ip-port 137.184.181.252"
$env:NARROWCTI_OPENCTI_AUDIT_FIRST = "80"
docker compose -f deployment\docker-compose.narrowcti-gateway.yml --profile ops run --rm narrowcti-opencti-relationship-audit
docker compose -f deployment\docker-compose.narrowcti-gateway.yml --profile ops run --rm narrowcti-curation-report
docker compose -f deployment\docker-compose.narrowcti-gateway.yml --profile ops run --rm narrowcti-operational-validation
docker compose -f deployment\docker-compose.narrowcti-gateway.yml --profile ops run --rm narrowcti-support-diagnostics
```

The relationship audit service prints JSON to stdout and writes the same
evidence to `/app/state/opencti-relationship-audit.json` by default. Override
`NARROWCTI_OPENCTI_AUDIT_OUTPUT_FILE` when multiple object audits need to be
kept separately in the state volume.

The curation report service reads
`NARROWCTI_OPENCTI_RELATIONSHIP_AUDIT_FILE`, defaulting to
`/app/state/opencti-relationship-audit.json`. Run the relationship audit before
`narrowcti-curation-report` when the report needs to show post-ingestion
Diamond quadrant and Kill Chain coverage for the audited OpenCTI object.

When the validation goal is full Diamond/Kill Chain readiness for one object,
set explicit coverage expectations before running the audit:

```powershell
$env:NARROWCTI_OPENCTI_AUDIT_EXPECTED_QUADRANTS = "adversary,capability,infrastructure,victimology"
$env:NARROWCTI_OPENCTI_AUDIT_REQUIRE_KILL_CHAIN = "true"
docker compose -f deployment\docker-compose.narrowcti-gateway.yml --profile ops run --rm narrowcti-opencti-relationship-audit
```

The resulting JSON includes `coverage.present_quadrants`,
`coverage.missing_quadrants`, `coverage.kill_chain_present` and
`coverage.status`. Missing expected quadrants are treated as
`needs-evidence` by the operational validation checklist, not as successful
coverage.

If the OpenCTI network name is not `opencti_default`, set
`NARROWCTI_DOCKER_NETWORK` before running compose.

The compose template defaults to `deployment/gateway.env.example` so
`docker compose config` can validate the template before secrets exist. For real
execution, set `NARROWCTI_GATEWAY_ENV_FILE=./gateway.env` after creating the
local env file.

The operational validation service optionally reads
`/app/state/operational-validation-evidence.json`. Use that local state-volume
file to record manual checks such as `full_validation_passed`,
`opencti_ui_no_duplicate` and `resource_posture_ok` after the operator has
actually validated them. Missing evidence keeps those checks in
`needs-evidence` state. Support diagnostics reads the same file when configured
so the support bundle and the operational validation report do not diverge.

Resource posture evidence can be generated from the host with:

```powershell
.\scripts\capture-resource-posture.ps1 -OutputFile state\operational-validation-evidence.json
```

The script captures whether `docker stats --no-stream`, `docker system df` and
container status checks completed. It does not mark disk posture as healthy by
itself; after reviewing Docker disk usage, rerun with `-DiskPostureOk` to let
the operational validation checklist pass the resource posture check.

The operational validation service also reads
`/app/state/opencti-relationship-audit.json` by default. Run
`narrowcti-opencti-relationship-audit` before the validation service when the
goal is to prove that at least one promoted OpenCTI object has direct Diamond or
Kill Chain graph context.

The curation report service writes text, JSON and HTML artifacts from the same
evidence snapshot. Use the JSON file as the stable contract artifact for
comparison between validation runs, the text file for terminal review and the
HTML file for local analyst or support review.

## Safe Promotion To Continuous Operation

Only consider continuous operation after a bounded dry-run proves:

- Preflight has no errors.
- Source dry-run posture and per-source limits are visible.
- Decision audit records are being written.
- Quarantine repository and release audit paths are configured.
- Operational validation has no failing checks and expected missing-evidence
  items are understood before promotion decisions.
- Artifact deduplication is enabled with `NARROWCTI_DEDUP_MODE=hybrid`.
- Graph promotion remains `audit` or `dry-run`.
- OpenCTI and Elasticsearch capacity are acceptable.
- OpenCTI graph lookup is intentionally enabled or intentionally disabled.
- Open source distribution posture and capability inventory are visible in
  preflight.

Continuous operation requires explicit changes:

```env
NARROWCTI_RUN_ONCE=false
NARROWCTI_DRY_RUN=false
OTX_DRY_RUN=false
MISP_DRY_RUN=false
```

For constrained environments, enable one source at a time and keep MISP bounded
with date range, TLP tags and per-run volume limits.

Real graph export requires one additional, explicit promotion step after the
bounded validation evidence is clean:

```env
NARROWCTI_GRAPH_EXPORT_MODE=export
NARROWCTI_OPENCTI_GRAPH_LOOKUP=true
```

If `NARROWCTI_ALLOWED_GRAPH_ENTITY_TYPES` and
`NARROWCTI_ALLOWED_GRAPH_STIX_OBJECT_TYPES` are left empty in `export` mode,
NarrowCTI applies the safe export default. It promotes source-backed CTI graph
objects such as infrastructure, ASN, observables, sectors, locations, arsenal,
ATT&CK, vulnerabilities and reports, while holding collector/source identity,
labels and markings in audit/report metadata unless the operator explicitly
allow-lists those candidate types.

For bounded MISP validation, direct event replay can be used:

```env
MISP_QUERIES=event:<id>
```

This loads a known event by id/uuid and avoids broad MISP searches while
validating object mapping and OpenCTI import behavior.

## Upgrade Procedure

Before upgrading:

1. Record the current NarrowCTI image tag or commit.
2. Export or back up the gateway state volume.
3. Save current local env values without committing secrets.
4. Run preflight on the current version and keep the output with the change
   record.

During upgrade:

1. Pull or checkout the target release.
2. Review `docs/release-v*.md` between the current and target versions.
3. Compare local env values with `deployment/gateway.env.example`.
4. Rebuild the gateway image.
5. Run `gateway.preflight` before running the connector.
6. Run one dry-run/run-once execution.
7. Review reports before restoring continuous operation.

Rollback is valid when preflight fails, graph evidence changes unexpectedly,
source volume exceeds capacity or OpenCTI import behavior is not acceptable.
Rollback should restore the previous image and the previous state backup.

## Deployment Handoff Checklist

- Product purpose and gateway boundary are explained.
- OpenCTI remains the graph and knowledge platform.
- NarrowCTI remains the curation, policy, deduplication, enrichment and audit
  layer before ingestion.
- `.env` files with real secrets are excluded from version control.
- Preflight output is captured for the installation record.
- Operational validation output is captured for the graph-promotion readiness
  record.
- Source guardrails are documented for OTX and MISP.
- Quarantine/release workflow is documented for analysts.
- Graph promotion mode and OpenCTI lookup posture are documented.
- `distribution_model=open_source`, `open_source=true` and capability inventory
  are visible in preflight.
- Upgrade and rollback procedures are understood before continuous operation.

## Non-Goals In v0.8

- Managed installer.
- Hosted activation service.
- Runtime commercial activation parsing or paid feature blocking.
- Unbounded automatic OpenCTI graph writes from graph candidates.
- Customer-facing administration UI.
