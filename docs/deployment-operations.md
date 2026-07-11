# Deployment Operations

This is the current public deployment entry point for NarrowCTI Community
Edition.

The v0.8 detailed deployment snapshot is `deployment-operations-v0.8.md`.
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

The Compose template builds `Dockerfile.gateway`, joins an existing OpenCTI
Docker network and stores runtime evidence in a Docker volume.

For local validation, the default image is `narrowcti/gateway:local`. The latest
published stable release remains v0.9 while v1.0 is in development. For release
deployments, use a pinned published image such as:

```text
NARROWCTI_GATEWAY_IMAGE=ghcr.io/narrowcti/narrowcti-gateway:0.8.0
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

## Optional Analyst Review API

v0.9 adds an isolated `review-api` Compose profile. It shares only the
NarrowCTI state volume and OpenCTI network with the gateway, runs with a
read-only root filesystem, drops Linux capabilities and publishes its port to
host loopback only.

Create a hashed credential file before starting it. The versioned example is
deliberately unusable.

```powershell
python -m gateway.review_auth
Copy-Item deployment\review-api-credentials.example.json deployment\review-api-credentials.json
```

Replace the example principal, roles and token hash. The credentials source is
a Compose host interpolation, so set it in the shell and start the service:

```powershell
$env:NARROWCTI_REVIEW_API_CREDENTIALS_SOURCE = "./review-api-credentials.json"
$env:NARROWCTI_REVIEW_API_PUBLISHED_PORT = "8081"
docker compose -f deployment\docker-compose.narrowcti-gateway.yml --profile review-api up -d --build narrowcti-review-api
```

Keep real export disabled until preview and deduplication checks pass. See
`analyst-review-api.md` for the complete security and role model.

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

- `deployment-operations-v0.8.md`: detailed v0.8 deployment snapshot.
- `environment-profiles.md`: safe profiles for lab, validation, continuous
  operation and controlled graph export.
- `configuration-reference.md`: configuration variable reference.
- `analyst-review-api.md`: authenticated review API operations and security.
- `curation-decision-reference.md`: decision behavior reference.
- `support-diagnostics-v0.8.md`: support bundle and redaction behavior.
