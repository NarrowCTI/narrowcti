# Deployment Operations

This is the current public deployment entry point for NarrowCTI Community
Edition.

The v0.8 detailed deployment snapshot is `deployment-operations-v0.8.md`.
Versioned deployment files remain available as release history; operators
should link to this unversioned document for the current deployment path.

## Current Deployment Model

The v0.8 deployment model is conservative:

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

For local validation, the default image is `narrowcti/gateway:local`. For
release deployments, use a pinned published image such as:

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

## Current Operational References

- `deployment-operations-v0.8.md`: detailed v0.8 deployment snapshot.
- `environment-profiles.md`: safe profiles for lab, validation, continuous
  operation and controlled graph export.
- `configuration-reference.md`: configuration variable reference.
- `curation-decision-reference.md`: decision behavior reference.
- `support-diagnostics-v0.8.md`: support bundle and redaction behavior.
