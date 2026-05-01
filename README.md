# CTI Gateway

CTI Gateway is a modular threat intelligence ingestion layer designed to collect,
score, deduplicate and export intelligence into OpenCTI.

The current release focuses on a custom AlienVault OTX connector that turns OTX
pulses into controlled OpenCTI ingestion candidates, with explicit policy
decisions before export.

## Current Version

```text
v0.3.0-dev
```

`v0.2.0` is the latest stable release. `v0.3.0-dev` is the current product
foundation track.

## What It Does

- Searches OTX pulses using configurable threat intelligence queries.
- Enriches candidate pulses through the OTX API.
- Calculates contextual scores before ingestion.
- Applies ingestion policy for drop, quarantine and export decisions.
- Deduplicates processed pulses with persistent local state.
- Builds STIX bundles for OpenCTI ingestion.
- Runs as a Dockerized connector inside an OpenCTI lab environment.

## Architecture

```text
OTX API
  -> OTX client
  -> processor
  -> scoring and policy
  -> state repository
  -> STIX builder
  -> OpenCTI exporter
```

Main modules:

```text
connectors/otx/      OTX connector runtime, settings, client and processor
core/                Feed contracts, scoring, policy and persistent state handling
exporters/           OpenCTI export and STIX bundle construction
tests/               Unit coverage for the processor and shared pipeline logic
docs/                Release and implementation documentation
```

## Product Positioning

CTI Gateway is designed as a pre-ingestion intelligence decision layer for
OpenCTI. Its role is to reduce feed noise before data reaches the OpenCTI graph
by applying source-specific enrichment, scoring, deduplication and policy.

The long-term product direction is multi-feed support with a shared decision
engine, so OTX, MISP, commercial feeds and internal sources can be evaluated
through the same explainable ingestion model.

## OTX Connector

The OTX connector is configured through environment variables. A safe template is
provided at:

```text
connectors/otx/.env.example
```

The real runtime file must be created locally as:

```text
connectors/otx/.env
```

Do not commit the real `.env` file. It contains OpenCTI and OTX credentials.

Required variables:

```text
OPENCTI_URL
OPENCTI_TOKEN
OTX_API_KEY
OTX_QUERIES
```

## Docker Runtime

This repository is expected to sit next to the OpenCTI Compose workspace:

```text
<lab-root>/
  cti-gateway/
  opencti/
```

The OpenCTI Compose file owns the connector service definition. The connector
service name is:

```text
connector-otx-custom
```

Common commands:

```powershell
$LAB_ROOT = "<path-to-lab-root>"
cd "$LAB_ROOT\opencti"
docker compose --profile otx-custom build connector-otx-custom
docker compose --profile otx-custom up -d --force-recreate connector-otx-custom
docker compose --profile otx-custom logs --tail 120 connector-otx-custom
```

## Validation

Run validation from the repository root after building the Docker image:

```powershell
$LAB_ROOT = "<path-to-lab-root>"
cd "$LAB_ROOT\cti-gateway"
docker run --rm opencti-connector-otx-custom python -m py_compile connector.py models.py processor.py runtime.py settings.py otx_client.py core/scoring.py core/policy.py core/state_repository.py exporters/opencti.py exporters/stix_builder.py
docker run --rm -v "${LAB_ROOT}\cti-gateway:/repo" -w /repo opencti-connector-otx-custom python -m unittest discover -s tests -v
```

## Release Flow

The project uses `dev` as the integration branch and `main` as the stable branch.
Official versions should be marked with Git tags.

```text
feature/refactor branch -> dev -> main -> version tag
```

For this release:

```text
v0.2.0
```

## Documentation

Detailed implementation notes for this release are available in:

```text
docs/otx-custom-connector-refactor-v2.md
```

Product foundation documents:

```text
docs/product-foundation-v0.3.md
docs/roadmap.md
docs/licensing-strategy.md
```

## Roadmap

- Product foundation and commercial licensing structure.
- Multi-feed support beyond the custom OTX connector.
- Advanced correlation across sources.
- Richer scoring model with source-specific weighting.
- Sigma or detection-rule generation.
- Administrative controls for policy tuning.

## Security Notes

- Never commit real `.env` files or API tokens.
- Do not commit local machine paths, usernames or lab-specific secrets.
- Preserve `state/state.json` unless reprocessing old pulses is intentional.
- Avoid destructive Docker cleanup commands against persistent OpenCTI or MISP
  volumes unless backups are confirmed.

## License

CTI Gateway is being prepared as proprietary commercial software. See:

```text
LICENSE
THIRD_PARTY_NOTICES.md
```

The current license notice is an initial product foundation and should be
reviewed by qualified legal counsel before commercial distribution.
