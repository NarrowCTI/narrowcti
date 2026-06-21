# NarrowCTI

NarrowCTI is a modular threat intelligence ingestion layer designed to collect,
score, deduplicate and export intelligence into OpenCTI.

NarrowCTI Gateway currently uses AlienVault OTX as its first reference feed
adapter. OTX pulses are normalized into controlled ingestion candidates, scored,
deduplicated and evaluated before export to OpenCTI.

## Current Version

```text
v0.3.0-dev
```

`v0.2.0` is the latest stable release. `v0.3.0-dev` is the current product
foundation track.

## Product Identity

The v0.2 line was the modular OTX connector foundation. The v0.3 line is the
transition from an OTX-specific connector into NarrowCTI Gateway, an OpenCTI-native
pre-ingestion intelligence gateway. OTX remains the first source adapter; it is no
longer the product identity. v0.4 is expected to validate the gateway model with a
second real feed.

## What It Does

- Searches OTX pulses using configurable threat intelligence queries.
- Enriches candidate pulses through the OTX API.
- Calculates contextual scores before ingestion.
- Applies ingestion policy for drop, quarantine and export decisions.
- Optionally writes structured decision audit records for operational review.
- Logs per-query operational summaries for reviewed, ingested, dropped,
  quarantined, skipped and failed candidates.
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
connectors/otx/      OTX connector runtime, feed adapter, settings and processor
core/                Feed contracts, scoring, policy and persistent state handling
exporters/           OpenCTI export and STIX bundle construction
tests/               Unit coverage for the processor and shared pipeline logic
docs/                Release and implementation documentation
```

## Product Positioning

NarrowCTI is designed as a pre-ingestion intelligence decision layer for
OpenCTI. Its role is to reduce feed noise before data reaches the OpenCTI graph
by applying source-specific enrichment, scoring, deduplication and policy.

The long-term product direction is multi-feed support with a shared decision
engine, so OTX, MISP, commercial feeds and internal sources can be evaluated
through the same explainable ingestion model.

## NarrowCTI Gateway Runtime

The NarrowCTI Gateway runtime is configured through environment variables. The
current runtime uses the OTX adapter, and a safe template is
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
  NarrowCTI/
  opencti/
```

The OpenCTI Compose file owns the connector service definition. The connector
service name is:

```text
connector-narrowcti
```

Common commands:

```powershell
$LAB_ROOT = "<path-to-lab-root>"
cd "$LAB_ROOT\opencti"
docker compose --profile narrowcti build connector-narrowcti
docker compose --profile narrowcti up -d --force-recreate connector-narrowcti
docker compose --profile narrowcti logs --tail 120 connector-narrowcti
```

## Validation

Run validation from the repository root after building the Docker image:

```powershell
$LAB_ROOT = "<path-to-lab-root>"
cd "$LAB_ROOT\NarrowCTI"
docker run --rm opencti-connector-narrowcti python -m py_compile connector.py feed_adapter.py models.py processor.py runtime.py settings.py otx_client.py core/decision_audit.py core/feed_contract.py core/scoring.py core/policy.py core/state_repository.py exporters/opencti.py exporters/stix_builder.py
docker run --rm -v "${LAB_ROOT}\NarrowCTI:/repo" -w /repo opencti-connector-narrowcti python -m unittest discover -s tests -v
```

## Release Flow

The project uses `dev` as the integration branch and `main` as the stable branch.
Official versions should be marked with Git tags.

```text
feature/refactor branch -> dev -> main -> version tag
```

For this development track:

```text
v0.3.0-dev
```

## Documentation

Detailed implementation notes for this release are available in:

```text
docs/otx-adapter-foundation-v0.2.md
```

Product foundation documents:

```text
docs/product-foundation-v0.3.md
docs/roadmap.md
docs/licensing-strategy.md
```

## Roadmap

- Product foundation and commercial licensing structure.
- Multi-feed support beyond the reference OTX adapter.
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

NarrowCTI is being prepared as proprietary commercial software. See:

```text
LICENSE
THIRD_PARTY_NOTICES.md
```

The current license notice is an initial product foundation and should be
reviewed by qualified legal counsel before commercial distribution.
