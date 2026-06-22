# NarrowCTI

NarrowCTI is an OpenCTI-native threat intelligence gateway designed to curate,
score, deduplicate and govern threat intelligence before it reaches the OpenCTI
graph.

NarrowCTI Gateway turns raw feed data into controlled ingestion candidates with
explainable decisions, source provenance, guardrails and operational evidence for
CTI, hunting and SOC teams.

## Current Version
```text
v0.5.0-dev
```

`v0.5.0-dev` is the current gateway runtime and decision engine development
track. `v0.4.0` remains the latest stable multi-feed expansion release.

## Product Identity

The v0.2 line was the modular OTX connector foundation. The v0.3 line is the
transition from an OTX-specific connector into NarrowCTI Gateway, an OpenCTI-native
pre-ingestion intelligence gateway. OTX remains the first source adapter; it is no
longer the product identity. The v0.4 release validates the gateway model with a
second real feed, with MISP as the first strategic candidate. The v0.5 track
starts the move toward a unified gateway runtime.

## What It Does

- Searches OTX pulses using configurable threat intelligence queries.
- Enriches candidate pulses through the OTX API.
- Calculates contextual scores before ingestion.
- Applies ingestion policy for drop, quarantine and export decisions.
- Optionally writes structured decision audit records for operational review.
- Logs per-query operational summaries for reviewed, ingested, dropped,
  quarantined, skipped and failed candidates.
- Deduplicates processed pulses with persistent local state.
- Provides a MISP adapter foundation with independent state, dry-run mode,
  run-once execution and safe backfill filters.
- Builds STIX bundles for OpenCTI ingestion.
- Runs as a Dockerized connector inside an OpenCTI lab environment.

## Architecture

```text
External and internal intelligence sources
  -> source adapters such as OTX and MISP
  -> shared feed contract
  -> scoring, policy and decision audit
  -> source-scoped state and guardrails
  -> STIX builder
  -> OpenCTI exporter
```

Main modules:

```text
connectors/otx/      OTX connector runtime, feed adapter, settings and processor
connectors/misp/     MISP client, feed adapter, settings and processor foundation
core/                Feed contracts, scoring, policy and persistent state handling
exporters/           OpenCTI export and STIX bundle construction
tests/               Unit coverage for the processor and shared pipeline logic
docs/                Release and implementation documentation
```

## Product Positioning

NarrowCTI is designed as a pre-ingestion intelligence decision layer for
OpenCTI. Its role is to reduce feed noise before data reaches the OpenCTI graph
by applying source-specific enrichment, scoring, deduplication and policy.

The product direction is a professional CTI gateway for analysts, hunters, SOC
and platform teams that need curated intelligence, explainable decisions and
auditable feed governance instead of raw IoC forwarding. OTX, MISP, commercial
feeds and internal sources should be evaluated through the same explainable
ingestion model.

## v0.4 Release

The v0.4 release starts the multi-feed expansion. OTX remains the reference
adapter, while MISP becomes the likely second adapter because many operations
use MISP as the central IoC and event hub.

The intended flow for MISP-backed environments is:

```text
AlienVault OTX and other feeds
  -> MISP
  -> NarrowCTI Gateway
  -> OpenCTI
```

NarrowCTI should preserve both the collector context, such as MISP, and the
original intelligence source, such as AlienVault OTX, when that information is
available.

A 2026-06-21 local validation confirmed that one MISP event can contain tens
of thousands of attributes, and that `opencti/connector-misp:6.9.4` does not
support `MISP_IMPORT_LIMIT`. NarrowCTI therefore needs first-class per-run and
per-event safety controls instead of relying on the official connector for
controlled backfill.

The MISP adapter foundation now includes explicit guardrails for maximum events
per run, maximum attributes per event and maximum exported IoCs per event.
Oversized events are skipped by default, with an explicit truncate mode available
for controlled experiments.
The adapter also supports dry-run validation, one-shot execution and bounded
historical backfill filters for date ranges, tags and published-only imports.
The adapter has dedicated settings, MISP event state and a processor foundation
so it can evolve without sharing OTX pulse processing state.

## v0.5 Development Track

The v0.5 track introduces the first unified NarrowCTI Gateway runtime.
Instead of treating each source container as the product shape, the gateway
runtime should orchestrate enabled sources such as OTX and MISP through a source
registry while keeping source-level state, audit evidence, guardrails and failure
isolation intact.

The source-specific OTX and MISP runtimes should remain available for debugging,
validation and bounded backfill. MISP should stay opt-in and guarded until local
OpenCTI, queue and Elasticsearch behavior remains stable across repeated bounded
runs. The detailed v0.5 design is tracked in `docs/gateway-runtime-v0.5.md`,
and the product/architecture continuity validation is tracked in
`docs/product-architecture-validation-v0.5.md`.

## NarrowCTI Gateway Runtime

The NarrowCTI Gateway runtime is configured through environment variables. The
current stable runtime uses the OTX adapter, and a safe template is provided at:

```text
connectors/otx/.env.example
```

The MISP adapter foundation has its own configuration template for controlled
local validation:

```text
connectors/misp/.env.example
```

Real runtime files must be created locally as needed:

```text
connectors/otx/.env
connectors/misp/.env
```

Do not commit real `.env` files. They contain OpenCTI, OTX or MISP credentials.

Required OTX variables:

```text
OPENCTI_URL
OPENCTI_TOKEN
OTX_API_KEY
OTX_QUERIES
```

Required MISP foundation variables:

```text
OPENCTI_URL
OPENCTI_TOKEN
MISP_URL
MISP_KEY
MISP_QUERIES
```

Recommended safe MISP validation controls for limited local machines:

```text
MISP_DRY_RUN=true
MISP_RUN_ONCE=true
MISP_MAX_EVENTS_PER_RUN=1
MISP_MAX_ATTRIBUTES_PER_EVENT=1000
MISP_MAX_IOCS_PER_EVENT=1000
MISP_QUERIES=*
MISP_FROM_DATE=YYYY-MM-DD
MISP_TO_DATE=YYYY-MM-DD
MISP_TAGS=tlp:green
MISP_PUBLISHED_ONLY=true
MISP_OVERSIZED_EVENT_ACTION=skip
```

## Docker Runtime

This repository is expected to sit next to the OpenCTI Compose workspace:

```text
<lab-root>/
  NarrowCTI/
  opencti/
```

The OpenCTI Compose file owns the connector service definitions. Runtime
services are intentionally split by source:

```text
connector-narrowcti       OTX reference runtime
connector-narrowcti-misp  MISP dry-run/backfill runtime
```

Common OTX commands:

```powershell
$LAB_ROOT = "<path-to-lab-root>"
cd "$LAB_ROOT\opencti"
docker compose --profile narrowcti build connector-narrowcti
docker compose --profile narrowcti up -d --force-recreate connector-narrowcti
docker compose --profile narrowcti logs --tail 120 connector-narrowcti
```

Safe MISP runtime validation commands:

```powershell
$LAB_ROOT = "<path-to-lab-root>"
cd "$LAB_ROOT\opencti"
docker compose --profile narrowcti-misp build connector-narrowcti-misp
docker compose --profile narrowcti-misp up --force-recreate connector-narrowcti-misp
docker compose --profile narrowcti-misp logs --tail 120 connector-narrowcti-misp
```

Safe MISP backfill helper:

```powershell
$LAB_ROOT = "<path-to-lab-root>"
cd "$LAB_ROOT\NarrowCTI"
.\scripts\misp-backfill-window.ps1 -FromDate 2016-01-01 -ToDate 2016-12-31 -Tags tlp:green -Preview
.\scripts\misp-backfill-window.ps1 -FromDate 2016-01-01 -ToDate 2016-12-31 -Tags tlp:green
.\scripts\misp-backfill-window.ps1 -FromDate 2026-01-02 -ToDate 2026-01-02 -Tags type:OSINT
```

The helper always runs `MISP_DRY_RUN=true`, `MISP_RUN_ONCE=true` and
ephemeral `/tmp` state. Use `-Preview` to inspect the Compose command before
execution. It also caps `MaxEvents` at 5 and defaults to `MaxEvents=1`.

When the MISP runtime runs inside the shared Docker network, use
`MISP_URL=http://misp-core` in `connectors/misp/.env`. Use `misp.local` only
for host-side browser or API access through Caddy.

## Validation

Run validation from the repository root after building the Docker image:

```powershell
$LAB_ROOT = "<path-to-lab-root>"
cd "$LAB_ROOT\NarrowCTI"
docker run --rm -v "${LAB_ROOT}\NarrowCTI:/repo" -w /repo opencti-connector-narrowcti python -m py_compile connectors/otx/connector.py connectors/otx/feed_adapter.py connectors/otx/models.py connectors/otx/processor.py connectors/otx/runtime.py connectors/otx/settings.py connectors/otx/otx_client.py connectors/misp/client.py connectors/misp/connector.py connectors/misp/feed_adapter.py connectors/misp/models.py connectors/misp/processor.py connectors/misp/runtime.py connectors/misp/settings.py core/decision_audit.py core/feed_contract.py core/scoring.py core/policy.py core/state_repository.py exporters/opencti.py exporters/stix_builder.py
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
v0.5.0-dev
```

## Documentation

Detailed implementation notes for this release are available in:

```text
docs/otx-adapter-foundation-v0.2.md
```

Product and expansion documents:

```text
docs/product-foundation-v0.3.md
docs/multi-feed-expansion-v0.4.md
docs/misp-validation-v0.4.md
docs/release-v0.4.0.md
docs/gateway-runtime-v0.5.md
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
