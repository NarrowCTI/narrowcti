# NarrowCTI Gateway OTX Adapter - v0.2.0 Foundation Notes

## Purpose

This document describes the refactored OTX adapter foundation used by
NarrowCTI Gateway. The goal of this version is to turn the OTX adapter into a modular,
testable and safer foundation for future development while preserving
compatibility with the Docker/OpenCTI lab runtime.

## Version Scope

This version covers:

- OTX pulse ingestion through configurable queries.
- OTX pulse enrichment through the OTX API.
- Contextual scoring before ingestion.
- Ingestion policy with drop and quarantine support.
- Persistent deduplication by pulse id.
- OpenCTI export through STIX bundles.
- Runtime configuration through environment variables.
- Docker-based syntax, unit and runtime validation.

This version does not implement yet:

- Advanced correlation across feeds.
- Complete support for feed adapters beyond OTX.
- An asynchronous pipeline or dedicated ingestion queue.
- An administrative interface for dynamic policy tuning.

## Architecture

The connector was split into modules with focused responsibilities:

```text
connectors/otx/connector.py
  Process entrypoint. Loads settings, builds clients and starts the runtime.

connectors/otx/runtime.py
  Main process loop. Runs the processor and waits for the configured interval.

connectors/otx/settings.py
  Environment variable loading and normalization.

connectors/otx/otx_client.py
  OTX HTTP client with timeout, retries and backoff.

connectors/otx/processor.py
  Ingestion orchestration: queries, state, enrichment, policy and export.

connectors/otx/models.py
  Internal processor DTOs, including PulseCandidate and QuerySummary.

core/scoring.py
  Pulse score and age calculations.

core/policy.py
  Ingestion decision rules for drop, quarantine and export.

core/state_repository.py
  Persistent state used to avoid reprocessing the same pulse.

exporters/opencti.py
  OpenCTI export integration.

exporters/stix_builder.py
  STIX bundle creation, including identity, report and indicators.
```

## Runtime Flow

1. `connector.py` loads environment variables through `load_settings()`.
2. `connector.py` creates the `OpenCTIApiClient` and `OTXClient`.
3. `connector.py` builds the `OTXProcessor`.
4. `runtime.py` runs `processor.run_once()` inside the continuous loop.
5. `run_once()` creates the state repository and processes each configured
   query.
6. `process_query()` searches OTX pulses and applies review/ingestion limits.
7. `process_pulse()` validates the pulse id, checks state, enriches the pulse,
   evaluates policy and exports accepted candidates.
8. After a successful export, the pulse id is marked in state.
9. At the end of each query, a `QuerySummary` is returned and logged.

## Ingestion Policy

The ingestion decision lives in `core/policy.py` and receives a `PolicyConfig`.

Main rules:

- Pulses without a valid date continue with unknown age.
- Low-score pulses can be sent to quarantine when quarantine is enabled.
- Pulses below `MIN_SCORE_TO_INGEST` are dropped.
- Old pulses must reach `MIN_SCORE_FOR_OLD_PULSE`.
- `MAX_DAYS_HARD_FILTER` can enforce an absolute age cutoff.

Relevant parameters:

```text
MIN_SCORE_TO_INGEST=60
MAX_DAYS_OLD=1095
MIN_SCORE_FOR_OLD_PULSE=80
MAX_DAYS_HARD_FILTER=0
ENABLE_QUARANTINE=true
QUARANTINE_SCORE_THRESHOLD=50
```

## State And Deduplication

The state is stored in a JSON file. The default container path is:

```text
/app/state/state.json
```

In Docker Compose, that path is mounted from the local workspace:

```text
../NarrowCTI/state:/app/state
```

This prevents the connector from reprocessing pulses that were already handled.
The state is marked only after the OpenCTI export succeeds. If export fails, the
pulse is not marked and can be retried in a future run.

## Environment Variables

The versioned example lives at:

```text
connectors/otx/.env.example
```

The real runtime file should be created locally at:

```text
connectors/otx/.env
```

The real `.env` file contains secrets and must not be committed.

Required variables:

```text
OPENCTI_URL
OPENCTI_TOKEN
OTX_API_KEY
OTX_QUERIES
```

Main operational variables:

```text
CONNECTOR_NAME
CONNECTOR_RUN_INTERVAL
STATE_FILE
OTX_TIMEOUT
OTX_SEARCH_TIMEOUT
OTX_RETRIES
OTX_RETRY_BACKOFF_SECONDS
MAX_PULSES_PER_QUERY
MAX_SEARCH_RESULTS_PER_QUERY
MAX_IOCS_PER_PULSE
INGEST_PAUSE_SECONDS
```

## Docker

The main Docker Compose file lives outside this repository:

```text
<lab-root>/opencti/docker-compose.yml
```

Expected local lab layout:

```text
<lab-root>/
  NarrowCTI/
  opencti/
```

Connector service:

```text
connector-narrowcti
```

Container name:

```text
narrowcti-connector
```

Main commands:

```powershell
$LAB_ROOT = "<path-to-lab-root>"
cd "$LAB_ROOT\opencti"
docker compose --profile narrowcti build connector-narrowcti
docker compose --profile narrowcti up -d --force-recreate connector-narrowcti
docker compose --profile narrowcti logs --tail 120 connector-narrowcti
docker compose --profile narrowcti ps connector-narrowcti
```

The current Compose file may show this warning:

```text
the attribute `version` is obsolete
```

This warning does not block runtime. It only means the `version` field can be
removed from the Compose file in a future cleanup.

## Development Summary

This version was developed in small, validated slices.

Main changes:

- Adjusted the Docker build so `core` and `exporters` are copied into the image.
- Extracted configuration handling into `settings.py`.
- Extracted OTX HTTP access into `otx_client.py`.
- Extracted the main processing flow into `processor.py`.
- Added `runtime.py` to isolate the continuous process loop.
- Added `models.py` for `PulseCandidate` and `QuerySummary`.
- Added `PolicyConfig` in `core/policy.py`.
- Added `PulseStateRepository` in `core/state_repository.py`.
- Split STIX construction into `exporters/stix_builder.py`.
- Added dependency injection points to the processor:
  - exporter
  - state repository factory
  - sleeper
  - ingest pause
- Added structured summaries per query and per run.
- Added protection for pulses without ids.
- Added protection for enrichment failures.
- Prevented state marking when export fails.
- Configured STIX identity through `CONNECTOR_NAME`.
- Added `.env.example` without secrets.
- Split processor-focused tests into a dedicated test file.

## Tests

Test files:

```text
tests/test_core_pipeline.py
tests/test_otx_processor.py
```

Main validation command:

```powershell
$LAB_ROOT = "<path-to-lab-root>"
cd "$LAB_ROOT\NarrowCTI"
docker run --rm -v "${LAB_ROOT}\NarrowCTI:/repo" -w /repo opencti-connector-narrowcti python -m unittest discover -s tests -v
```

Final validation for this version on 2026-05-01 passed with:

```text
Ran 34 tests
OK
```

## Final Image Validation

Build:

```powershell
$LAB_ROOT = "<path-to-lab-root>"
cd "$LAB_ROOT\opencti"
docker compose --profile narrowcti build connector-narrowcti
```

Python syntax:

```powershell
$LAB_ROOT = "<path-to-lab-root>"
cd "$LAB_ROOT\NarrowCTI"
docker run --rm opencti-connector-narrowcti python -m py_compile connector.py feed_adapter.py models.py processor.py runtime.py settings.py otx_client.py core/decision_audit.py core/feed_contract.py core/scoring.py core/policy.py core/state_repository.py exporters/opencti.py exporters/stix_builder.py
```

Runtime:

```powershell
$LAB_ROOT = "<path-to-lab-root>"
cd "$LAB_ROOT\opencti"
docker compose --profile narrowcti up -d --force-recreate connector-narrowcti
docker compose --profile narrowcti logs --tail 120 connector-narrowcti
```

Expected log signals:

```text
INFO:api:Health check (platform version)...
[INFO] Query: ...
[INFO] Searching OTX: ...
[INFO] Candidate: ...
[INFO] Drop: ... reason=...
[INFO] Query summary: ... reviewed=... ingested=... available=...
```

## Operations

To adjust search scope, edit `OTX_QUERIES` in the real local `.env` file.

To reduce OTX API calls:

```text
MAX_SEARCH_RESULTS_PER_QUERY
MAX_PULSES_PER_QUERY
CONNECTOR_RUN_INTERVAL
```

To enforce a stricter policy against old intelligence:

```text
MAX_DAYS_OLD
MAX_DAYS_HARD_FILTER
MIN_SCORE_FOR_OLD_PULSE
```

To reduce exported indicator volume per pulse:

```text
MAX_IOCS_PER_PULSE
```

## Safety Notes

- Do not commit `connectors/otx/.env`.
- Do not delete `state/state.json` unless reprocessing old pulses is intended.
- Do not run `docker compose down -v` against OpenCTI or MISP without backups.
- Do not run `docker volume prune` when important persistent volumes exist.
- For disk cleanup, prefer `docker builder prune` and `docker image prune`
  before any volume-related operation.

## PR Preparation

Before opening the PR to `main`, validate from `dev`:

```powershell
$LAB_ROOT = "<path-to-lab-root>"
cd "$LAB_ROOT\NarrowCTI"
git status
cd "$LAB_ROOT\opencti"
docker compose --profile narrowcti build connector-narrowcti
cd "$LAB_ROOT\NarrowCTI"
docker run --rm opencti-connector-narrowcti python -m py_compile connector.py feed_adapter.py models.py processor.py runtime.py settings.py otx_client.py core/decision_audit.py core/feed_contract.py core/scoring.py core/policy.py core/state_repository.py exporters/opencti.py exporters/stix_builder.py
docker run --rm -v "${LAB_ROOT}\NarrowCTI:/repo" -w /repo opencti-connector-narrowcti python -m unittest discover -s tests -v
```

Suggested PR title:

```text
release: promote v0.3.0 product foundation
```

Suggested summary:

```text
This PR promotes NarrowCTI v0.3.0 product foundation. It keeps OTX as the
reference adapter while aligning runtime identity, documentation and Compose
naming to NarrowCTI Gateway.
```
