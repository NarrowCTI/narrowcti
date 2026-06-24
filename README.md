# NarrowCTI

NarrowCTI is an OpenCTI-native threat intelligence gateway designed to curate,
score, deduplicate and govern threat intelligence before it reaches the OpenCTI
graph.

NarrowCTI Gateway turns raw feed data into controlled ingestion candidates with
explainable decisions, source provenance, guardrails and operational evidence for
CTI, hunting and SOC teams.

## Current Version

```text
v0.8.0-dev
```

`v0.8.0-dev` is the active graph promotion, analyst review and product
operations development track. `v0.7.0` remains the latest stable foundation
release with audit-first graph evidence, graph candidates, STIX preview
summaries, contextual scoring evidence and a clear MITRE ATT&CK curation
architecture.

## Product Identity

The v0.2 line was the modular OTX connector foundation. The v0.3 line is the
transition from an OTX-specific connector into NarrowCTI Gateway, an OpenCTI-native
pre-ingestion intelligence gateway. OTX remains the first source adapter; it is no
longer the product identity. The v0.4 release validates the gateway model with a
second real feed, with MISP as the first strategic candidate. The v0.5 track
starts the move toward a unified gateway runtime. The v0.5 track also records
the enterprise intelligence gateway target: NarrowCTI should become the decision
layer that shapes actor, arsenal, TTP, victimology, infrastructure and
quarantine/release context before OpenCTI ingestion.

## What It Does

- Searches OTX pulses using configurable threat intelligence queries.
- Enriches candidate pulses through the OTX API.
- Calculates contextual scores and records scoring evidence before ingestion.
- Applies ingestion policy for drop, quarantine and export decisions.
- Optionally writes structured decision audit records for operational review.
- Logs per-query operational summaries for reviewed, ingested, dropped,
  quarantined, skipped and failed candidates.
- Deduplicates processed pulses with persistent local state.
- Provides a MISP adapter foundation with independent state, dry-run mode,
  run-once execution and safe backfill filters.
- Defines the enterprise roadmap for actor, arsenal, MITRE ATT&CK,
  victimology, quarantine-release and graph-enrichment filters.
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
ingestion model. The enterprise target is to enrich OpenCTI with actors,
arsenal, MITRE tactics and techniques, victimology, infrastructure, campaigns,
vulnerabilities and detection context when source evidence supports it. The v1.0
market position is tracked in `docs/market-positioning-v1.0.md`.

MITRE ATT&CK is treated as reference and curation context. The official MITRE
connector should populate OpenCTI with the canonical ATT&CK baseline, while
NarrowCTI uses ATT&CK ids found in OTX, MISP and future feeds to enrich, score,
filter, deduplicate, audit and later relate curated intelligence to the OpenCTI
graph. This decision is tracked in
`docs/mitre-curation-architecture-v0.7.md`.

## Deduplication Posture

NarrowCTI should protect OpenCTI graph hygiene instead of forwarding the same
artifact repeatedly. The current implementation deduplicates processed source
items with local state, deduplicates repeated STIX patterns inside each bundle
and can keep a local artifact index with provenance sightings for cross-source
correlation. The v0.5 gateway design extends this into layered pre-export
deduplication:

- Source-item deduplication prevents the same OTX pulse or MISP event from being
  processed repeatedly.
- Artifact deduplication normalizes indicator type and value before export.
- The local artifact index records source sightings so repeated OTX/MISP
  evidence can become correlation context instead of duplicate imports.
- Optional OpenCTI lookup can check existing STIX Indicator patterns before
  import when enabled.
- Cross-source matches should become provenance and confidence evidence, not
  duplicate graph noise.

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

## v0.5 Release

The v0.5 release introduces the first unified NarrowCTI Gateway runtime.
Instead of treating each source container as the product shape, the gateway
runtime should orchestrate enabled sources such as OTX and MISP through a source
registry while keeping source-level state, audit evidence, guardrails and failure
isolation intact.

The source-specific OTX and MISP runtimes should remain available for debugging,
validation and bounded backfill. MISP should stay opt-in and guarded until local
OpenCTI, queue and Elasticsearch behavior remains stable across repeated bounded
runs. The detailed v0.5 design is tracked in `docs/gateway-runtime-v0.5.md`,
the enterprise intelligence gateway model is tracked in
`docs/enterprise-intelligence-gateway-v0.5.md`, and the product/architecture
continuity validation is tracked in
`docs/product-architecture-validation-v0.5.md`.

## v0.6 Release Track

The v0.6 track is the quarantine and enrichment foundation. The goal is to
turn quarantine from a decision outcome into a reviewable, auditable operator
workflow while beginning structured enrichment from OTX and MITRE ATT&CK.

The current v0.6 implementation provides a local quarantine repository and CLI
workflow for listing, showing, rejecting and releasing held candidates with
reviewer reason and release audit evidence. OTX and MISP quarantine decisions
write pending records into the local repository with scoring metadata, source
provenance, indicators and a bounded raw snapshot. Released records can be
replayed through the existing OpenCTI export path with dry-run as the default.

The enrichment foundation extracts OTX adversary, malware family, ATT&CK,
industry, country, TLP and reference fields, then resolves ATT&CK technique and
tactic context through a local MITRE cache when configured. Gateway preflight
checks and operational reporting now include quarantine/release and MITRE cache
posture for operator readiness.

The detailed v0.6 design is tracked in
`docs/quarantine-enrichment-v0.6.md`, and the release notes are
tracked in `docs/release-v0.6.0.md`.

Initial quarantine CLI commands:

```powershell
python -m gateway.quarantine --repository state\quarantine.jsonl list --status pending
python -m gateway.quarantine --repository state\quarantine.jsonl show --id <quarantine-id>
python -m gateway.quarantine --repository state\quarantine.jsonl --release-audit-file state\audit\releases.jsonl reject --id <quarantine-id> --reason "Out of scope"
python -m gateway.quarantine --repository state\quarantine.jsonl --release-audit-file state\audit\releases.jsonl release --id <quarantine-id> --reason "Relevant to monitored actor"
python -m gateway.quarantine --repository state\quarantine.jsonl --release-audit-file state\audit\releases.jsonl release-indicators --id <quarantine-id> --type filehash-sha256,url --reason "High-value indicators"
python -m gateway.quarantine --repository state\quarantine.jsonl export-released --id <quarantine-id>
python -m gateway.quarantine --repository state\quarantine.jsonl export-released --id <quarantine-id> --execute --dedup-state-file state\dedup_index.json
python -m gateway.quarantine --release-audit-file state\audit\releases.jsonl audit
```

The initial v0.6 CLI records review state and release audit evidence locally.
The source processors automatically enqueue policy-quarantined OTX pulses and
MISP events when `NARROWCTI_QUARANTINE_REPOSITORY` is configured. Released
records can be replayed through the same OpenCTI export path with a dry-run
default; `--execute` is required for real export. The `audit` command summarizes
release, reject and export audit events without requiring manual JSONL parsing.

OTX entity extraction is controlled by
`NARROWCTI_ENABLE_OTX_ENTITY_EXTRACTION=true`. In v0.6 this extraction is
metadata-only: adversary, malware family, ATT&CK ids, industries, targeted
countries, TLP, references and tags are preserved as structured evidence for
future graph enrichment.

## v0.7 Release

The v0.7 release turns the enrichment evidence from v0.6 into graph-aware
STIX/OpenCTI planning and preview output. The objective is to validate source
metadata more deeply, map supported evidence into actors, intrusion sets,
malware, tools, infrastructure, vulnerabilities, campaigns, sectors, locations,
ATT&CK techniques and relationships, and keep those relationships explainable
before they affect the OpenCTI graph.

The consolidated architecture is tracked in `docs/architecture-v0.7.md`. The
detailed graph-enrichment design is tracked in
`docs/graph-enrichment-v0.7.md`, and the release notes are tracked in
`docs/release-v0.7.0.md`. The MITRE curation architecture is tracked in
`docs/mitre-curation-architecture-v0.7.md`. MISP
compatibility with the official OpenCTI connector mapping is tracked in
`docs/misp-official-connector-mapping-v0.7.md`, and OTX compatibility with the
official AlienVault connector mapping is tracked in
`docs/otx-official-connector-mapping-v0.7.md`. Contextual scoring research is
tracked in `docs/contextual-scoring-reference-v0.7.md`.
The direct source, MISP collector and hybrid ingestion architecture is tracked
in `docs/source-ingestion-modes-v0.7.md`.

## v0.8 Development Track

The v0.8 track starts the controlled promotion gate after v0.7. Its first
technical priority is read-only OpenCTI graph lookup so NarrowCTI can detect
canonical ATT&CK objects, such as existing `attack-pattern` entries loaded by
the official MITRE connector, before any real graph promotion is enabled.

The graph promotion design is tracked in `docs/graph-promotion-v0.8.md`, and
the detailed development notes are tracked in `docs/release-v0.8.0.md`.
Bounded lab validation for this track is described in
`docs/operational-validation-v0.8.md`.

## Curation Configuration

Curation controls must be visible in configuration and then applied
automatically by the gateway. Current source runtimes expose score thresholds,
age limits, quarantine behavior, gateway-level allowed TLP, exportable
indicator types, MISP date ranges, MISP tag filters and volume guardrails
through environment variables. The v0.5 track adds gateway-level `NARROWCTI_*`
controls for shared policy, deduplication and source selection. Future
enterprise controls should cover actor, arsenal, ATT&CK, victimology, graph
state and quarantine release workflows without hiding those policy choices from
operators.

The v0.7 graph layer currently records `graph_candidate_policy` and
`graph_export_plan` metadata. `NARROWCTI_GRAPH_EXPORT_MODE=audit` keeps the
plan audit-only, while `dry-run` records what graph objects and relationships
would be attempted later. The first graph-aware STIX builder foundation can
convert accepted candidates into STIX objects for validation, and OTX/MISP
decision metadata now records a safe `graph_stix_preview` summary with bundle,
object, relationship and skipped-candidate counts. Real graph export remains
blocked until controlled export wiring, deduplication promotion and OpenCTI
validation are complete. The local graph deduplication state can be read with
`NARROWCTI_GRAPH_DEDUP_STATE_FILE` so OTX and MISP export plans can mark known
local graph keys as deduplicated. This is read-only planning evidence; dry-run
plans are not marked as exported knowledge. In v0.8,
`NARROWCTI_OPENCTI_GRAPH_LOOKUP=true` can also be enabled so OTX and MISP
planning query OpenCTI for canonical graph objects, starting with ATT&CK
attack-patterns, before later promotion work is allowed to create new graph
knowledge. Canonical matches are exposed as bounded
`graph_export_plan_lookup_matches` metadata for audit and future enterprise
reporting, and the decision audit report summarizes lookup match counts by
object type and match type.

The full configuration reference is tracked in
`docs/configuration-reference-v0.6.md`, extending the base v0.5 reference in
`docs/configuration-reference-v0.5.md`.

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


Initial v0.5 gateway runtime command for development validation:

```powershell
$LAB_ROOT = "<path-to-lab-root>"
cd "$LAB_ROOT\NarrowCTI"
docker run --rm --env-file config\.env.example -v "${LAB_ROOT}\NarrowCTI:/repo" -w /repo opencti-connector-narrowcti python -m gateway.connector
```

The example keeps `NARROWCTI_DRY_RUN=true` and `OTX_DRY_RUN=true` for safe local validation.

Before running ingestion, operators can validate the gateway runtime posture
without calling feed APIs or OpenCTI:

```powershell
$LAB_ROOT = "<path-to-lab-root>"
cd "$LAB_ROOT\NarrowCTI"
docker run --rm --env-file config\.env.example -v "${LAB_ROOT}\NarrowCTI:/repo" -w /repo opencti-connector-narrowcti python -m gateway.preflight
docker run --rm --env-file config\.env.example -v "${LAB_ROOT}\NarrowCTI:/repo" -w /repo opencti-connector-narrowcti python -m gateway.preflight --json
```

The preflight reports enabled sources, deduplication posture, OpenCTI lookup,
aggregate summary output, source dry-run controls and local evidence paths for
source state, decision audit, release audit, quarantine repository, MITRE cache
and artifact deduplication. Unknown sources fail the check; weaker
graph-hygiene, missing MITRE cache and operational settings are reported as
warnings.

After one or more gateway runs, operators can summarize the aggregate JSONL
evidence written by `NARROWCTI_RUN_SUMMARY_FILE`:

```powershell
$LAB_ROOT = "<path-to-lab-root>"
cd "$LAB_ROOT\NarrowCTI"
docker run --rm -v "${LAB_ROOT}\NarrowCTI:/repo" -w /repo opencti-connector-narrowcti python -m gateway.report --file state\gateway_runs.jsonl
docker run --rm -v "${LAB_ROOT}\NarrowCTI:/repo" -w /repo opencti-connector-narrowcti python -m gateway.report --file state\gateway_runs.jsonl --json
docker run --rm -v "${LAB_ROOT}\NarrowCTI:/repo" -w /repo opencti-connector-narrowcti python -m gateway.decisions --dir state\audit
docker run --rm -v "${LAB_ROOT}\NarrowCTI:/repo" -w /repo opencti-connector-narrowcti python -m gateway.correlation --file state\dedup_index.json
```

The report aggregates run count, time range, total outcomes and per-source
outcomes for reviewed, ingested, dropped, quarantined, skipped, error and
dry-run candidates. It also reports directional value metrics such as accepted
items, filtered items, acceptance rate, filter rate and error rate, and it lists
source failures captured during gateway runs. Per-query rollups show which
searches produced reviewed, handled, accepted and filtered candidates. The
decision audit report aggregates ingest, drop, quarantine, skip, dry-run and
error reasons from source audit JSONL files, plus score ranges, averages and
per-query decision rollups for operator review. It also lists recent
quarantined candidates. When v0.7 `graph_export_plan` metadata is present, it
also aggregates graph export modes, statuses, actions, held reasons,
source/query rollups, deduplicated entity/relationship counts and dry-run
would-create object/relationship counts. The correlation report summarizes the
local artifact index, including cross-source fingerprints and source sighting
counts.

The unified gateway entrypoint composes enabled source runtimes and isolates
source failures. Keep source-specific runtimes available for debugging and
bounded backfills while the v0.5 gateway matures.

## Deployment

The authoritative v0.8 deployment and upgrade procedure is centralized in:

```text
docs/deployment-operations-v0.8.md
```

The deployment assets are:

```text
deployment/docker-compose.narrowcti-gateway.yml
deployment/gateway.env.example
```

The v0.8 template is dry-run/run-once by default, joins an existing OpenCTI
Docker network and must be validated with `gateway.preflight` before any source
execution. Older deployment snippets in release-specific documents are
historical context; use `docs/deployment-operations-v0.8.md` for the current
procedure.

Source-specific OTX and MISP runtimes remain available for debugging and
bounded backfill investigations, but they are not the current deployment source
of truth. Use `docs/deployment-operations-v0.8.md` for deployment and upgrade
steps, and `scripts/misp-backfill-window.ps1 -Preview` only for controlled MISP
backfill command inspection.

## Validation

Run validation from the repository root after building the Docker image:

```powershell
$LAB_ROOT = "<path-to-lab-root>"
cd "$LAB_ROOT\NarrowCTI"
.\scripts\validate-v0.6.ps1
```

The helper runs the same Docker-based syntax and unit validation commands used
for the release. To inspect commands without executing Docker:

```powershell
.\scripts\validate-v0.6.ps1 -Preview
```

Manual equivalent:

```powershell
docker run --rm -v "${LAB_ROOT}\NarrowCTI:/repo" -w /repo opencti-connector-narrowcti python -m py_compile connectors/otx/connector.py connectors/otx/entity_extraction.py connectors/otx/feed_adapter.py connectors/otx/models.py connectors/otx/processor.py connectors/otx/runtime.py connectors/otx/settings.py connectors/otx/otx_client.py connectors/misp/client.py connectors/misp/connector.py connectors/misp/feed_adapter.py connectors/misp/models.py connectors/misp/processor.py connectors/misp/runtime.py connectors/misp/settings.py core/decision_audit.py core/feed_contract.py core/graph_candidates.py core/graph_evidence.py core/indicator_policy.py core/mitre_attack.py core/quarantine.py core/scoring.py core/policy.py core/state_repository.py core/tlp.py exporters/opencti.py exporters/stix_builder.py
docker run --rm -v "${LAB_ROOT}\NarrowCTI:/repo" -w /repo opencti-connector-narrowcti python -m py_compile gateway/preflight.py gateway/report.py gateway/decisions.py gateway/correlation.py gateway/mitre.py gateway/quarantine.py gateway/quarantine_export.py
docker run --rm -v "${LAB_ROOT}\NarrowCTI:/repo" -w /repo opencti-connector-narrowcti python -m unittest discover -s tests -v
```

## Release Flow

The project uses `dev` as the integration branch and `main` as the stable branch.
Official versions should be marked with Git tags.

```text
feature/refactor branch -> dev -> main -> version tag
```

Current development track:

```text
v0.8.0-dev
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
docs/release-v0.5.0.md
docs/release-v0.6.0.md
docs/release-v0.7.0.md
docs/release-v0.8.0.md
docs/graph-promotion-v0.8.md
docs/deployment-operations-v0.8.md
docs/analyst-review-v0.8.md
docs/quarantine-enrichment-v0.6.md
docs/architecture-v0.7.md
docs/graph-enrichment-v0.7.md
docs/mitre-curation-architecture-v0.7.md
docs/metadata-validation-v0.7.md
docs/contextual-scoring-reference-v0.7.md
docs/source-ingestion-modes-v0.7.md
docs/misp-official-connector-mapping-v0.7.md
docs/otx-official-connector-mapping-v0.7.md
docs/gateway-runtime-v0.5.md
docs/configuration-reference-v0.6.md
docs/configuration-reference-v0.5.md
docs/enterprise-intelligence-gateway-v0.5.md
docs/product-architecture-validation-v0.5.md
docs/market-positioning-v1.0.md
docs/post-v1-ml-roadmap.md
docs/roadmap.md
docs/licensing-strategy.md
```

## Roadmap

- Product foundation and commercial licensing structure.
- v0.8 preflight-visible edition and feature gate inventory for offline-first
  commercial packaging.
- Multi-feed support beyond the reference OTX adapter.
- Advanced correlation scoring and analyst-facing source evidence.
- Richer scoring model with source-specific weighting.
- Sigma or detection-rule generation.
- Administrative controls for policy tuning.
- Quarantine review and analyst release workflow.
- Enterprise filters for actor, arsenal, MITRE ATT&CK, victimology and graph
  state.
- Post-v1.0 ML-assisted curation for aliases, relationship suggestions,
  semantic deduplication and prioritization after the deterministic v1.0 engine
  is stable.

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
