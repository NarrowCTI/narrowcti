# NarrowCTI v0.5.0 Release Notes

## Status

`v0.5.0` is the gateway runtime and decision engine release. It promotes
NarrowCTI from source-specific connector execution into a unified gateway
runtime that orchestrates enabled sources while preserving source isolation,
state, audit evidence, guardrails and failure reporting.

The release keeps OTX and MISP source-specific runtimes available for debugging,
bounded validation and controlled backfill. MISP remains opt-in and guarded.

## Highlights

- Adds the unified `gateway.connector` runtime.
- Adds gateway settings under the `NARROWCTI_*` namespace.
- Adds a source registry that can orchestrate OTX and MISP.
- Preserves source-scoped state and decision audit files.
- Adds failure isolation so one source failure does not stop the whole gateway.
- Adds `Dockerfile.gateway` for the product gateway image.
- Adds layered graph-hygiene controls with local artifact deduplication and
  optional OpenCTI indicator lookup.
- Adds preflight validation for enabled sources, dry-run posture, deduplication,
  OpenCTI lookup and evidence paths.
- Adds aggregate gateway run summaries in JSONL.
- Adds operational reporting for run totals, source failures, per-source
  outcomes, per-query outcomes and directional value metrics.
- Adds decision audit reporting by action, reason, source, query and score
  bands, including recent quarantined candidates.
- Adds artifact correlation reporting from the local deduplication index.
- Documents enterprise curation direction for actor, arsenal, MITRE ATT&CK,
  victimology, quarantine release and graph enrichment.

## Operational Validation

Validation was performed on 2026-06-22 with the rebuilt gateway image:

```text
narrowcti-gateway:v0.5-validation
```

Preflight passed for an OTX-only controlled run:

```text
ok=true
enabled_sources=otx
dedup_mode=hybrid
opencti_dedup_lookup=false
otx.dry_run=true
otx.state_file=/app/state/validation-v0.5/otx_state.json
otx.decision_audit_file=/app/state/validation-v0.5/audit/otx_decisions.jsonl
```

Preflight also passed for OTX and MISP source posture:

```text
ok=true
enabled_sources=otx,misp
dedup_mode=hybrid
otx.dry_run=true
misp.dry_run=true
```

A first OTX gateway execution outside the OpenCTI Docker network failed to
resolve the `opencti` hostname. The gateway recorded the failure without
crashing the process, proving source failure capture in the aggregate summary.

The execution was repeated inside the shared `threat-net` Docker network. The
gateway reached OpenCTI, queried OTX and processed one `lummac2` candidate in a
bounded dry-run. The candidate was dropped by policy because it was older than
the configured age threshold:

```text
reviewed=1
ingested=0
dropped=1
reason=old pulse with low score (1260d > 1095d and score 75 < 80)
```

For real OpenCTI visibility, one controlled non-dry-run OTX execution was then
performed with explicit bounds:

```text
NARROWCTI_ENABLED_SOURCES=otx
OTX_QUERIES=lummac2
MAX_SEARCH_RESULTS_PER_QUERY=1
MAX_PULSES_PER_QUERY=1
MAX_IOCS_PER_PULSE=50
MAX_DAYS_OLD=2000
MIN_SCORE_FOR_OLD_PULSE=70
NARROWCTI_DEDUP_MODE=hybrid
NARROWCTI_OPENCTI_DEDUP_LOOKUP=false
```

Result:

```text
Candidate: LummaC2 Stealer: A Potent Threat to Crypto Users
score=75
indicators_before_type_filter=12
indicators_after_type_filter=4
ingested=1
artifact_dedup_added=4
```

MISP was also validated with one controlled non-dry-run execution and explicit
resource bounds:

```text
NARROWCTI_ENABLED_SOURCES=misp
MISP_QUERIES=*
MISP_FROM_DATE=2016-01-01
MISP_TO_DATE=2016-12-31
MISP_TAGS=tlp:green
MISP_MAX_EVENTS_PER_RUN=1
MISP_MAX_ATTRIBUTES_PER_EVENT=1000
MISP_MAX_IOCS_PER_EVENT=50
MISP_OVERSIZED_EVENT_ACTION=skip
MAX_DAYS_OLD=5000
MIN_SCORE_FOR_OLD_EVENT=30
MIN_SCORE_TO_INGEST=30
QUARANTINE_SCORE_THRESHOLD=20
```

Result:

```text
Candidate: OSINT - New Hacking team samples (OSX)
score=30
indicators_before_type_filter=7
indicators_after_type_filter=3
ingested=1
artifact_dedup_added=3
```

The final operational report summarized four validation runs:

```text
run_count=4
reviewed=3
ingested=2
dropped=1
accepted=2
filtered=1
acceptance_rate_pct=66.67
filter_rate_pct=33.33
otx query=lummac2 reviewed=2 ingested=1 dropped=1
misp query=* reviewed=1 ingested=1
```

The final decision audit report summarized:

```text
record_count=3
actions=ingest=2 drop=1 quarantine=0 skip=0 dry-run=0 error=0
alienvault:otx query=lummac2 records=2 score=75
misp:misp query=* records=1 score=30
```

The artifact correlation report confirmed the local deduplication index:

```text
artifact_count=7
record_count=7
correlated_count=0
source=alienvault:otx artifacts=4
source=misp:misp artifacts=3
```

Evidence was written under local validation paths:

```text
state/validation-v0.5/gateway_runs.jsonl
state/validation-v0.5/audit/otx_decisions.jsonl
state/validation-v0.5/audit/misp_decisions.jsonl
state/validation-v0.5/dedup_index.json
state/validation-v0.5/otx_state.json
state/validation-v0.5/misp_state.json
```

## Test Validation

Final release validation should include:

```powershell
docker build -f Dockerfile.gateway -t narrowcti-gateway:v0.5-validation .

docker run --rm -v "${LAB_ROOT}\NarrowCTI:/repo" -w /repo opencti-connector-narrowcti python -m py_compile connectors/otx/connector.py connectors/otx/feed_adapter.py connectors/otx/models.py connectors/otx/processor.py connectors/otx/runtime.py connectors/otx/settings.py connectors/otx/otx_client.py connectors/misp/client.py connectors/misp/connector.py connectors/misp/feed_adapter.py connectors/misp/models.py connectors/misp/processor.py connectors/misp/runtime.py connectors/misp/settings.py core/decision_audit.py core/feed_contract.py core/indicator_policy.py core/scoring.py core/policy.py core/state_repository.py core/tlp.py exporters/opencti.py exporters/stix_builder.py

docker run --rm -v "${LAB_ROOT}\NarrowCTI:/repo" -w /repo opencti-connector-narrowcti python -m py_compile gateway/preflight.py gateway/report.py gateway/decisions.py gateway/correlation.py

docker run --rm -v "${LAB_ROOT}\NarrowCTI:/repo" -w /repo opencti-connector-narrowcti python -m unittest discover -s tests -v
```

## Release Boundaries

- Direct OTX and MISP runtimes remain supported for troubleshooting.
- MISP remains bounded, opt-in and dry-run-first by default.
- Broad MISP historical backfill is not part of this release.
- The quarantine repository and analyst release workflow move to v0.6.
- MITRE cache, entity extraction and graph enrichment move to later releases.
- Customer-facing UI, commercial activation and enterprise CTI report output are
  not included in v0.5.0.

## Next Release Direction

The next release should focus on quarantine and enrichment foundations:

- Quarantine repository.
- CLI review, reject and release workflow.
- Release audit records.
- OTX entity extraction for adversary, malware families, ATT&CK ids,
  industries, countries, TLP and references.
- Local MITRE ATT&CK cache and technique/tactic resolver.
