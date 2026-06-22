# Configuration Reference - v0.5.0

## Purpose

NarrowCTI must make curation controls visible, configurable and auditable. The
operator should be able to understand which intelligence is allowed into the
pipeline by reading configuration, while the gateway automatically applies the
normalization, scoring, policy, deduplication, audit and export workflow.

The product rule is:

```text
visible configuration
  -> filters, thresholds, limits, dry-run and source selection

automatic curation engine
  -> normalize, score, decide, deduplicate, audit and export
```

This keeps NarrowCTI usable as a professional CTI gateway instead of a hidden
black-box connector.

## Naming Model

The v0.5 gateway should use clear configuration namespaces:

```text
NARROWCTI_*   gateway-level runtime, policy and curation controls
OTX_*         OTX-specific connection, query and source behavior
MISP_*        MISP-specific connection, filters, guardrails and source behavior
```

Current source-specific runtimes already implement several controls. Some policy
variables are still shared names such as `MIN_SCORE_TO_INGEST` and
`ENABLE_QUARANTINE`; v0.5 should map them into gateway-level `NARROWCTI_*`
settings while preserving backward compatibility during the transition.

## Current Implemented Curation Controls

### Shared Policy Controls

These variables are currently used by OTX and MISP processors.

| Variable | Purpose |
| --- | --- |
| `MIN_SCORE_TO_INGEST` | Minimum score required for normal ingest. |
| `MAX_DAYS_OLD` | Age threshold used by the policy engine for older intelligence. |
| `MIN_SCORE_FOR_OLD_PULSE` | OTX score required when a pulse is older than `MAX_DAYS_OLD`. |
| `MIN_SCORE_FOR_OLD_EVENT` | MISP score required when an event is older than `MAX_DAYS_OLD`. |
| `MAX_DAYS_HARD_FILTER` | Optional hard age filter; `0` disables it. |
| `ENABLE_QUARANTINE` | Sends low-score candidates to quarantine instead of dropping them when enabled. |
| `QUARANTINE_SCORE_THRESHOLD` | Score below which candidates become quarantine/drop decisions. |
| `DECISION_AUDIT_FILE` | OTX decision audit JSONL output path. |
| `MISP_DECISION_AUDIT_FILE` | MISP decision audit JSONL output path. |

### OTX Controls

| Variable | Purpose |
| --- | --- |
| `OTX_QUERIES` | Comma-separated OTX search terms. |
| `MAX_SEARCH_RESULTS_PER_QUERY` | Maximum OTX search candidates reviewed per query. |
| `MAX_PULSES_PER_QUERY` | Maximum OTX pulses ingested per query. |
| `MAX_IOCS_PER_PULSE` | Maximum indicators exported from a single OTX pulse. |
| `OTX_DRY_RUN` | Exercises OTX search, enrichment, scoring, policy and audit without OpenCTI export. |
| `STATE_FILE` | Local OTX processed-pulse state file. |

### MISP Controls

| Variable | Purpose |
| --- | --- |
| `MISP_QUERIES` | MISP search query or wildcard query. |
| `MISP_FROM_DATE` | Lower bound for controlled historical backfill. |
| `MISP_TO_DATE` | Upper bound for controlled historical backfill. |
| `MISP_TAGS` | MISP tag filter, commonly used for TLP such as `tlp:green`. |
| `MISP_PUBLISHED_ONLY` | Restricts import candidates to published MISP events when enabled. |
| `MISP_DRY_RUN` | Exercises search, enrichment, scoring, policy and audit without OpenCTI export. |
| `MISP_RUN_ONCE` | Runs one bounded cycle and exits. |
| `MISP_MAX_EVENTS_PER_RUN` | Maximum MISP events processed per run. |
| `MISP_MAX_ATTRIBUTES_PER_EVENT` | Metadata-first guardrail for event size before enrichment. |
| `MISP_MAX_IOCS_PER_EVENT` | Maximum indicators exported from a single MISP event. |
| `MISP_OVERSIZED_EVENT_ACTION` | Oversized event behavior: `skip` by default, `truncate` for controlled tests. |
| `MISP_STATE_FILE` | Local MISP processed-event state file. |

## Target v0.5 Gateway Controls

These settings define the target gateway configuration model. They should be
implemented by the unified runtime and documented in `.env.example` files once
supported by code.

| Variable | Purpose |
| --- | --- |
| `NARROWCTI_MODE` | Runtime mode, usually `gateway`. |
| `NARROWCTI_ENABLED_SOURCES` | Comma-separated enabled sources such as `otx,misp`. |
| `NARROWCTI_DRY_RUN` | Gateway-level dry-run default for enabled sources. |
| `NARROWCTI_RUN_ONCE` | Gateway-level run-once behavior. |
| `NARROWCTI_SOURCE_INTERVAL_SECONDS` | Gateway loop interval between source runs. |
| `NARROWCTI_STATE_DIR` | Base directory for source state and gateway indexes. |
| `NARROWCTI_DECISION_AUDIT_DIR` | Base directory for decision audit output. |
| `NARROWCTI_MIN_SCORE_TO_INGEST` | Gateway-level default minimum score. |
| `NARROWCTI_ENABLE_QUARANTINE` | Gateway-level quarantine default. |
| `NARROWCTI_QUARANTINE_SCORE_THRESHOLD` | Gateway-level quarantine threshold. |
| `NARROWCTI_MAX_DAYS_OLD` | Gateway-level age threshold. |
| `NARROWCTI_ALLOWED_TLP` | Allowed TLP values before source-specific mapping. |
| `NARROWCTI_DEDUP_MODE` | Deduplication mode. `source` keeps source-item state only; `artifact` or `hybrid` enables the local artifact fingerprint index. |
| `NARROWCTI_OPENCTI_DEDUP_LOOKUP` | Enables optional OpenCTI STIX Indicator pattern lookup before export. Lookup errors are logged and fail open. |
| `NARROWCTI_DEDUP_STATE_FILE` | Local artifact index used by `artifact` and `hybrid` modes. It stores `artifact_fingerprints` for skip decisions and `artifact_records` for source sightings/correlation metadata. |

## Target Enterprise Curation Controls

These controls are not all implemented yet. They define the enterprise filter
surface that should be introduced after quarantine release and entity extraction
are available.

| Variable | Purpose |
| --- | --- |
| `NARROWCTI_ALLOWED_INDICATOR_TYPES` | Allows only selected indicator or observable classes. |
| `NARROWCTI_CRITICAL_INDICATOR_TYPES` | Indicator classes that can receive criticality override scoring. |
| `NARROWCTI_HIGH_VALUE_TAGS` | Tags that increase priority or bypass low-context drops. |
| `NARROWCTI_ALLOWED_ATTACK_PATTERN_IDS` | ATT&CK technique/sub-technique ids allowed by policy. |
| `NARROWCTI_ALLOWED_MITRE_TACTICS` | ATT&CK tactics allowed by policy. |
| `NARROWCTI_ALLOWED_THREAT_ACTORS` | Actor, group or intrusion-set names allowed by policy. |
| `NARROWCTI_ALLOWED_MALWARE_FAMILIES` | Malware family names allowed by policy. |
| `NARROWCTI_ALLOWED_TARGET_SECTORS` | Victimology filter for sectors or industries. |
| `NARROWCTI_ALLOWED_TARGET_COUNTRIES` | Victimology filter for countries or regions. |
| `NARROWCTI_MIN_CORROBORATING_SOURCES` | Minimum source corroboration before automatic ingest. |
| `NARROWCTI_QUARANTINE_REPOSITORY` | Future repository for reviewable quarantined candidates. |
| `NARROWCTI_RELEASE_QUARANTINE_REQUIRES_REASON` | Requires analyst release reason before export. |

Detailed behavior and backlog placement are documented in
`docs/enterprise-intelligence-gateway-v0.5.md`.

## Example Safe Local MISP Backfill

```env
MISP_DRY_RUN=true
MISP_RUN_ONCE=true
MISP_QUERIES=*
MISP_FROM_DATE=2026-06-01
MISP_TO_DATE=2026-06-21
MISP_TAGS=tlp:green
MISP_PUBLISHED_ONLY=true
MISP_MAX_EVENTS_PER_RUN=1
MISP_MAX_ATTRIBUTES_PER_EVENT=1000
MISP_MAX_IOCS_PER_EVENT=1000
MISP_OVERSIZED_EVENT_ACTION=skip
MIN_SCORE_TO_INGEST=60
ENABLE_QUARANTINE=true
QUARANTINE_SCORE_THRESHOLD=50
```

## Example Target Gateway Policy

```env
NARROWCTI_MODE=gateway
NARROWCTI_ENABLED_SOURCES=otx,misp
NARROWCTI_DRY_RUN=true
NARROWCTI_RUN_ONCE=true
NARROWCTI_MIN_SCORE_TO_INGEST=60
NARROWCTI_ENABLE_QUARANTINE=true
NARROWCTI_QUARANTINE_SCORE_THRESHOLD=50
NARROWCTI_ALLOWED_TLP=white,green
NARROWCTI_MAX_DAYS_OLD=365
NARROWCTI_DEDUP_MODE=hybrid
NARROWCTI_OPENCTI_DEDUP_LOOKUP=false
NARROWCTI_ALLOWED_INDICATOR_TYPES=ipv4,ipv6,domain,hostname,url,filehash-sha256,cve
NARROWCTI_ALLOWED_MITRE_TACTICS=initial-access,execution,command-and-control
NARROWCTI_ALLOWED_TARGET_SECTORS=finance,government,healthcare,energy
NARROWCTI_RELEASE_QUARANTINE_REQUIRES_REASON=true
```

## Automatic Behavior

The following behavior is intentionally automatic and should remain auditable:

- Normalize source data into the shared feed contract.
- Calculate contextual score.
- Apply policy and produce ingest, drop, quarantine, skip, dry-run or error
  decisions.
- Deduplicate source items and artifact fingerprints, then record source sightings for exported artifacts when artifact or hybrid deduplication is enabled.
- Build STIX bundles after curation.
- Export to OpenCTI only after policy and deduplication pass.
- Write decision evidence and runtime summaries.
- Preserve quarantined candidates for future analyst review and release when the
  quarantine repository is implemented.

Operators configure the boundaries. NarrowCTI executes the curation workflow and
records why each candidate was accepted, rejected, skipped or held for review.
