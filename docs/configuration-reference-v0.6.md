# Configuration Reference - v0.6.0

## Purpose

This reference documents the configuration surface added or promoted by the
v0.6 quarantine and enrichment foundation. It extends the base gateway controls
from `docs/configuration-reference-v0.5.md`.

The operating model remains:

```text
visible configuration
  -> policy limits, source scope, review workflow and enrichment posture

automatic curation engine
  -> normalize, score, decide, quarantine, deduplicate, audit and export
```

Operators should be able to understand the NarrowCTI intake boundary from
environment variables, then rely on the gateway to apply those controls
consistently and record evidence.

## Quarantine Review Controls

| Variable | Purpose |
| --- | --- |
| `NARROWCTI_QUARANTINE_REPOSITORY` | Shared local JSONL repository where OTX and MISP can queue policy-quarantined candidates for review. |
| `OTX_QUARANTINE_REPOSITORY` | OTX-specific override for the quarantine repository. Defaults to `NARROWCTI_QUARANTINE_REPOSITORY` when unset. |
| `MISP_QUARANTINE_REPOSITORY` | MISP-specific override for the quarantine repository. Defaults to `NARROWCTI_QUARANTINE_REPOSITORY` when unset. |
| `NARROWCTI_RELEASE_AUDIT_FILE` | JSONL audit file for analyst release, partial release, reject and export evidence. |
| `NARROWCTI_RELEASE_QUARANTINE_REQUIRES_REASON` | Requires a review reason before release or rejection. Default should remain `true` for governed environments. |
| `NARROWCTI_REVIEWER` | Default reviewer identity used by the quarantine CLI when `--reviewer` is not provided. |
| `NARROWCTI_QUARANTINE_RAW_SNAPSHOT_MAX_BYTES` | Maximum raw source payload snapshot retained in quarantine evidence. Oversized snapshots are truncated. |

Quarantine is not a dead end. It is the governed path for intelligence that may
be important but should not enter OpenCTI automatically. Analysts can review,
release, partially release, reject and replay records with audit evidence.

## Enrichment Controls

| Variable | Purpose |
| --- | --- |
| `NARROWCTI_ENABLE_OTX_ENTITY_EXTRACTION` | Extracts metadata-only OTX evidence for adversaries, malware families, ATT&CK ids, industries, countries, TLP, references and tags. |
| `NARROWCTI_ENABLE_MITRE_ATTACK_RESOLUTION` | Resolves extracted ATT&CK ids through the local MITRE cache when available. Missing cache records evidence instead of blocking ingestion. |
| `NARROWCTI_MITRE_CACHE_FILE` | Local normalized ATT&CK cache used by preflight and OTX metadata enrichment. |
| `NARROWCTI_MITRE_STIX_URL` | ATT&CK STIX bundle URL used by `gateway.mitre refresh-cache`. |

MITRE ATT&CK is treated as reference data in v0.6, not as an ingest feed. The
cache enriches source evidence so later releases can build graph objects and
enterprise filters with provenance.

## Source Examples

Gateway-level review repository shared by enabled sources:

```env
NARROWCTI_QUARANTINE_REPOSITORY=/app/state/quarantine.jsonl
NARROWCTI_RELEASE_AUDIT_FILE=/app/state/audit/releases.jsonl
NARROWCTI_RELEASE_QUARANTINE_REQUIRES_REASON=true
NARROWCTI_REVIEWER=operator
NARROWCTI_QUARANTINE_RAW_SNAPSHOT_MAX_BYTES=65536
```

OTX-specific enrichment posture:

```env
OTX_QUARANTINE_REPOSITORY=/app/state/quarantine.jsonl
NARROWCTI_ENABLE_OTX_ENTITY_EXTRACTION=true
NARROWCTI_ENABLE_MITRE_ATTACK_RESOLUTION=true
NARROWCTI_MITRE_CACHE_FILE=/app/state/mitre_attack_cache.json
NARROWCTI_MITRE_STIX_URL=https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json
```

MISP-specific review posture:

```env
MISP_QUARANTINE_REPOSITORY=/app/state/quarantine.jsonl
MISP_DRY_RUN=true
MISP_RUN_ONCE=true
MISP_MAX_EVENTS_PER_RUN=1
MISP_MAX_ATTRIBUTES_PER_EVENT=1000
MISP_MAX_IOCS_PER_EVENT=1000
MISP_OVERSIZED_EVENT_ACTION=skip
```

For constrained labs, keep MISP dry-run and bounded until decision audit,
quarantine volume and OpenCTI/Elasticsearch capacity are understood.

## Operational Commands

```powershell
python -m gateway.quarantine --repository state\quarantine.jsonl list --status pending
python -m gateway.quarantine --repository state\quarantine.jsonl show --id <quarantine-id>
python -m gateway.quarantine --repository state\quarantine.jsonl --release-audit-file state\audit\releases.jsonl release --id <quarantine-id> --reason "Relevant to monitored scope"
python -m gateway.quarantine --repository state\quarantine.jsonl --release-audit-file state\audit\releases.jsonl release-indicators --id <quarantine-id> --type domain,url --reason "High-value observables"
python -m gateway.quarantine --repository state\quarantine.jsonl --release-audit-file state\audit\releases.jsonl reject --id <quarantine-id> --reason "Out of scope"
python -m gateway.quarantine --repository state\quarantine.jsonl export-released --id <quarantine-id>
python -m gateway.quarantine --release-audit-file state\audit\releases.jsonl audit --limit 20
```

`export-released` is dry-run by default. Use `--execute` only after OpenCTI
capacity, deduplication posture and review evidence are acceptable.

## Validation

Before promoting v0.6, run:

```powershell
.\scripts\validate-v0.6.ps1
python -m gateway.preflight
python -m gateway.report --file state\gateway_runs.jsonl --quarantine-file state\quarantine.jsonl
python -m gateway.quarantine --release-audit-file state\audit\releases.jsonl audit --limit 20
```

The validation goal is to prove that quarantine records are created, review
actions are audited, released records remain dry-run by default and enrichment
gaps such as a missing MITRE cache are warnings instead of ingest blockers.
