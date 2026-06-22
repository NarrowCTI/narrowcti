# Quarantine And Enrichment Foundation - v0.6.0

## Purpose

The v0.6.0 track starts the first reviewable quarantine and enrichment
foundation for NarrowCTI. v0.5 proved that the unified gateway can orchestrate
OTX and MISP, make explainable decisions, report outcomes and ingest bounded
real data into OpenCTI. v0.6 should make held intelligence operationally useful
instead of treating quarantine as only an audit action.

The product goal is to keep NarrowCTI aligned with its role as the pre-ingestion
decision gateway in front of OpenCTI:

```text
source candidate
  -> normalize
  -> score and decide
  -> quarantine when uncertain or policy-blocked
  -> analyst release or reject
  -> audit release action
  -> export through the same OpenCTI pipeline
```

## Product Standard

Quarantine must be governed and explainable. A candidate held by NarrowCTI
should preserve enough evidence for an operator to answer:

- What source produced it?
- Why was it held?
- Which policy, score or guardrail caused the decision?
- Which indicators and source entities would be released?
- Who released or rejected it, when and why?
- Did release preserve deduplication and source provenance?

The v0.6 implementation should stay local and CLI-first. A future API or UI can
build on the same repository and audit model.

## Scope

In scope for v0.6:

- Local quarantine repository.
- CLI review commands for pending, released and rejected candidates.
- Release, partial release and reject actions with required reasons.
- Release audit records.
- Automatic quarantine repository writes from OTX and MISP policy decisions.
- Replay of released candidates through the existing STIX/export path.
- OTX entity extraction groundwork for adversary, malware families, ATT&CK ids,
  industries, targeted countries, TLP and references.
- Local MITRE ATT&CK cache and technique/tactic resolver foundation.
- Operator reporting that can include quarantine and release outcomes.

Out of scope for v0.6:

- Customer-facing UI.
- Enterprise policy UI.
- Full graph enrichment export for actors, malware, tools, sectors and
  locations.
- Relationship confidence engine.
- License enforcement.
- Broad MISP backfill by default.

## Quarantine Repository

The repository should be append-friendly and easy to inspect locally. JSONL is
acceptable for the first implementation; SQLite can be introduced later if
querying and status updates become awkward.

Target record fields:

| Field | Meaning |
| --- | --- |
| `quarantine_id` | Stable local id for review commands. |
| `status` | `pending`, `released`, `partially-released`, `rejected` or `expired`. |
| `source_key` | Source identity such as `alienvault:otx` or `misp:misp`. |
| `external_id` | Source object id, pulse id, event uuid or equivalent. |
| `query` | Source query that surfaced the candidate. |
| `title` | Candidate title or name. |
| `reason` | Decision reason that caused quarantine. |
| `score` | Final curation score. |
| `age_days` | Candidate age at decision time when available. |
| `indicator_count` | Original indicator count before release filtering. |
| `indicators` | Candidate indicators preserved for review. |
| `metadata` | Scoring, provenance, guardrail, TLP and source metadata. |
| `raw_snapshot` | Bounded source payload snapshot for review. |
| `created_at` | Quarantine timestamp. |
| `updated_at` | Last state transition timestamp. |
| `review` | Reviewer, reason, released types and release metadata. |

The repository must not silently overwrite historical review records. New
quarantine writes are idempotent by stable `quarantine_id`, so repeated source
runs do not duplicate the pending queue or reopen records already reviewed.
State transitions should be audit-friendly.

## CLI Target

Initial commands:

```text
python -m gateway.quarantine list --status pending
python -m gateway.quarantine show --id <quarantine-id>
python -m gateway.quarantine reject --id <quarantine-id> --reason "Out of scope"
python -m gateway.quarantine release --id <quarantine-id> --reason "Relevant to monitored actor"
python -m gateway.quarantine release-indicators --id <quarantine-id> --type filehash-sha256,url --reason "High-value indicators"
python -m gateway.quarantine export-released --id <quarantine-id>
python -m gateway.quarantine export-released --id <quarantine-id> --execute --dedup-state-file /app/state/dedup_index.json
```

Behavior:

- `list` must be read-only.
- `show` must expose source, reason, score, indicators and metadata.
- `reject` must require a reason.
- `release` must require a reason and write release approval evidence.
- Partial release must preserve which indicators were released and which stayed
  held.
- Every state transition must write release audit evidence.
- `export-released` must be dry-run by default and require `--execute` for
  OpenCTI import.
- Export replay must use the released indicator subset, preserve deduplication
  and mark the quarantine record as exported only after successful execution or
  confirmed dedup-skip.

The initial v0.6 implementation provides the local JSONL repository, automatic
OTX/MISP quarantine writes, CLI state transitions, release audit records and
controlled export replay for released records through the existing STIX/OpenCTI
path. Rich graph enrichment remains a later integration step.

## Enrichment Foundation

v0.6 should not pretend to export the full enterprise graph. It should extract
and normalize entity hints so v0.7 can safely build richer STIX/OpenCTI objects.

Target OTX fields:

| OTX field | v0.6 use |
| --- | --- |
| `adversary` | Actor or cluster hint with source provenance. |
| `malware_families` | Malware family hint for future arsenal graphing. |
| `attack_ids` | ATT&CK technique ids for MITRE resolver. |
| `industries` | Target-sector hint. |
| `targeted_countries` | Geography/victimology hint. |
| `TLP` | Marking and handling evidence. |
| `references` | External references for report context. |
| `tags` | Weak labels and extraction candidates. |

The output should be metadata and normalized extraction records first. STIX
object expansion for actors, malware, attack patterns, sectors and locations is
a v0.7 responsibility unless a narrow helper is required to validate the v0.6
cache.

## MITRE ATT&CK Cache

The MITRE cache should be treated as reference data, not as an intelligence feed.

Target cache inputs:

- ATT&CK STIX bundles.
- Technique and sub-technique objects.
- Tactic phases on techniques.
- Group, software and relationship objects for later enrichment.

Target v0.6 behavior:

- Load or refresh a local ATT&CK cache from a configured path or URL.
- Resolve `attack_ids` such as `T1059` into technique name and tactics.
- Keep cache refresh explicit and auditable.
- Avoid blocking ingestion when the cache is unavailable; record missing
  enrichment evidence instead.

## Configuration Direction

Candidate variables:

```env
NARROWCTI_QUARANTINE_REPOSITORY=/app/state/quarantine.jsonl
OTX_QUARANTINE_REPOSITORY=/app/state/quarantine.jsonl
MISP_QUARANTINE_REPOSITORY=/app/state/quarantine.jsonl
NARROWCTI_RELEASE_AUDIT_FILE=/app/state/audit/releases.jsonl
NARROWCTI_RELEASE_QUARANTINE_REQUIRES_REASON=true
NARROWCTI_REVIEWER=operator
NARROWCTI_QUARANTINE_RAW_SNAPSHOT_MAX_BYTES=65536
NARROWCTI_ENABLE_OTX_ENTITY_EXTRACTION=true
NARROWCTI_MITRE_CACHE_FILE=/app/state/mitre_attack_cache.json
NARROWCTI_MITRE_STIX_URL=https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json
```

## Validation Plan

Minimum validation for v0.6:

- Unit tests for repository write/read/status transitions.
- Unit tests for release and reject commands.
- Unit tests proving release requires a reason when configured.
- Unit tests proving partial release filters indicator types safely.
- Unit tests for release audit records.
- Unit tests proving OTX and MISP quarantine decisions write pending repository
  records without export or state marking.
- CLI validation for list, show, reject, release and partial release.
- CLI validation for dry-run released-record replay.
- Unit tests for released-record export, partial release export and dedup-skip
  export marking.
- Unit tests for OTX entity extraction from representative pulse payloads.
- Unit tests for MITRE technique/tactic resolver.
- Local dry-run validation showing quarantine records are created.
- Controlled release validation showing a quarantined candidate can be exported
  once through the same deduplication and OpenCTI export path.

## Success Criteria

- Quarantined intelligence is preserved as reviewable evidence.
- OTX and MISP decisions that return `quarantine` create pending review records
  automatically.
- Operators can list, inspect, release and reject held candidates locally.
- Release actions are audited with reviewer reason and timestamp.
- Released candidates can be replayed through existing STIX building, OpenCTI
  export and deduplication controls.
- OTX entity extraction creates structured metadata for future graph enrichment.
- MITRE technique ids can be resolved to names and tactics through a local cache.
- v0.6 improves governance without weakening the v0.5 safety posture.
