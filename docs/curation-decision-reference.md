# Curation Decision Reference

This document explains how NarrowCTI turns configuration and source evidence
into operator-visible decisions.

## Decision Pipeline

```text
source candidate
  -> source state and basic validation
  -> TLP and indicator-type filters
  -> scoring
  -> policy decision
  -> deduplication
  -> dry-run / quarantine / export
  -> audit evidence
```

Every decision should be visible in decision audit, run summaries, reports or
quarantine records.

## Score Calculation

The base score starts at `40`.

| Signal | Effect |
| --- | --- |
| Source confidence | `OTX_SOURCE_CONFIDENCE` or `MISP_SOURCE_CONFIDENCE`; `50` is neutral. Every 5 points above/below 50 adds/subtracts 1 score point. |
| Query in title | Exact query in title adds `15`; query term in title adds `10`. |
| Query in tags | Exact query in tag adds `10`; query term in tag adds `5`. |
| Indicator volume | `10..500` indicators adds `20`; `501..2000` adds `10`; more than `2000` subtracts `10`. |
| Recency | `<30d` adds `20`; `<90d` adds `10`; `>365d` subtracts `10`. |

The final score is clamped to `0..100`.

Contextual scoring evidence can also be recorded from graph candidates, but in
the current v0.8 posture it is audit/report evidence and does not silently
bypass policy.

## Policy Matrix

| Condition | Decision | Reason |
| --- | --- | --- |
| Candidate missing required source id or enrichment fails | `skip` or `error` | Source item cannot be safely processed. |
| Candidate already processed in source state | `skip` | Source deduplication prevents repeated processing. |
| `MAX_DAYS_HARD_FILTER > 0` and candidate age exceeds it | `drop` | Hard age cutoff. |
| Score `< NARROWCTI_QUARANTINE_SCORE_THRESHOLD` and quarantine enabled | `quarantine` | Low score, analyst review required. |
| Score `< NARROWCTI_QUARANTINE_SCORE_THRESHOLD` and quarantine disabled | `drop` | Very low score. |
| Score `< NARROWCTI_MIN_SCORE_TO_INGEST` | `drop` | Below minimum score. |
| Candidate age `> NARROWCTI_MAX_DAYS_OLD` and score below old-item threshold | `drop` | Old intelligence with insufficient score. |
| TLP tag exists and is not in `NARROWCTI_ALLOWED_TLP` | `drop` | Handling policy denies export. |
| Indicator type filtering removes all exportable indicators | `skip` | Nothing safe remains to export. |
| Artifact deduplication finds all indicators already known | `skip` | Avoids duplicate OpenCTI indicator noise. |
| Artifact deduplication finds all indicators known and graph replay is enabled for bounded MISP export | graph-only export path | Replays improved graph context without indicator objects. |
| Dry-run is enabled after policy passes | `dry-run` | Would ingest/export, but OpenCTI is not mutated. |
| Policy passes, deduplication passes and dry-run is disabled | `ingest` / `export` | Candidate can be exported to OpenCTI. |

## Graph Export Matrix

| `NARROWCTI_GRAPH_EXPORT_MODE` | Behavior |
| --- | --- |
| `audit` | Records graph candidate policy and held reasons only. No graph objects are added to the STIX bundle. |
| `dry-run` | Records what graph objects and relationships would be created. Does not mark graph state as exported. |
| `export` | Adds accepted graph objects and relationships to the OpenCTI import path after policy and deduplication pass. |

In `export` mode, empty graph allow-lists use safe defaults. NarrowCTI promotes
source-backed CTI objects such as sectors, locations, arsenal, ATT&CK,
infrastructure, ASN, observables, vulnerabilities and reports while holding
collector/source identity, labels and markings unless explicitly allow-listed.

## OpenCTI Lookup and Deduplication

| Control | Decision impact |
| --- | --- |
| `NARROWCTI_OPENCTI_DEDUP_LOOKUP=true` | Checks existing OpenCTI Indicators by pattern before export. Lookup errors fail open. |
| `NARROWCTI_OPENCTI_GRAPH_LOOKUP=true` | Checks canonical OpenCTI graph objects before creating new graph objects. Matches are referenced instead of duplicated when a valid STIX id is available. |
| `NARROWCTI_GRAPH_DEDUP_STATE_FILE` | Reads local graph known keys and marks newly exported graph keys only after successful OpenCTI import. |
| `NARROWCTI_DEDUP_MODE=hybrid` | Combines source-item deduplication with artifact fingerprint correlation. |

## Quarantine Decisions

Quarantine is for intelligence that may matter but should not enter OpenCTI
automatically.

Quarantined records preserve:

- source identity;
- query;
- score and score details;
- policy reason;
- indicators;
- graph evidence and graph candidates when available;
- bounded raw snapshot;
- reviewer release/reject/export audit.

`export-released` remains dry-run by default. Use `--execute` only after review
and capacity checks.

## How Operators Validate Decisions

Use:

```powershell
python -m gateway.preflight
python -m gateway.decisions --dir state\audit
python -m gateway.report --file state\gateway_runs.jsonl --quarantine-file state\quarantine.jsonl
python -m gateway.correlation --file state\dedup_index.json
```

In Compose deployments, use the `ops` profile services documented in
`deployment-operations.md`.
