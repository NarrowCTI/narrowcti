# Curation Decision Reference

This document explains how NarrowCTI turns configuration and source evidence
into operator-visible decisions.

## Decision Pipeline

```text
source candidate
  -> source state and basic validation
  -> base scoring and graph evidence
  -> TLP policy
  -> contextual scoring mode
  -> policy decision
  -> indicator-type filter
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

## Contextual Scoring

Contextual scoring uses accepted, source-backed graph candidates to measure how
much useful context accompanies the source item. The default impacts are:

| Category | Default impact | Examples |
| --- | --- | --- |
| `threat` | `20` | Threat actor or intrusion set. |
| `toolbox` | `15` | Malware, tool or detection rule. |
| `ttp` | `15` | ATT&CK technique, tactic or detection context. |
| `sector` | `10` | Target sector. |
| `location` | `10` | Target country or region. |
| `vulnerability` | `15` | Source-backed vulnerability. |
| `author` | `5` | Source identity evidence. |
| `graph_state` | `5` | Observable, sighting or object-reference context. |

Repeated category/entity/value matches are deduplicated before impact is
calculated. The combined impact is capped by
`NARROWCTI_CONTEXTUAL_SCORING_MAX_IMPACT` and applied with:

```text
contextual_score = base_score + ((100 - base_score) * impact_ratio)
```

The result is clamped to `0..100` and never lowers the base score.

| Mode | Decision effect |
| --- | --- |
| `off` | Uses base score and emits no contextual adjustments. |
| `shadow` | Calculates full evidence but keeps `decision_score=base_score`. This is the default. |
| `enforce` | Sets `decision_score=contextual_score` for score-based policy checks. |

Example: base score `40` with `threat:20` and `ttp:15` has combined impact
`35%` and contextual score `61`. In `shadow`, policy still sees `40`; in
`enforce`, policy sees `61`. Audit retains both scores, the `21`-point delta,
matched values and every adjustment.

Contextual scoring runs only after TLP acceptance. It cannot override denied
TLP, a positive hard age cutoff, explicit graph-policy holds or a type filter
that leaves no exportable indicator. The soft old-item rule remains
score-dependent and therefore uses `decision_score` in `enforce` mode.

## Policy Matrix

| Condition | Decision | Reason |
| --- | --- | --- |
| Candidate missing required source id or enrichment fails | `skip` or `error` | Source item cannot be safely processed. |
| Candidate already processed in source state | `skip` | Source deduplication prevents repeated processing. |
| `MAX_DAYS_HARD_FILTER > 0` and candidate age exceeds it | `drop` | Hard age cutoff. |
| Decision score `< NARROWCTI_QUARANTINE_SCORE_THRESHOLD` and quarantine enabled | `quarantine` | Low score, analyst review required. |
| Decision score `< NARROWCTI_QUARANTINE_SCORE_THRESHOLD` and quarantine disabled | `drop` | Very low score. |
| Decision score `< NARROWCTI_MIN_SCORE_TO_INGEST` | `drop` | Below minimum score. |
| Candidate age `> NARROWCTI_MAX_DAYS_OLD` and decision score below old-item threshold | `drop` | Old intelligence with insufficient score. |
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
