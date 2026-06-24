# Curation Reporting - v0.8.0

## Purpose

This document defines the v0.8 reporting model for analyst-facing CTI curation
reports.

The goal is to consolidate NarrowCTI evidence into a report that explains:

- What was reviewed.
- What was accepted, filtered, quarantined or errored.
- What still needs analyst review.
- What graph context was prepared.
- What should be validated before promotion or continuous operation.

This is the reporting model foundation for future enterprise CTI reports. It is
not a PDF generator, dashboard or customer-facing UI yet.

## Evidence Sources

The v0.8 curation report is built from existing evidence:

| Evidence | Source |
| --- | --- |
| Gateway operational runs | `NARROWCTI_RUN_SUMMARY_FILE` |
| Decision audit records | `NARROWCTI_DECISION_AUDIT_DIR` or explicit JSONL paths |
| Quarantine queue | `NARROWCTI_QUARANTINE_REPOSITORY` |
| Release/reject/export audit | `NARROWCTI_RELEASE_AUDIT_FILE` |
| Graph promotion planning | `graph_export_plan` in decision metadata |
| OpenCTI graph lookup evidence | `graph_export_plan_lookup_matches` in decision metadata |
| Graph STIX preview evidence | `graph_stix_preview` in decision metadata |

The report intentionally reads evidence. It does not call source APIs, query
OpenCTI, mutate quarantine records or export graph objects.

## Current Implementation

v0.8 introduces `gateway.curation_report`.

The module composes:

- `gateway.report` operational summaries.
- `gateway.decisions` decision audit summaries.
- `gateway.review` analyst review summaries.

It exposes:

- `build_curation_report`
- `build_curation_report_from_files`
- `format_text_report`
- CLI entrypoint: `python -m gateway.curation_report`

## CLI Usage

Text report:

```powershell
python -m gateway.curation_report `
  --summary-file state\gateway_runs.jsonl `
  --decision-path state\audit `
  --quarantine-file state\quarantine.jsonl `
  --release-audit-file state\audit\releases.jsonl
```

JSON report:

```powershell
python -m gateway.curation_report `
  --summary-file state\gateway_runs.jsonl `
  --decision-path state\audit `
  --quarantine-file state\quarantine.jsonl `
  --release-audit-file state\audit\releases.jsonl `
  --json
```

When arguments are omitted, the command falls back to the corresponding
`NARROWCTI_*` settings. Missing evidence is treated as empty input so an
operator can still generate a partial report during early validation.

## Report Sections

The current report contains:

- `executive_summary`: compact counts and graph readiness indicators.
- `operational`: gateway run and source outcome rollups.
- `decisions`: decision audit, score, graph export and graph STIX summaries.
- `analyst_review`: quarantine queue status/source counts.
- `recommendations`: deterministic next actions based on evidence gaps and
  risk signals.

Current recommendation examples:

- Collect evidence when no run or decision records exist.
- Review source errors before continuous operation.
- Review pending quarantine records.
- Validate graph dry-run objects before export mode.
- Preserve OpenCTI graph lookup when canonical matches are found.

## Product Boundary

The v0.8 report model is designed to support the later enterprise report the
product should provide: what was ingested, held, filtered, enriched,
deduplicated, promoted and why.

It remains deterministic and evidence-driven. It should not infer facts that are
not present in gateway, decision, quarantine or graph-planning evidence.

## Future Work

- Add export formats for PDF/HTML once the report schema stabilizes.
- Add richer per-actor, per-sector, per-ATT&CK and per-source narratives.
- Add policy tuning insights from repeated release/reject patterns.
- Add graph-quality deltas after controlled graph promotion is enabled.
- Add customer-safe redaction profiles for external report delivery.
