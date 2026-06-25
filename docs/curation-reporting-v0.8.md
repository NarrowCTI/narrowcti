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
- `format_html_report`
- `format_text_report`
- `write_html_report`
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

HTML report:

```powershell
python -m gateway.curation_report `
  --summary-file state\gateway_runs.jsonl `
  --decision-path state\audit `
  --quarantine-file state\quarantine.jsonl `
  --release-audit-file state\audit\releases.jsonl `
  --html-file state\curation-report.html
```

Support-safe report:

```powershell
python -m gateway.curation_report `
  --redaction-profile support `
  --html-file state\curation-report-support.html `
  --json
```

External-safe report:

```powershell
python -m gateway.curation_report `
  --redaction-profile external `
  --html-file state\curation-report-external.html
```

`--redaction-profile none` is the default and keeps the complete local report.
`--redaction-profile support` keeps aggregate counts, source posture, graph
readiness and recommendations, but removes detailed failure, query and
quarantined-candidate lists from the rendered output. Use it before sharing a
curation report with support.
`--redaction-profile external` uses the same conservative aggregate-only report
shape for customer-safe or external report delivery when raw local evidence
should not be exposed.

Each rendered report includes the selected profile and policy metadata:

- `audience`: intended recipient category, such as local operator, support or
  external recipient.
- `raw_evidence_included`: whether detailed local evidence remains present.
- `aggregate_only`: whether the report is reduced to aggregate posture and
  decision evidence.
- `removed_fields`: detailed report fields intentionally removed from shared
  profiles, currently operational failures, operational queries, per-source
  failures, quarantined candidate details and decision query detail.
- `retained_sections`: sections intentionally kept because they preserve
  executive posture, graph readiness, source posture, policy insights and
  recommendations without exposing raw local evidence.

When arguments are omitted, the command falls back to the corresponding
`NARROWCTI_*` settings. Missing evidence is treated as empty input so an
operator can still generate a partial report during early validation.

## Report Sections

The current report contains:

- `schema_version`: stable report contract identifier, currently
  `curation-report/v0.8`, used by JSON, text, HTML and embedded support
  diagnostics output.
- `redaction_profile` and `redaction_policy`: explicit report sharing contract
  for the selected profile. `none` keeps local raw evidence, while `support`
  and `external` expose aggregate-only output and list the detailed fields that
  were removed.
- `executive_summary`: compact counts and graph readiness indicators.
- `operational`: gateway run and source outcome rollups.
- `decisions`: decision audit, score, graph export and graph STIX summaries.
- `analyst_review`: quarantine queue status/source counts.
- `analyst_review_actions`: aggregate release, reject and export audit
  feedback for policy tuning, including top review reasons by action and
  source.
- `source_summaries`: per-source posture with operational, decision, review and
  review-action counters, plus an evidence-driven context narrative when
  source decision metadata carries ATT&CK, threat actor/intrusion set or
  target-sector graph evidence, or arsenal evidence such as malware, tools and
  vulnerabilities.
- `policy_insights`: source-level policy tuning hints derived from repeated
  release/reject audit patterns, with top analyst reasons attached to explain
  what drove the signal and decision score distributions attached to show
  whether the source is repeatedly producing low-score or higher-confidence
  reviewed candidates. Graph evidence density is also attached so analysts can
  see whether a source is producing graph context, OpenCTI canonical matches and
  relationship-ready evidence. Context-quality metrics are attached from
  contextual scoring evidence so analysts can see whether reviewed candidates
  carry actor, TTP, sector, arsenal or other high-value CTI context. The same
  evidence also feeds a compact context narrative with top ATT&CK techniques,
  top arsenal, top threat actors/intrusion sets and top target sectors per
  source.
  Repeated quarantine reasons are attached from source-level decision audit
  action reasons so operators can see which policy condition is holding a
  source back.
- `recommendations`: deterministic next actions based on evidence gaps and
  risk signals.

Current recommendation examples:

- Collect evidence when no run or decision records exist.
- Review source errors before continuous operation.
- Review pending quarantine records.
- Continue queue triage when review actions exist but pending records remain.
- Review policy thresholds and source scope when rejected releases exceed
  accepted releases.
- Validate graph dry-run objects before export mode.
- Preserve OpenCTI graph lookup when canonical matches are found.

## Product Boundary

The v0.8 report model is designed to support the later enterprise report the
product should provide: what was ingested, held, filtered, enriched,
deduplicated, promoted and why.

It remains deterministic and evidence-driven. It should not infer facts that are
not present in gateway, decision, quarantine or graph-planning evidence.

Source posture is intentionally simple in v0.8:

- `stable`: evidence exists and no obvious source warning is present.
- `needs-attention`: the source has failures, errors, pending review or more
  rejected review actions than released actions.
- `no-evidence`: no operational, decision, quarantine or review-action evidence
  exists for the source.

Policy insights are also intentionally bounded in v0.8. They do not decide that
a source is good or bad. They show review patterns an operator should inspect:

- `policy-too-permissive-or-source-too-noisy`: three or more source review
  decisions exist and rejects exceed releases.
- `policy-may-be-too-strict`: three or more source review decisions exist and
  releases exceed rejects.
- `observe-review-pattern`: review evidence exists but is not yet strong enough
  to recommend a tuning direction.

These insights help analysts decide whether thresholds, TLP/date filters, source
scope or contextual requirements need tuning before broader promotion.

The report also carries the most frequent analyst review reasons observed in
release/reject audit events. These reasons are evidence, not automatic policy
changes. They help operators understand whether a tuning signal came from
examples such as repeated "out of scope" rejects, repeated high-value releases
or recurring partial releases for specific observable types.

Policy insights also include the decision score summary available for each
source: scored record count, minimum score, maximum score, average score and
the low-score volume from the lower bands. This makes tuning evidence more
explicit without changing the scoring algorithm or automatically rewriting
policy.

The graph evidence summary includes source-level candidate count, accepted and
held graph candidates, OpenCTI lookup matches, would-create object/relationship
counts and density ratios. It is evidence for review and promotion readiness,
not an automatic export trigger. It also surfaces the top accepted graph object
types, accepted relationship types, OpenCTI lookup object types and STIX preview
object/relationship types so an analyst can see whether a source is carrying
ATT&CK, malware, vulnerability or relationship-rich context before promotion.

The executive graph-readiness summary reads the current decision-audit
`graph_stix_preview` counters: preview record count as STIX bundle count,
`graph_object_count` as STIX object count and `graph_relationship_count` as
STIX relationship count. Legacy `bundle_count`, `object_count` and
`relationship_count` fields remain accepted for older support snapshots.

The context-quality summary includes source-level contextual scoring records,
accepted context candidates, adjustment volume, average score delta, maximum
contextual score and top context categories. In v0.8 this remains report
evidence only; it does not apply contextual scoring to final ingest decisions.

The context narrative summary is also evidence-only. It is built from
`graph_evidence.records` in decision metadata and currently surfaces top
`attack_pattern`, `malware`/`tool`/`vulnerability`,
`threat_actor`/`intrusion_set` and `target_sector` values by source. It does
not invent missing actors, arsenal, sectors or ATT&CK techniques; if a feed does
not provide those fields, the report shows `none`.

Repeated quarantine reasons are taken from decision audit evidence grouped by
source and action. They explain why candidates are being held, for example low
score, missing relationship provenance or blocked TLP, without changing
quarantine policy automatically.

## Future Work

- Add PDF export once the report schema stabilizes.
- Expand the first evidence-driven context narrative into richer per-actor,
  per-arsenal, per-sector and per-ATT&CK report sections.
- Add graph-quality deltas after controlled graph promotion is enabled.
- Add tenant-configurable redaction policies for future customer-specific
  external report delivery.
