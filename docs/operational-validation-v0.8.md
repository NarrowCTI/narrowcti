# v0.8 Operational Validation

## Purpose

This document defines the observable validation plan for the v0.8 graph
promotion gate.

v0.8 remains conservative. The goal is to prove that NarrowCTI can detect
canonical OpenCTI graph objects, record lookup evidence, summarize that evidence
for operators and keep graph promotion in dry-run until lab validation
explicitly allows controlled export.

No secrets should be recorded here. Local `.env` files remain unversioned.

## Safety Boundary

The default v0.8 validation posture is:

```text
NARROWCTI_DRY_RUN=true
NARROWCTI_GRAPH_EXPORT_MODE=dry-run
NARROWCTI_OPENCTI_GRAPH_LOOKUP=true
NARROWCTI_GRAPH_DEDUP_STATE_FILE=/app/state/graph_dedup.json
```

Expected safety result:

- OpenCTI indicator/report export follows existing dry-run behavior.
- Graph objects and relationships are not promoted unless
  `NARROWCTI_GRAPH_EXPORT_MODE=export` is explicitly enabled for a bounded lab
  import.
- OpenCTI graph lookup is read-only.
- Lookup errors fail open and are logged as evidence.
- Canonical graph matches are recorded in
  `graph_export_plan_lookup_matches`.
- The decision audit report aggregates lookup match counts in `graph_export`.

## Controlled Export Evidence

A bounded lab export can be used to validate a single OpenCTI tab mapping after
dry-run evidence is acceptable. The recommended pattern is:

```text
NARROWCTI_GRAPH_EXPORT_MODE=export
NARROWCTI_OPENCTI_GRAPH_LOOKUP=true
NARROWCTI_ALLOWED_GRAPH_ENTITY_TYPES=target_sector
MAX_PULSES_PER_QUERY=1
MAX_SEARCH_RESULTS_PER_QUERY=1
MAX_IOCS_PER_PULSE=10
```

Observed local validation for the OTX `lummac2` query created the curated
`Crypto` object in OpenCTI as `entity_type=Sector`, confirming that
`target_sector` metadata exported by NarrowCTI can populate
`Entities / Sectors`. This evidence should be repeated per source and per
entity class before enabling broader graph export allow-lists.

When ATT&CK candidates are included in a bounded export, validation should also
confirm whether `existing_reference_count` is greater than zero. That shows
NarrowCTI referenced canonical OpenCTI ATT&CK objects by `standard_id` instead
of creating duplicate `attack-pattern` objects.

When Arsenal candidates are included, validation should prefer a bounded
`malware` or `tool` allow-list and confirm whether the lookup matched an
existing OpenCTI object by `standard_id`, exact name or a curated alias group.
Broader fuzzy matching is not part of the current v0.8 export gate.

When Vulnerability candidates are included, validation should prefer a bounded
CVE-only export with OpenCTI lookup enabled. The expected result is that an
existing OpenCTI Vulnerability is referenced by `standard_id`, the export
summary shows `existing_reference_counts.vulnerability=1`, and the OpenCTI
Vulnerability count for that CVE does not increase.

When Intrusion Set or Threat Actor candidates are included, validation should
prefer one canonical object that already exists in OpenCTI and, when possible,
one source alias. The expected result is that the export summary shows
`existing_reference_counts.intrusion-set=1` or
`existing_reference_counts.threat-actor=1`, the validation Report references
the existing object, and the OpenCTI object count for the canonical name or
alias search does not increase.

Observed local validation for the OTX `lummac2` query with
`NARROWCTI_ALLOWED_GRAPH_ENTITY_TYPES=malware` and
`MAX_IOCS_PER_PULSE=10` ingested one curated report with 10 indicators. OpenCTI
GraphQL confirmed the report object references included `Malware` `LummaC2`
with `standard_id=malware--58dd33b2-647b-5c42-89e8-09b5f64b9469`. The decision
audit recorded `existing_reference_counts={"malware":1}`. Follow-up review
showed this was still not the desired canonical object because OpenCTI already
contained `Lumma Stealer` with alias `LummaStealer`.

The guardrail was tightened so future `LummaC2` candidates resolve to
`Lumma Stealer` by curated alias match when that canonical object is present.
The validation query returned `match_type=alias`, `name=Lumma Stealer` and
`standard_id=malware--961a6bc2-1b2e-5f56-ba42-4655b23fd730`.

Report hygiene must also be checked during repeated validation. Report STIX ids
are now deterministic from report name and description, so repeated export of
the same source report should update the same OpenCTI Report rather than create
another duplicate report row.

Observed repeated export validation confirmed the behavior: before the stable
Report id change, the lab had 5 duplicate OpenCTI Reports with the same LummaC2
title. The first run with deterministic Report ids created one stable Report
with `standard_id=report--d6555acf-74d4-5841-948b-4dde4c06cbe8`; a second
forced run with a fresh state file kept the count at 6 instead of creating a
seventh Report. The newest Report references `Malware` `Lumma Stealer` with
`standard_id=malware--961a6bc2-1b2e-5f56-ba42-4655b23fd730`.

Observed Vulnerability export validation confirmed the same guarded promotion
model for CVEs. The lab used existing OpenCTI Vulnerability `CVE-2019-13939`
with `standard_id=vulnerability--00055e46-c19c-50c1-8d3b-58dd0a63a66e`.
NarrowCTI lookup returned one known entity, the export plan reported
`deduplicated_entity_count=1` and `would_create_object_count=0`, and the
curated bundle summary reported `existing_reference_counts.vulnerability=1`.
After real import, the validation Report was authored by `OTX AlienVault` and
referenced the existing CVE; the OpenCTI Vulnerability count for that search
remained unchanged.

Observed Intrusion Set export validation confirmed exact alias linking. The lab
used existing OpenCTI Intrusion Set `BlackTech` with alias `Palmerworm` and
`standard_id=intrusion-set--058f30a0-efd4-5d3a-aa39-a8dd414ba288`. NarrowCTI
lookup returned one known entity for source value `Palmerworm`, the export plan
reported `deduplicated_entity_count=1` and `would_create_object_count=0`, and
the curated bundle summary reported `existing_reference_counts.intrusion-set=1`.
After real import, the validation Report was authored by `OTX AlienVault` and
referenced the existing `BlackTech` object; the OpenCTI search counts for
`BlackTech` and `Palmerworm` remained unchanged.

Observed Country export validation confirmed deterministic graph object ids and
Location lookup. A controlled lab import created `Argentina` once in OpenCTI as
`entity_type=Country` with
`standard_id=location--a5c43e9c-7f5e-5fc2-b9eb-3c2eaf055301`. Repeating the
same import kept the exact `Argentina` Country count at `1`. A follow-up lookup
validation returned `known_entity_count=1`, `match_type=name`,
`plan_deduplicated_entity_count=1`, `plan_exported_object_count=0` and
`existing_reference_counts.location=1`. The validation Report
`NarrowCTI country lookup export live validation 20260625` was authored by
`OTX AlienVault` and referenced the existing `Argentina` object instead of
creating another Country.

Report hygiene validation confirmed that repeated imports with the same Report
name and description do not create another OpenCTI Report row. OpenCTI can still
hold separate Reports with the same title when the description differs, because
NarrowCTI intentionally derives the deterministic Report STIX id from
`name + description`.

## Required Lab Posture

Before live validation, confirm:

- Caddy, OpenCTI, MISP, RabbitMQ, Redis, MinIO and Elasticsearch are healthy.
- The official MITRE connector has populated canonical ATT&CK objects in
  OpenCTI.
- OTX and MISP source credentials are present only in local `.env` files.
- Source limits are bounded for the local machine.
- Dry-run is enabled for OTX and MISP unless a specific non-dry-run test is
  approved.

## Preflight

Run preflight before any source execution:

```powershell
python -m gateway.preflight
python -m gateway.preflight --json
```

The output must show:

```text
graph_export_mode=dry-run
graph_dedup_state_file=/app/state/graph_dedup.json
opencti_graph_lookup=true
```

If `opencti_graph_lookup=false`, the run can still validate local graph
deduplication and dry-run planning, but it does not validate canonical OpenCTI
graph lookup.

## Controlled OTX Validation

Use a bounded ATT&CK-rich OTX query or pulse sample.

Expected evidence:

- `otx_entities.attack_ids` contains at least one ATT&CK id.
- `mitre_attack.resolved` resolves the technique locally.
- `graph_candidates` contains an accepted `attack_pattern` candidate.
- `graph_export_plan` marks the matching entity as deduplicated when OpenCTI
  already contains the canonical ATT&CK object.
- `graph_export_plan_lookup_matches` includes the OpenCTI `opencti_id`,
  `standard_id`, `entity_type`, `name`, `x_mitre_id`, `match_type` and
  `match_value`.
- `gateway.decisions` report shows `lookup_matches` greater than zero.
- For Arsenal validation, `graph_export_plan_lookup_matches` can include
  existing `Malware` or `Tool` objects matched by `standard_id`, exact name or
  curated alias group.

## Controlled MISP Validation

Use a bounded MISP event with galaxy or ATT&CK evidence.

Expected evidence:

- MISP galaxy/cluster or tag metadata is converted into graph evidence.
- ATT&CK candidates are looked up against canonical OpenCTI attack-patterns.
- Lookup matches are recorded without creating duplicate attack-pattern
  objects.
- Large events remain guarded by `MISP_MAX_EVENTS_PER_RUN`,
  `MISP_MAX_ATTRIBUTES_PER_EVENT`, `MISP_MAX_IOCS_PER_EVENT` and
  `MISP_OVERSIZED_EVENT_ACTION`.

## Decision Audit Report

After a dry-run, summarize decision audit evidence:

```powershell
python -m gateway.decisions `
  --file state\audit\otx_decisions.jsonl `
  --output-file state\reports\otx-decision-audit.txt

python -m gateway.decisions `
  --file state\audit\misp_decisions.jsonl `
  --output-file state\reports\misp-decision-audit.txt
```

For v0.8, the `graph_export` section should include:

```text
lookup_matches=<count>
lookup_objects=attack-pattern:<count>
lookup_match_types=mitre_attack_id:<count>
```

This proves that canonical OpenCTI graph lookup is visible to operators and
future enterprise CTI reports.

## Operational Validation Checklist

v0.8 also provides a read-only checklist command that consolidates preflight and
decision-audit evidence into pass/fail/needs-evidence status:

```powershell
python -m gateway.operational_validation `
  --decision-path state\audit `
  --required-sources otx,misp
```

After repository validation, OpenCTI UI review and local resource review are
completed, record those manual lab checks explicitly:

```powershell
python -m gateway.operational_validation `
  --decision-path state\audit `
  --required-sources otx,misp `
  --full-validation-passed `
  --opencti-ui-no-duplicate `
  --resource-posture-ok
```

Manual lab checks can also be recorded in a local JSON evidence file. This is
the recommended path for repeatable compose `ops` runs because the file can live
in the local state volume without changing the compose command:

```json
{
  "full_validation_passed": true,
  "opencti_ui_no_duplicate": true,
  "opencti_ui_duplicate_found": false,
  "resource_posture_ok": true,
  "resource_posture_unhealthy": false
}
```

Then run:

```powershell
python -m gateway.operational_validation `
  --decision-path state\audit `
  --required-sources otx,misp `
  --evidence-file state\operational-validation-evidence.json
```

If the evidence file is missing, the checklist remains read-only and treats
manual checks as `needs-evidence`. If the file exists, it must contain a JSON
object.

JSON output is available for attaching evidence to release notes:

```powershell
python -m gateway.operational_validation `
  --decision-path state\audit `
  --required-sources otx,misp `
  --format json `
  --output-file state\reports\v0.8-operational-validation.json
```

HTML output is available for local review or support-safe evidence packages:

```powershell
python -m gateway.operational_validation `
  --decision-path state\audit `
  --required-sources otx,misp `
  --format html `
  --output-file state\reports\v0.8-operational-validation.html
```

Text output can also be written as a local evidence artifact:

```powershell
python -m gateway.operational_validation `
  --decision-path state\audit `
  --required-sources otx,misp `
  --output-file state\reports\v0.8-operational-validation.txt
```

Checklist status meanings:

- `pass`: evidence is present and satisfies the v0.8 criterion.
- `warn`: the run is not blocked, but controls are incomplete.
- `fail`: validation found an unsafe or blocking condition.
- `needs-evidence`: the criterion cannot be closed from local evidence yet.

The checklist does not call source APIs, query OpenCTI or mutate state. It reads
existing preflight settings and decision audit records, then leaves UI duplicate
checks and resource posture as explicit operator-recorded evidence.

## Pass Criteria

The v0.8 graph lookup gate is acceptable when:

- Full validation passes with `.\scripts\validate-v0.6.ps1`.
- Gateway preflight reports graph lookup controls.
- OTX and MISP bounded dry-runs complete without graph writes.
- At least one ATT&CK candidate is matched to a canonical OpenCTI object.
- Decision metadata includes bounded lookup match evidence.
- Decision report aggregates lookup evidence.
- No duplicate ATT&CK attack-pattern object is created in OpenCTI.

## Stop Criteria

Stop validation and keep graph promotion blocked if:

- OpenCTI lookup causes repeated runtime errors.
- Lookup results are ambiguous or point to the wrong canonical object.
- Dry-run plans imply large graph growth outside configured limits.
- Elasticsearch, RabbitMQ or OpenCTI queue pressure becomes unhealthy.
- MISP events exceed local resource guardrails.

## Remaining Evidence To Capture

- Real OTX ATT&CK-rich dry-run with OpenCTI canonical match.
- Real MISP ATT&CK/galaxy dry-run with OpenCTI canonical match.
- Decision audit report excerpt showing lookup counters.
- OpenCTI UI check proving no duplicate ATT&CK object was created.
- Resource posture after bounded runs on the local lab.
