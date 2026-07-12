# Environment Profiles

This document defines safe configuration profiles for NarrowCTI Community
Edition.

Use these profiles as starting points. Tune source scope and thresholds only
after reviewing preflight, decision audit, curation reports and OpenCTI graph
behavior.

## Local Validation

Goal: verify connectivity and decision evidence without OpenCTI writes.

```env
NARROWCTI_ENABLED_SOURCES=otx
NARROWCTI_DRY_RUN=true
NARROWCTI_RUN_ONCE=true
NARROWCTI_CONTEXTUAL_SCORING_MODE=shadow
NARROWCTI_GRAPH_EXPORT_MODE=audit
NARROWCTI_OPENCTI_GRAPH_LOOKUP=false
OTX_DRY_RUN=true
MISP_DRY_RUN=true
MISP_RUN_ONCE=true
MISP_MAX_EVENTS_PER_RUN=1
MISP_MAX_ATTRIBUTES_PER_EVENT=1000
MISP_MAX_IOCS_PER_EVENT=1000
```

Expected behavior:

- candidates can be searched, scored and audited;
- no OpenCTI export occurs;
- graph candidates stay audit-only;
- reports explain what would happen next.

## Controlled Source Import

Goal: import a small, bounded source sample after dry-run evidence is clean.

```env
NARROWCTI_DRY_RUN=false
NARROWCTI_RUN_ONCE=true
NARROWCTI_DEDUP_MODE=hybrid
NARROWCTI_CONTEXTUAL_SCORING_MODE=shadow
NARROWCTI_OPENCTI_DEDUP_LOOKUP=false
NARROWCTI_GRAPH_EXPORT_MODE=audit
OTX_DRY_RUN=false
MISP_DRY_RUN=false
MISP_RUN_ONCE=true
MISP_QUERIES=event:<id>
MISP_MAX_EVENTS_PER_RUN=1
MISP_MAX_ATTRIBUTES_PER_EVENT=1000
MISP_MAX_IOCS_PER_EVENT=100
```

Expected behavior:

- accepted indicators/reports can be exported;
- graph promotion remains audit-only;
- duplicate pressure stays bounded;
- decision audit explains ingest/drop/quarantine/skip outcomes.

## Constrained MISP Backfill

Goal: pull historical MISP data without overwhelming a limited machine.

```env
NARROWCTI_ENABLED_SOURCES=misp
NARROWCTI_DRY_RUN=true
NARROWCTI_RUN_ONCE=true
NARROWCTI_CONTEXTUAL_SCORING_MODE=shadow
MISP_DRY_RUN=true
MISP_RUN_ONCE=true
MISP_QUERIES=*
MISP_FROM_DATE=YYYY-MM-DD
MISP_TO_DATE=YYYY-MM-DD
MISP_TAGS=tlp:green
MISP_PUBLISHED_ONLY=true
MISP_MAX_EVENTS_PER_RUN=1
MISP_MAX_ATTRIBUTES_PER_EVENT=1000
MISP_MAX_IOCS_PER_EVENT=1000
MISP_OVERSIZED_EVENT_ACTION=skip
```

Expected behavior:

- one bounded window is evaluated at a time;
- oversized events are skipped before enrichment;
- decision audit shows volume and policy effect;
- operator can widen dates or limits gradually.

## Continuous Production-Like Operation

Goal: run a validated source continuously with conservative graph posture.

Only use after preflight, dry-run, controlled import and reports are clean.

```env
NARROWCTI_RUN_ONCE=false
NARROWCTI_DRY_RUN=false
NARROWCTI_DEDUP_MODE=hybrid
NARROWCTI_CONTEXTUAL_SCORING_MODE=shadow
NARROWCTI_OPENCTI_DEDUP_LOOKUP=true
NARROWCTI_GRAPH_EXPORT_MODE=audit
NARROWCTI_OPENCTI_GRAPH_LOOKUP=true
NARROWCTI_RUN_SUMMARY_FILE=/app/state/gateway_runs.jsonl
OTX_DRY_RUN=false
MISP_DRY_RUN=false
```

Expected behavior:

- indicators/reports can be ingested continuously;
- graph candidates remain audit-only until graph export is explicitly enabled;
- OpenCTI dedup lookup reduces indicator duplication;
- run summaries and decision audit remain available for review.

## Contextual Scoring Promotion

Goal: compare contextual evidence before allowing it to change threshold
decisions.

First run the normal bounded source workload with:

```env
NARROWCTI_CONTEXTUAL_SCORING_MODE=shadow
NARROWCTI_CONTEXTUAL_SCORING_MAX_IMPACT=100
NARROWCTI_CONTEXTUAL_SCORING_IMPACTS=threat:20,toolbox:15,ttp:15,sector:10,location:10,vulnerability:15,author:5,graph_state:5
```

Review base score, contextual score, delta, category adjustments and the
simulated decision boundary in decision and curation reports. After confirming
that source-backed context does not promote noisy candidates, change only:

```env
NARROWCTI_CONTEXTUAL_SCORING_MODE=enforce
```

Expected behavior:

- score-threshold decisions use the contextual score;
- TLP, hard age cutoff, graph holds and indicator-type policy remain blocking;
- audit records retain base score, contextual score and every adjustment;
- reverting to `shadow` restores the previous decision score without losing
  evidence.

## Controlled Graph Export

Goal: promote graph objects and relationships after source-specific validation.

```env
NARROWCTI_GRAPH_EXPORT_MODE=export
NARROWCTI_OPENCTI_GRAPH_LOOKUP=true
NARROWCTI_GRAPH_DEDUP_STATE_FILE=/app/state/graph_dedup_index.json
NARROWCTI_REQUIRE_RELATIONSHIP_PROVENANCE=true
NARROWCTI_MIN_ENTITY_CONFIDENCE=0
NARROWCTI_MIN_RELATIONSHIP_CONFIDENCE=0
NARROWCTI_ALLOWED_GRAPH_ENTITY_TYPES=
NARROWCTI_ALLOWED_GRAPH_STIX_OBJECT_TYPES=
NARROWCTI_ENABLE_INFRASTRUCTURE_VICTIMOLOGY_EXPORT=false
```

Expected behavior:

- safe default graph allow-lists apply when explicit lists are empty;
- canonical OpenCTI objects are reused when lookup finds them;
- newly exported graph keys are marked only after successful import;
- relationship audit can validate Diamond and Kill Chain coverage.

Infrastructure victimology remains disabled in this baseline. For a bounded
same-event MISP validation, set
`NARROWCTI_ENABLE_INFRASTRUCTURE_VICTIMOLOGY_EXPORT=true`, export one known
event, and confirm the `Infrastructure -> targets -> Sector/Organization`
relationship through the OpenCTI API and UI before widening the scope.

## Graph-Only MISP Replay

Goal: replay improved graph mappings for a bounded MISP event whose indicators
are already known.

```env
NARROWCTI_GRAPH_EXPORT_MODE=export
NARROWCTI_OPENCTI_GRAPH_LOOKUP=true
NARROWCTI_GRAPH_REPLAY_ON_ARTIFACT_DEDUP=true
MISP_QUERIES=event:<id>
MISP_MAX_EVENTS_PER_RUN=1
```

Expected behavior:

- no duplicate indicator objects are exported;
- accepted graph context can still be promoted;
- decision metadata records `graph_replay_only=true`.

## Relationship Audit

Goal: validate whether an OpenCTI object has expected graph context.

```env
NARROWCTI_OPENCTI_AUDIT_TYPE=infrastructure
NARROWCTI_OPENCTI_AUDIT_SEARCH=<object name>
NARROWCTI_OPENCTI_AUDIT_FIRST=100
NARROWCTI_OPENCTI_AUDIT_EXPECTED_QUADRANTS=adversary,capability,infrastructure,victimology
NARROWCTI_OPENCTI_AUDIT_REQUIRE_KILL_CHAIN=true
NARROWCTI_OPENCTI_AUDIT_OUTPUT_FILE=/app/state/opencti-relationship-audit.json
```

Expected behavior:

- audit reads OpenCTI but does not mutate it;
- output can feed curation reports and operational validation;
- missing expected quadrants become `needs-evidence`, not false success.
