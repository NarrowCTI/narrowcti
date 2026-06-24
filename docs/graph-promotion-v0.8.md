# Graph Promotion - v0.8.0

## Purpose

This document defines the v0.8 graph promotion direction.

v0.7 proved that NarrowCTI can extract source metadata, normalize graph
evidence, build graph candidates, apply graph policy and preview STIX graph
objects without importing them into OpenCTI. v0.8 starts the controlled path
from preview to promotion.

## Product Rule

OpenCTI remains the protected intelligence graph. NarrowCTI must not create
graph entities or relationships until the candidate passes:

- Source metadata validation.
- Graph candidate policy.
- TLP and sharing controls.
- Local graph deduplication.
- OpenCTI graph lookup.
- Canonical MITRE lookup when ATT&CK evidence is present.
- Operator-visible audit evidence.

## Promotion Pipeline

```text
source metadata
  -> graph evidence
  -> graph candidates
  -> graph candidate policy
  -> local graph deduplication
  -> OpenCTI graph lookup
  -> graph export dry-run evidence
  -> OpenCTI lab import validation
  -> controlled graph promotion
  -> post-export local graph state marking
```

## v0.8 First Cut

The first v0.8 implementation is intentionally read-only:

- `core/opencti_graph_lookup.py` provides an OpenCTI graph lookup adapter.
- ATT&CK attack-pattern candidates can be looked up by `x_mitre_id`.
- ATT&CK attack-pattern candidates can fall back to STIX `standard_id` lookup.
- The lookup implements the same `known_keys_for_plan` interface already used
  by local graph deduplication.
- Lookup errors fail open and are logged, preserving the current audit/dry-run
  behavior.
- `NARROWCTI_OPENCTI_GRAPH_LOOKUP=false` keeps the runtime read-only lookup
  disabled by default. When set to `true`, OTX and MISP planning combine local
  graph deduplication state with OpenCTI canonical graph lookup.
- Lookup matches are retained as bounded audit evidence in
  `graph_export_plan_lookup_matches` so analysts can inspect which canonical
  OpenCTI object was matched before future promotion logic creates anything.

This lets NarrowCTI mark a candidate such as `T1059` as already known by
OpenCTI before future graph promotion tries to create anything.

## Runtime Configuration

`NARROWCTI_OPENCTI_GRAPH_LOOKUP` controls the v0.8 OpenCTI graph lookup gate.

- `false`: default. NarrowCTI only uses local graph deduplication state when
  `NARROWCTI_GRAPH_DEDUP_STATE_FILE` is configured.
- `true`: NarrowCTI queries OpenCTI during graph export planning and treats
  canonical matches, such as existing ATT&CK attack-patterns, as known graph
  entities before promotion logic is allowed to create anything.

The lookup is still read-only. It does not create entities, relationships or
state marks in OpenCTI.

When matches exist, decision metadata can include
`graph_export_plan_lookup_matches` with the NarrowCTI candidate key, candidate
type, candidate value and canonical OpenCTI match fields such as `opencti_id`,
`standard_id`, `entity_type`, `name`, `x_mitre_id`, `match_type` and
`match_value`. The decision audit report also aggregates these matches in the
`graph_export` summary with counters by candidate object type, canonical match
type and canonical entity type.

## Canonical MITRE Linking

The intended MITRE behavior is:

```text
Official MITRE connector
  -> loads canonical ATT&CK attack-patterns into OpenCTI

NarrowCTI
  -> finds T1059 in OTX/MISP/source metadata
  -> resolves technique context locally
  -> checks OpenCTI for canonical T1059
  -> creates curated relationships to the existing object in a later promotion
     step
```

v0.8 must prefer linking to existing canonical ATT&CK objects over creating new
attack-pattern objects. If the canonical object is missing, the candidate should
remain in audit/dry-run or be held until policy explicitly allows creation.

## Current Non-Goals

The first v0.8 cut does not:

- Import graph objects into OpenCTI.
- Mark graph objects or relationships as exported.
- Create OpenCTI relationships.
- Query every possible STIX object type.
- Replace local graph deduplication.

## Expansion Path

After ATT&CK lookup is validated, the same pattern should expand to:

- Malware and tool lookup by name, aliases and source references.
- Threat actor and intrusion set lookup by name, aliases and external
  references.
- Sector and location lookup with controlled vocabulary normalization.
- Vulnerability lookup by CVE id.
- Relationship lookup before edge creation.
- Post-export graph state marking only after OpenCTI import succeeds.

## Validation

Validation must cover:

- Unit tests for lookup query construction and fail-open behavior.
- Dry-run graph export plans with OpenCTI-known entity keys.
- Lab comparison against OpenCTI with the official MITRE connector enabled.
- Evidence that duplicate ATT&CK attack-pattern objects are not created.
- Evidence that future curated relationships point to canonical OpenCTI objects.
