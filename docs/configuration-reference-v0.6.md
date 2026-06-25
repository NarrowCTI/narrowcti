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
| `NARROWCTI_RELEASE_QUARANTINE_REQUIRES_REASON` | Requires a review reason before release, partial release or rejection. Default should remain `true` for governed environments. |
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

## v0.7 Graph Candidate Controls

These controls expose the graph curation surface used by the v0.7 audit-first
graph enrichment layer.

| Variable | Purpose |
| --- | --- |
| `NARROWCTI_MIN_ENTITY_CONFIDENCE` | Minimum entity confidence required for a graph candidate to be accepted by graph candidate policy. Lower-confidence candidates are held in audit metadata. |
| `NARROWCTI_MIN_RELATIONSHIP_CONFIDENCE` | Minimum relationship confidence required for a graph candidate relationship to be accepted by graph candidate policy. |
| `NARROWCTI_REQUIRE_RELATIONSHIP_PROVENANCE` | Requires graph candidates to carry source provenance before they are accepted by graph candidate policy. |
| `NARROWCTI_ALLOWED_GRAPH_ENTITY_TYPES` | Optional allow-list for NarrowCTI graph entity types such as `attack_pattern`, `malware`, `threat_actor`, `source_identity` or `marking`. Empty allows all current candidate types. |
| `NARROWCTI_ALLOWED_GRAPH_STIX_OBJECT_TYPES` | Optional allow-list for STIX/OpenCTI object types such as `attack-pattern`, `malware`, `threat-actor`, `identity` or `marking-definition`. Empty allows all current candidate object types. |
| `NARROWCTI_GRAPH_EXPORT_MODE` | Graph export mode. `audit` records audit-only actions, `dry-run` records `would_create` object and relationship counts, and `export` enables controlled graph promotion for accepted candidates. |
| `NARROWCTI_GRAPH_DEDUP_STATE_FILE` | Optional local graph deduplication index used as a known-key lookup when building `graph_export_plan`. Empty disables persisted graph lookup. Exported graph state is marked only after a successful OpenCTI import. |
| `NARROWCTI_OPENCTI_GRAPH_LOOKUP` | v0.8 opt-in OpenCTI graph lookup. `false` keeps only local graph deduplication state. `true` lets OTX and MISP planning query OpenCTI for canonical graph objects, including ATT&CK attack-patterns, malware, tools, infrastructure, CVE vulnerabilities, threat actors, intrusion sets, controlled locations/countries, autonomous systems and supported cyber observables, before graph promotion creates new objects. |

Use `export` only with explicit graph thresholds, allow-lists and validation
evidence. The first promotion gate can create supported STIX objects such as
`threat-actor`, `intrusion-set`, `infrastructure`, `malware`, `tool`,
`vulnerability`, `attack-pattern`, `identity` sectors, `location`, `indicator`,
`note` and basic observables. Infrastructure should be allowed only when the
source provides explicit infrastructure evidence or the candidate has been
curated for release; raw observables alone should remain Observables or
Indicators. When local or OpenCTI lookup reports a known graph key with a valid
canonical STIX `standard_id`, the export gate references that existing object
instead of duplicating it.

## v0.8 License And Feature Gate Controls

These controls expose the first technical inventory for commercial packaging.
They are intentionally preflight-visible before they become runtime blockers.
This lets operators and support teams identify edition, customer and capability
state without requiring internet activation. Preflight reports both enabled and
disabled known capabilities so support can see whether a capability is available
for the declared edition or explicit override.

| Variable | Purpose |
| --- | --- |
| `NARROWCTI_LICENSE_EDITION` | Declared product edition. Current recognized values are `evaluation`, `professional`, `enterprise` and `mssp`. |
| `NARROWCTI_LICENSE_CUSTOMER_ID` | Optional non-secret customer or environment identifier shown in preflight for support and entitlement tracing. |
| `NARROWCTI_LICENSE_FILE` | Future signed offline license file path. Preflight reports only whether it is configured. |
| `NARROWCTI_LICENSED_CAPABILITIES` | Optional comma-separated capability override. Empty uses the default capability set for the declared edition. |
| `NARROWCTI_FEATURE_GATES_ENFORCED` | Enables strict preflight validation for license configuration. Runtime feature blocking is still pending broader product validation. |
| `NARROWCTI_OPERATIONAL_VALIDATION_SOURCES` | Optional compose-runner helper for the v0.8 operational validation service. It controls the comma-separated source list passed to `gateway.operational_validation --required-sources`. |
| `NARROWCTI_OPERATIONAL_VALIDATION_EVIDENCE_FILE` | Optional compose-runner helper for the v0.8 operational validation and support diagnostics services. It points to a local JSON file with operator-recorded manual checks such as full validation, OpenCTI duplicate review and resource posture. |

Known v0.8 capability identifiers:

```text
source.otx
source.misp
enrichment.otx_entities
enrichment.mitre_attack
quarantine.review
reports.operational
reports.operational_validation
reports.support_diagnostics
graph.export.audit
graph.export.dry_run
graph.lookup.opencti
graph.export.controlled
deployment.templates
mssp.multi_environment
```

Graph controls make promotion decisions visible in decision audit and
quarantine metadata through `graph_candidate_policy` and `graph_export_plan`.
The decision audit report also aggregates graph export plan evidence so
operators can review modes, statuses, actions, would-create counts, exported
counts, held reasons and source/query rollups without reading raw JSONL
records. v0.7 graph export plans also include local intra-plan entity and
relationship deduplication evidence. This reduces duplicate dry-run intent
inside one decision record, but does not replace OpenCTI graph lookup. When
`NARROWCTI_GRAPH_DEDUP_STATE_FILE` is configured, OTX and MISP can read known
local graph keys and mark matching candidates as deduplicated in the plan. This
is read-only in audit/dry-run modes. In v0.8,
`NARROWCTI_OPENCTI_GRAPH_LOOKUP=true` extends this planning aid to canonical
OpenCTI graph lookup. When canonical matches are found, OTX and MISP decision
metadata can include `graph_export_plan_lookup_matches` so operators can audit
which OpenCTI object was matched. In `export` mode, known local/OpenCTI graph
keys with canonical STIX ids are referenced by the curated bundle, and newly
promoted graph keys are marked locally only after successful OpenCTI import.
Graph SDOs created by NarrowCTI use deterministic STIX ids derived from object
type, identity class and normalized value/name so repeated exports converge on
the same OpenCTI `standard_id` when the curated object is unchanged.
For cyber observables, OpenCTI stores the concrete SCO type rather than the
generic NarrowCTI candidate type. For example, a NarrowCTI `observable`
candidate can resolve to an existing `ipv4-addr--...`, `domain-name--...` or
`url--...` STIX id, while an ASN candidate resolves to
`autonomous-system--...` through `stixCyberObservables`.
The STIX Author / OpenCTI Author is resolved from the logical upstream source
for audit visibility, for example `OTX AlienVault` for `alienvault:otx` and
`MISP` for `misp:misp`. NarrowCTI remains visible through decision audit,
curation reports, export plans and `x_narrowcti_*` graph metadata. Existing
OpenCTI objects keep their previous author; the source-aware identity mapping
is applied to new exported bundles and newly created objects.

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

Graph candidate audit posture:

```env
NARROWCTI_MIN_ENTITY_CONFIDENCE=50
NARROWCTI_MIN_RELATIONSHIP_CONFIDENCE=60
NARROWCTI_REQUIRE_RELATIONSHIP_PROVENANCE=true
NARROWCTI_ALLOWED_GRAPH_ENTITY_TYPES=attack_pattern,malware,threat_actor,source_identity,marking
NARROWCTI_ALLOWED_GRAPH_STIX_OBJECT_TYPES=attack-pattern,malware,threat-actor,identity,marking-definition
NARROWCTI_GRAPH_EXPORT_MODE=dry-run
NARROWCTI_GRAPH_DEDUP_STATE_FILE=/app/state/graph_dedup.json
NARROWCTI_OPENCTI_GRAPH_LOOKUP=false
```

Feature gate inventory posture:

```env
NARROWCTI_LICENSE_EDITION=enterprise
NARROWCTI_LICENSE_CUSTOMER_ID=customer-lab
NARROWCTI_LICENSE_FILE=/licenses/customer-lab.lic
NARROWCTI_LICENSED_CAPABILITIES=source.otx,source.misp,graph.lookup.opencti,reports.operational,reports.operational_validation,reports.support_diagnostics
NARROWCTI_FEATURE_GATES_ENFORCED=false
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
python -m gateway.quarantine --release-audit-file state\audit\releases.jsonl audit --action export
```

`export-released` is dry-run by default. Use `--execute` only after OpenCTI
capacity, deduplication posture and review evidence are acceptable.

## Validation

Before promoting v0.6, run:

```powershell
.\scripts\validate-v0.6.ps1
python -m gateway.preflight
python -m gateway.report --file state\gateway_runs.jsonl --quarantine-file state\quarantine.jsonl
python -m gateway.report --file state\gateway_runs.jsonl --quarantine-file state\quarantine.jsonl --output-file state\gateway-operational-report.txt
python -m gateway.quarantine --release-audit-file state\audit\releases.jsonl audit --limit 20
```

The validation goal is to prove that quarantine records are created, review
actions are audited, released records remain dry-run by default and enrichment
gaps such as a missing MITRE cache are warnings instead of ingest blockers.
In the v0.8 development track, `gateway.preflight` also reports
`NARROWCTI_GRAPH_EXPORT_MODE`, `NARROWCTI_GRAPH_DEDUP_STATE_FILE` and
`NARROWCTI_OPENCTI_GRAPH_LOOKUP` so operators can confirm the graph promotion
gate before running OTX or MISP sources. It also reports license edition,
customer id, whether a license file is configured, whether feature gates are
enforced and which capabilities are active for the declared edition or override.
