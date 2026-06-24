# v0.7 Operational Validation

## Purpose

This document records observable v0.7 validation runs against the local lab.

The goal is to evaluate graph-enrichment quality before real graph promotion:
source metadata extraction, graph candidates, graph candidate policy,
graph export planning, STIX preview, contextual scoring and guardrail evidence.

No secrets are recorded here. Local `.env` files remain unversioned.

## Validation Date

2026-06-24.

## Lab Posture

Containers were running for Caddy, OpenCTI, MISP, Redis, RabbitMQ, MinIO and
Elasticsearch.

The local source-tree validation used the host Python runtime with a temporary
venv under `state/.venv`. Because the local `.env` values are suitable for
Docker networking, host-side validation overrode internal service URLs with:

```text
OPENCTI_URL=http://localhost:8080
MISP_URL=http://localhost:8081
```

Both OTX and MISP runs used:

```text
NARROWCTI_RUN_ONCE=true
NARROWCTI_DRY_RUN=true
NARROWCTI_GRAPH_EXPORT_MODE=dry-run
NARROWCTI_MIN_ENTITY_CONFIDENCE=0
NARROWCTI_MIN_RELATIONSHIP_CONFIDENCE=0
NARROWCTI_REQUIRE_RELATIONSHIP_PROVENANCE=false
```

The validation artifacts were written under ignored `state/v07-observable-*`
directories.

## OTX Dry-Run Evidence

Controlled input:

| Field | Value |
| --- | --- |
| Query | `cobalt strike` |
| Pulse | `From RTF to Cobalt Strike passing via Flash` |
| Pulse id | `5898c794e8c61354aa1a7563` |
| Limit | `MAX_PULSES_PER_QUERY=1`, `MAX_IOCS_PER_PULSE=50` |
| Action | `drop` |
| Reason | old pulse with low score, `3424d > 1095d` and `75 < 80` |
| OpenCTI graph write | none |

Observed graph metadata:

| Area | Result |
| --- | --- |
| `graph_evidence` | external reference 1, marking 1, observable 12, source identity 1, tag 4, threat actor 1 |
| `graph_export_plan` | dry-run, 20 accepted, 0 held, 20 would-create objects, 20 would-create relationships |
| `graph_stix_preview` | 30 bundle objects, 14 graph objects, 14 graph relationships |
| STIX preview object types | file 10, identity 1, ipv4-addr 1, threat-actor 1, url 1 |
| STIX preview relationships | attributed-to 1, based-on 12, originated-from 1 |
| `contextual_scoring` | base score 75, contextual score 96, delta 21 |
| Context categories | author 1, graph_state 12, threat 1 |

Fine-grained finding:

The live OTX payload included an `author` value of `2`. This was too weak to
become a graph identity. NarrowCTI was adjusted so numeric OTX author ids no
longer create `source_identity` candidates. The same validation then produced
only `AlienVault` as source identity.

Current gap:

This OTX sample did not include ATT&CK ids, malware families, sectors,
countries or vulnerabilities. It validates observable, threat-actor, source,
label, marking and reference handling, but a richer OTX sample is still needed
to validate actor, arsenal, TTP and victimology graph coverage with live data.

## MISP Dry-Run Evidence

### URLHaus Large-Event Guardrail Sample

Controlled input:

| Field | Value |
| --- | --- |
| Query | `*` |
| Event | `URLHaus Malware URLs feed` |
| Event uuid | `39611bd6-b755-4324-9e5f-0cd3f4b378ed` |
| Limits | `MISP_MAX_EVENTS_PER_RUN=1`, `MISP_MAX_ATTRIBUTES_PER_EVENT=300`, `MISP_MAX_IOCS_PER_EVENT=50` |
| Oversized action | `truncate` |
| Action | `dry-run` |
| Reason | `ok` |
| OpenCTI graph write | none |

Observed guardrails:

| Field | Value |
| --- | --- |
| Source attribute count | 22812 |
| Normalized indicator count after attribute truncation | 300 |
| Export indicator cap | 50 |
| `iocs_truncated` | true |

Observed graph metadata:

| Area | Result |
| --- | --- |
| `graph_evidence` | collector 1, source identity 1, tag 1, vulnerability 6 |
| `graph_export_plan` | dry-run, 9 accepted, 0 held, 9 would-create objects, 9 would-create relationships |
| `graph_stix_preview` | 18 bundle objects, 8 graph objects, 8 graph relationships |
| STIX preview object types | identity 2, vulnerability 6 |
| STIX preview relationships | collected-by 1, originated-from 1, related-to 6 |
| `contextual_scoring` | base score 70, contextual score 100, delta 30 |
| Context categories | author 2, vulnerability 6 |

Fine-grained finding:

The raw MISP decision action remains `dry_run` for processor compatibility, but
the decision audit report now normalizes it to `dry-run` in actions, reasons,
source rollups, query rollups and score summaries. This keeps operator-facing
reports consistent with the rest of v0.7 terminology.

Current gap:

The sampled URLHaus event did not contain rich galaxies for actor, malware,
tools, ATT&CK techniques, sectors or countries. It validates large-event
guardrails, vulnerability extraction and source/collector context. A second
MISP sample with Galaxy/Cluster metadata is still needed for actor, arsenal,
TTP and victimology validation.

### Packrat Galaxy Victimology Sample

Controlled input:

| Field | Value |
| --- | --- |
| Query | `*` |
| Date range | `2015-12-09` to `2015-12-09` |
| Event | `OSINT - Packrat: Seven Years of a South American Threat Actor` |
| Event uuid | `5667e3ea-cec4-4a67-b7c0-f7a9950d210b` |
| Limits | `MISP_MAX_EVENTS_PER_RUN=1`, `MISP_MAX_ATTRIBUTES_PER_EVENT=500`, `MISP_MAX_IOCS_PER_EVENT=100` |
| Oversized action | `truncate` |
| Action | `drop` |
| Reason | below minimum score |
| OpenCTI graph write | none |

Observed source context:

| Field | Value |
| --- | --- |
| Tags | `type:OSINT`, `tlp:white`, `misp-galaxy:threat-actor="Packrat"` |
| Galaxy cluster | threat actor `Packrat` |
| Galaxy meta victimology | targeted sectors: `Activists`, `Journalist`, `Political party` |
| Source score | 50 |
| Source age | 3850 days |

Observed graph metadata after victimology extraction:

| Area | Result |
| --- | --- |
| `graph_evidence` | collector 1, marking 1, source identity 1, tag 2, target sector 3, threat actor 1 |
| Threat actor candidate | `Packrat`, STIX `threat-actor`, relationship `attributed-to`, confidence 80 |
| Target sector candidates | `Activists`, `Journalist`, `Political party`, STIX `identity`, relationship `targets`, confidence 70 |
| `graph_export_plan` | dry-run, 9 accepted, 0 held, 9 would-create objects, 9 would-create relationships |
| `graph_stix_preview` | 14 bundle objects, 6 graph objects, 6 graph relationships |
| STIX preview object types | identity 5, threat-actor 1 |
| STIX preview relationships | attributed-to 1, collected-by 1, originated-from 1, targets 3 |
| `contextual_scoring` | base score 50, contextual score 80, delta 30 |
| Context categories | author 2, sector 3, threat 1 |

Fine-grained finding:

The first Packrat run showed the `Galaxy.meta.targeted-sector` values in the
raw MISP Galaxy cluster, but NarrowCTI only emitted the parent threat actor.
The graph evidence layer was extended to emit victimology evidence from
MISP Galaxy metadata. Each derived sector candidate keeps parent cluster
provenance through `parent_cluster_value`, `parent_cluster_uuid`, `meta_key`
and related parent fields.

Current gap:

This sample validates threat actor plus targeted sectors from a real MISP
Galaxy payload. It does not cover intrusion set, malware, tool, ATT&CK
technique, target country or target region evidence. Additional MISP Galaxy
samples are still needed for those categories.

## Current Acceptance Evidence

Confirmed in this run:

- OTX and MISP can produce observable graph evidence in local dry-run mode.
- `graph_candidate_policy` accepted candidates without hidden promotion.
- `graph_export_plan` produced dry-run would-create counts.
- `graph_stix_preview` built in-memory STIX bundle summaries without OpenCTI
  import.
- `contextual_scoring` produced score deltas but did not apply them to final
  ingest/drop/dry-run decisions.
- MISP oversized events were bounded by attribute and IoC guardrails.
- A real MISP Galaxy threat-actor event produced actor and sector-victimology
  candidates with provenance.
- Operator reports aggregate graph export, contextual scoring and STIX preview
  evidence by source and query.
- Host-side validation requires URL overrides when `.env` uses Docker-internal
  service names.

Not complete yet:

- Live OTX sample covering malware family, ATT&CK ids, sector, country and CVE
  evidence.
- Live MISP samples covering Galaxy/Cluster intrusion set, malware, tool,
  ATT&CK, country and region evidence.
- OpenCTI graph import validation with graph export enabled.
- OpenCTI-side graph lookup and post-export deduplication.
- Direct comparison between official MISP connector import and
  NarrowCTI-curated graph output for the same event.
- Quarantine release path for graph candidates.

## Decision

The v0.7 graph foundation is observable and behaving safely in dry-run mode,
but real graph promotion should remain blocked until richer OTX/MISP samples,
OpenCTI import behavior and OpenCTI-side graph deduplication are validated.
