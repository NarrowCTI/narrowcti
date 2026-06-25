# NarrowCTI v0.8 Architecture Supplement

## Purpose

v0.8 moves NarrowCTI from graph-aware preview to controlled graph promotion.
The architectural boundary remains the same: OpenCTI is the graph, storage and
visualization layer; NarrowCTI is the curation, scoring, deduplication,
normalization and enrichment gateway before data reaches OpenCTI.

## Promotion Architecture

```text
source payload
  -> metadata extraction
  -> graph evidence
  -> graph candidates
  -> graph candidate policy
  -> local graph deduplication
  -> OpenCTI canonical lookup
  -> exportable graph policy
  -> curated STIX bundle
  -> OpenCTI import
  -> post-import validation and local state marking
```

The default posture remains audit/dry-run. Controlled export is only enabled
when `NARROWCTI_GRAPH_EXPORT_MODE=export` is explicitly configured.

## OpenCTI Mapping Boundary

| NarrowCTI concept | STIX/OpenCTI target | Current v0.8 posture |
| --- | --- | --- |
| Report context | `report` | Deterministic report ids reduce duplicate report rows. |
| IOC indicator | `indicator` | Existing behavior remains active. |
| Observable | Concrete SCO such as `ipv4-addr`, `domain-name`, `url`, `email-addr` | Supported for graph candidates and exact OpenCTI lookup. |
| Infrastructure | `infrastructure` | Controlled promotion only when explicit source evidence exists. |
| Autonomous System | `autonomous-system` under `stixCyberObservables` | Native export and lookup validated. |
| IP/CIDR to ASN | `belongs-to` relationship | Native export and GraphQL validation completed for IPv4 and CIDR. |
| Infrastructure contains IP/CIDR/ASN | `consists-of` relationship | Native export and GraphQL validation completed. |
| MITRE technique | Canonical `attack-pattern` | Prefer official MITRE connector object and link to it. |
| Malware/tool/vulnerability/actor/location/sector | Matching OpenCTI SDOs | Supported incrementally with conservative lookup and source-backed promotion. |

## Deduplication Rules

Entity deduplication uses normalized graph entity keys plus OpenCTI canonical
lookup. When OpenCTI returns a valid `standard_id`, NarrowCTI references that
object instead of recreating it.

Relationship deduplication must include the semantic source anchor. This lets
two edges with the same target and relationship type remain distinct when the
source objects are different, for example:

```text
203.0.113.11 -> belongs-to -> AS64513
203.0.113.0/25 -> belongs-to -> AS64513
```

Without the source anchor, infrastructure knowledge would be incorrectly
collapsed and OpenCTI would lose useful graph edges.

## Validated Infrastructure Flow

The controlled validation report
`NarrowCTI native ASN graph validation 20260625` proved this native flow:

```text
Infrastructure
  -> consists-of -> Autonomous-System
  -> consists-of -> IPv4-Addr
  -> consists-of -> IPv4 CIDR

IPv4-Addr
  -> belongs-to -> Autonomous-System

IPv4 CIDR
  -> belongs-to -> Autonomous-System
```

The final lookup-backed run found the existing Infrastructure, ASN, IP and CIDR
objects, exported no new graph objects, and imported the six expected
relationships into OpenCTI.

## Remaining Architecture Work

- Validate real MISP object payloads for ASN, netblock, domain-ip and ip-port
  evidence.
- Validate whether OTX payloads or enrichment responses provide source-backed
  ASN/netblock evidence.
- Add optional offline-first IP-to-ASN enrichment providers.
- Extend source mapping so actor, malware, campaign, sector, location, ATT&CK,
  Diamond, Timeline and Kill Chain context can be emitted together when source
  evidence supports it.
- Keep unsupported or weakly supported relationships held, quarantined or
  audit-only instead of guessing attribution.
