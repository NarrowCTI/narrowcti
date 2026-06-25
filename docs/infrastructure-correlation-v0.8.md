# Infrastructure Correlation - ASN And IP Enrichment

## Purpose

This document defines the enterprise infrastructure-intelligence direction for
NarrowCTI.

The goal is to move beyond flat IOC ingestion and let NarrowCTI curate the
operational infrastructure behind threat activity. Analysts should be able to
start from an actor, malware family, infrastructure name, IP address, network
range or ASN and understand how those artifacts relate to campaigns, arsenal,
TTPs, sectors and victimology.

## Product Goal

NarrowCTI should treat infrastructure as graph knowledge, not only as raw
network indicators.

The target analyst experience is:

```text
Threat actor or intrusion set
  -> uses malware/tool
  -> uses infrastructure
  -> infrastructure contains IPs, domains, URLs, ranges and ASNs
  -> IP belongs to ASN
  -> ASN exposes related malicious IPs/ranges observed by curated sources
  -> all relationships remain source-backed, scored, deduplicated and auditable
```

This is the same product direction as the broader graph promotion work: raw
data becomes explainable, correlated intelligence before it reaches OpenCTI.

## STIX And OpenCTI Mapping

The intended mapping is:

| Intelligence concept | STIX/OpenCTI object | Notes |
| --- | --- | --- |
| Curated threat infrastructure cluster | `infrastructure` SDO | Populates `Observations / Infrastructures`; must require explicit source evidence or analyst release. |
| IPv4 address | `ipv4-addr` SCO | Already supported as observable candidate. |
| IPv6 address | `ipv6-addr` SCO | Already supported as observable candidate. |
| Network range or CIDR | `ipv4-addr` / `ipv6-addr` SCO with CIDR value where accepted by STIX/OpenCTI | Requires OpenCTI lab validation before broad export. |
| Autonomous System | `autonomous-system` SCO | Supported by the local STIX library; OpenCTI ingestion/rendering must be validated before export gate activation. |
| Actor or intrusion set uses infrastructure | STIX `uses` relationship | Source must support attribution or NarrowCTI must hold it for review. |
| Infrastructure contains IP/domain/ASN | STIX `consists-of` or OpenCTI-supported relationship | Requires lab validation because OpenCTI rendering can vary by object type. |
| IP belongs to ASN | STIX/OpenCTI `belongs-to` relationship | Requires lab validation and source/enrichment provenance. |

OpenCTI should remain the graph and visualization layer. NarrowCTI should own
normalization, scoring, provenance, enrichment, deduplication and decision
audit before export.

## Curation Rules

NarrowCTI must not infer that every IP, domain or URL is an Infrastructure
object.

Safe promotion rules:

- Raw network artifacts remain Indicators or Observables by default.
- A curated `infrastructure` candidate is created only when the source provides
  explicit infrastructure context, actor/malware/campaign anchoring, object
  relationships, or an analyst releases the candidate from review.
- ASN enrichment must record where the ASN came from: source payload,
  MISP object, OTX pulse metadata, passive DNS/BGP enrichment provider, or
  analyst review.
- Actor-to-infrastructure attribution must require strong provenance. If the
  source only says an IP is malicious, NarrowCTI can attach it to a Report, but
  should not automatically claim an actor uses that infrastructure.
- Multiple threats sharing the same ASN should increase correlation evidence,
  not automatically prove common operator control.

## Enrichment Sources

The first implementation should support source-provided metadata. Later
implementations can add optional enrichment providers.

Candidate enrichment providers:

- Local/offline ASN database.
- Team Cymru-style IP-to-ASN lookup.
- RIPEstat/BGPView-style ASN and prefix metadata.
- MaxMind or similar commercial/local network metadata.
- MISP object attributes that already include ASN, netblock, domain-ip,
  ip-port or infrastructure relationships.
- Future URLHaus, MalwareBazaar, AbuseIPDB and passive DNS style feeds.

Provider usage must be configurable and auditable because enterprise
environments may require offline operation.

Future configuration should follow the existing visible-policy pattern:

```text
NARROWCTI_INFRA_ASN_ENRICHMENT_ENABLED=false
NARROWCTI_INFRA_ASN_PROVIDER=disabled
NARROWCTI_INFRA_PROMOTE_ASN=false
NARROWCTI_INFRA_PROMOTE_CIDR=false
NARROWCTI_INFRA_MIN_SHARED_THREAT_COUNT=2
NARROWCTI_INFRA_REQUIRE_ATTRIBUTION_PROVENANCE=true
NARROWCTI_INFRA_ALLOWED_RELATIONSHIPS=uses,consists-of,belongs-to
```

## Correlation Model

Infrastructure correlation should produce explainable evidence such as:

- `actor -> uses -> infrastructure`
- `malware -> uses -> infrastructure`
- `infrastructure -> consists-of -> ipv4-addr`
- `infrastructure -> consists-of -> autonomous-system`
- `ipv4-addr -> belongs-to -> autonomous-system`
- `report -> related-to -> infrastructure`

The decision audit and future enterprise CTI report should summarize:

- Top ASNs observed.
- Malicious IP count by ASN.
- Distinct sources reporting the ASN or IP.
- Actors, malware families, campaigns and sectors associated with the same
  infrastructure.
- Confidence and provenance for each relationship.
- Whether the relationship was promoted, deduplicated, held, quarantined or
  released by an analyst.

## Open Questions For Lab Validation

Observed local validation on June 25, 2026 confirmed:

- STIX `autonomous-system` imports into OpenCTI as
  `entity_type=Autonomous-System` under `stixCyberObservables`.
- OpenCTI does not expose a direct `autonomousSystems` GraphQL collection in
  this lab version; ASN lookup should use `stixCyberObservables`.
- `Infrastructure -> consists-of -> Autonomous-System` imports and is
  queryable through `stixCoreRelationships(fromId=...)`.
- `Infrastructure -> consists-of -> IPv4-Addr` imports and is queryable.
- `Infrastructure -> consists-of -> IPv4-Addr` with CIDR value imports and is
  queryable.
- `IPv4-Addr -> belongs-to -> Autonomous-System` imports and is queryable.
- `IPv4-Addr CIDR -> belongs-to -> Autonomous-System` imports and is queryable.
- Reimporting the same deterministic STIX bundle did not duplicate the
  controlled Infrastructure, ASN, IP, CIDR or Report objects.

Controlled validation objects:

| Object | OpenCTI result |
| --- | --- |
| `NarrowCTI ASN Correlation Infrastructure 20260625` | `Infrastructure`, `standard_id=infrastructure--2158da19-f14f-5e17-8289-ffa0034153c1` |
| `AS64512 NarrowCTI Validation ASN` | `Autonomous-System`, `standard_id=autonomous-system--f70107cd-c76d-511f-980d-a4ab7f4a9aad` |
| `203.0.113.10` | `IPv4-Addr`, `standard_id=ipv4-addr--570130c0-7daf-5d1e-992f-58b53b447312` |
| `203.0.113.0/24` | `IPv4-Addr`, `standard_id=ipv4-addr--a0895f10-d89d-56ad-a4a4-dc873ee08b8c` |

Observed relationships:

| Relationship | Result |
| --- | --- |
| Infrastructure `consists-of` ASN | Imported and queryable. |
| Infrastructure `consists-of` IP | Imported and queryable. |
| Infrastructure `consists-of` CIDR | Imported and queryable. |
| IP `belongs-to` ASN | Imported and queryable. |
| CIDR `belongs-to` ASN | Imported and queryable. |

Open questions before broad activation:

- Confirm the same relationships visually in OpenCTI's graph and knowledge UI,
  not only via GraphQL.
- Validate `IPv6-Addr -> belongs-to -> Autonomous-System`.
- Validate how noisy broad ASN searches become in larger OpenCTI datasets.
- Add exact lookup helpers because broad `stixCyberObservables(search=...)`
  can return unrelated objects for CIDR-like search strings.
- Validate real MISP/OTX payloads that carry ASN/netblock metadata before
  enabling source-driven ASN promotion.

## Backlog

Safe implementation sequence:

1. Add unit-level STIX support for `autonomous-system` observable candidates.
2. Add OpenCTI exact lookup support for ASN/IP/CIDR cyber observables through
   `stixCyberObservables`.
3. Add controlled graph export for ASN only when explicitly allow-listed.
4. Add MISP metadata extraction for ASN/netblock/domain-ip/ip-port objects.
5. Add optional IP-to-ASN enrichment provider interface with offline-first
   behavior.
6. Add relationship evidence for IP belongs-to ASN and infrastructure
   consists-of ASN/IP when the source supports it.
7. Add curation report sections for ASN concentration, shared infrastructure
   and actor/malware/infrastructure overlaps.

This backlog is intentionally staged. The product value is very high, but the
risk of graph pollution is also high if ASN and IP relationships are promoted
without source-backed provenance.
