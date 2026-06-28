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
| Autonomous System | `autonomous-system` SCO | Supported by the local STIX library and validated through native NarrowCTI export. OpenCTI stores it under `stixCyberObservables`. |
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
NARROWCTI_IP_ASN_ENRICHMENT_FILE=
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

## OpenCTI Knowledge, Diamond, Timeline And Kill Chain

The infrastructure model is expected to feed multiple OpenCTI views, but each
view depends on different graph material.

### Knowledge

Knowledge is fed when NarrowCTI exports graph objects and relationships, not
only Report references.

Already validated:

- `Infrastructure -> consists-of -> Autonomous-System`
- `Infrastructure -> consists-of -> IPv4-Addr`
- `Infrastructure -> consists-of -> IPv4-Addr` with CIDR value
- `IPv4-Addr -> belongs-to -> Autonomous-System`
- `IPv4-Addr CIDR -> belongs-to -> Autonomous-System`

This means ASN/IP infrastructure intelligence can become navigable OpenCTI
knowledge when the source evidence supports those relationships.

### Diamond

The Diamond-style analyst experience is a composition of graph relationships.
NarrowCTI should provide the four core pivots:

| Diamond facet | NarrowCTI/OpenCTI material |
| --- | --- |
| Adversary | `threat-actor` or `intrusion-set` |
| Capability | `malware`, `tool`, `vulnerability` and `attack-pattern` |
| Infrastructure | `infrastructure`, `ipv4-addr`, `ipv6-addr`, CIDR values and `autonomous-system` |
| Victimology | `identity` sectors, organizations, countries, regions and other locations |

The ASN/IP validation proved the infrastructure facet. Full Diamond population
requires the same curated bundle, or correlated source evidence, to also carry
actor, arsenal/TTP and victimology relationships such as:

```text
actor -> uses -> malware/tool/infrastructure/attack-pattern
actor -> targets -> sector/location/organization
infrastructure -> consists-of -> IP/CIDR/ASN
IP/CIDR -> belongs-to -> ASN
```

NarrowCTI should hold or quarantine unsupported Diamond edges rather than
guessing attribution from weak IOC-only evidence.

### Timeline

Timeline depends on timestamped entities and relationships.

Already validated:

- Controlled ASN/IP Infrastructure Reports include OpenCTI `created`,
  `modified` and `published` timestamps.
- OTX/MISP adapters preserve source `created`, `modified`, `first_seen` and
  `last_seen` evidence in metadata and graph candidate attributes.

Implementation gap:

- The graph exporter still needs broader source-time mapping so promoted
  Infrastructure, observable and relationship objects can carry the most useful
  source-backed temporal fields instead of only import time.

### Kill Chain

Kill Chain is primarily fed by ATT&CK `attack-pattern` objects and their
`killChainPhases`.

Already validated:

- The local OpenCTI MITRE baseline contains canonical ATT&CK techniques such as
  `T1059 Command and Scripting Interpreter`.
- `T1059` has `kill_chain_name=mitre-attack` and `phase_name=execution`.
- NarrowCTI can reference canonical ATT&CK objects instead of creating
  duplicate attack-patterns.
- For OTX single-adversary infrastructure inference, NarrowCTI emits
  source-backed `Infrastructure -> related-to -> Attack Pattern` relationships
  in addition to actor-to-technique relationships. This is required because the
  OpenCTI Infrastructure view should not be expected to inherit ATT&CK context
  through an indirect actor relationship. Local OpenCTI 6.9.4 validation showed
  that `Infrastructure -> uses -> Attack Pattern` is rejected by relationship
  consistency checks, while `related-to` is the compatible direct edge for this
  object pair.
- OTX author/source provenance is retained as report author and audit
  metadata, but the OTX extractor no longer promotes that provenance as a
  graph `Organization` object. Organizations should represent victimology,
  source-backed targets or meaningful CTI entities, not feed bookkeeping.
- OTX source-provided `ASN`/`AS` indicators are normalized into
  `autonomous_system` candidates. Source-provided `CIDR`/`netblock` style
  indicators are normalized as IP observables with CIDR values. When the same
  pulse has exactly one adversary, those objects are attached to the inferred
  Infrastructure through `consists-of`; when attribution is ambiguous, the ASN
  remains related evidence and is not anchored to Infrastructure.

Fallback behavior:

- If NarrowCTI creates an attack-pattern itself because no canonical OpenCTI
  ATT&CK object is available, the graph STIX builder now preserves
  source-backed `kill_chain_phases` carried by the candidate. The preferred
  production posture is still to use the official MITRE connector for
  canonical ATT&CK loading and let NarrowCTI link curated source evidence to
  those canonical techniques.

The decision audit and future enterprise CTI report should summarize:

- Top ASNs observed.
- Malicious IP count by ASN.
- Distinct sources reporting the ASN or IP.
- Actors, malware families, campaigns and sectors associated with the same
  infrastructure.
- Confidence and provenance for each relationship.
- Whether the relationship was promoted, deduplicated, held, quarantined or
  released by an analyst.

## Lab Validation Evidence

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
- Native NarrowCTI export can now build and import the same ASN/IP/CIDR model
  without a hand-built STIX bundle.
- The lookup-backed native export can reference existing Infrastructure, ASN,
  IP and CIDR objects instead of recreating them.
- Generic NarrowCTI `observable` candidates can safely reference concrete
  OpenCTI SCO ids such as `ipv4-addr--...` during export.
- Relationship deduplication now distinguishes semantic source anchors, so
  `IP -> belongs-to -> ASN` and `CIDR -> belongs-to -> ASN` can coexist for
  the same ASN.

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

Native NarrowCTI validation on June 25, 2026 used the controlled report
`NarrowCTI native ASN graph validation 20260625`.

The final lookup-backed export produced:

| Evidence | Result |
| --- | --- |
| Existing graph entities found by lookup | 4 |
| New graph objects exported | 0 |
| Existing references in the bundle | 1 Infrastructure, 1 Autonomous-System, 2 Observables |
| Relationships imported | 6 |
| OpenCTI object counts after import | 1 Infrastructure, 1 ASN, 1 IP, 1 CIDR, 1 Report |
| Queryable semantic relationships | `Infrastructure -> ASN`, `Infrastructure -> IP`, `Infrastructure -> CIDR`, `IP -> ASN`, `CIDR -> ASN` |

Real OTX actor-infrastructure validation on June 25, 2026 used pulse
`61f9392ac64510da57b9cdf9`.

Source-backed curation decisions:

- OTX `adversary=Lazarus` was treated as an Intrusion Set and resolved to the
  existing OpenCTI `Lazarus Group` object through curated alias lookup.
- OTX `malware_families=Lazarus` was not promoted as Malware because it
  duplicated the adversary value.
- The pulse contained exactly one adversary and two network observables, so
  NarrowCTI created one inferred Infrastructure object for that pulse.

Imported OpenCTI graph evidence:

| Evidence | Result |
| --- | --- |
| Report | `Lazarus APT ... Windows update service and Github C2`, confidence `65`, author `OTX AlienVault` |
| Canonical Intrusion Set | Existing `Lazarus Group`, not duplicated |
| Infrastructure | `Lazarus OTX observed infrastructure 61f9392a` |
| Infrastructure members | `markettrendingcenter.com`, `lm-career.com` |
| Victimology | `Lazarus Group -> targets -> Defense` |
| Actor infrastructure | `Lazarus Group -> uses -> Lazarus OTX observed infrastructure 61f9392a` |
| Infrastructure membership | Infrastructure `consists-of` both domain observables |
| ATT&CK context | 10 canonical Attack Patterns referenced from OpenCTI |
| Kill-chain coverage | `initial-access`, `execution`, `command-and-control`, `persistence`, `privilege-escalation`, `defense-evasion`, `stealth` |
| Infrastructure ATT&CK context | 10 direct `Infrastructure -> related-to -> Attack Pattern` relationships imported and queryable from the Infrastructure object |
| Organization hygiene | OTX pulse author `hitip_forever` is no longer promoted as a Report object; only `OTX AlienVault` remains as report author metadata |

Controlled MISP infrastructure validation on June 25, 2026 used local MISP
event `4390`
(`NarrowCTI MISP infrastructure export validation 1782423797`).

The local MISP lab contained events with objects, but the first 250 reviewed
events only exposed `file` and `virustotal-report` object types. No real local
feed sample carried `asn`, `netblock`, `domain-ip` or `ip-port` objects, so
the validation event was created with official MISP object templates for
`asn`, `domain-ip` and `ip-port`. The local MISP instance did not expose a
`netblock` template by that exact name; CIDR behavior was validated through the
ASN template `subnet-announced` attribute.

Imported MISP graph evidence:

| Evidence | Result |
| --- | --- |
| Report | `NarrowCTI MISP infrastructure export validation 1782423797`, author `MISP` |
| Infrastructure | `MISP domain-ip narrow-validation.example.com` |
| Infrastructure | `MISP ip-port 203.0.113.20` |
| ASN | `AS64512 NarrowCTI Validation ASN`, one canonical Autonomous-System observable |
| Domain observable | `narrow-validation.example.com`, one canonical Domain-Name observable |
| IP observables | `203.0.113.10`, `203.0.113.20`, `203.0.113.0/24` |
| Infrastructure membership | Both Infrastructure objects expose queryable `consists-of` relationships to their observables and ASN where source-backed |
| ASN membership | `203.0.113.20 -> belongs-to -> AS64512` and `203.0.113.0/24 -> belongs-to -> AS64512` imported and queried successfully |
| Report hygiene | Report object refs contain Infrastructure, Autonomous-System, Domain-Name and IPv4 objects only; MISP provenance remains author/audit metadata |

The MISP extraction also canonicalizes `AS64512` variants inside one event and
prevents port values such as `443` or `8443` from being misclassified as ASNs.
For bounded validation and replay, operators can use `MISP_QUERIES=event:<id>`
or `MISP_QUERIES=uuid:<uuid>` to load one event directly instead of running a
broad `events/restSearch` query.

Additional real MISP validation on June 28, 2026 closed the main
source-payload shape gap for top-level `AS` and `domain|ip` attributes:

| Evidence | Result |
| --- | --- |
| MISP `event:1442` | Top-level `AS=327712` promoted as Autonomous-System evidence |
| OpenCTI API | `Report -> related-to -> Autonomous-System` relationship returned with destination entity type `Autonomous-System` and number `327712`; NarrowCTI emits fallback name `AS327712` when the source does not provide an AS organization name |
| MISP `event:5280` | 49 top-level `domain|ip` attributes promoted as Infrastructure evidence |
| OpenCTI API | Infrastructure `MISP domain-ip arabica.podzone.net`, Domain-Name `arabica.podzone.net`, IPv4 `178.128.103.24` and report `OceanLotus - WateringHole - Framework B 2018` returned with author `MISP via NarrowCTI` |
| Graph export summary | `event:5280` created 145 entities and 147 relationships in the OpenCTI lab |

Open questions before broad activation:

- Confirm the same relationships visually in OpenCTI's graph and knowledge UI,
  not only via GraphQL.
- Validate `IPv6-Addr -> belongs-to -> Autonomous-System` visually in OpenCTI.
  Unit-level STIX builder coverage confirms the relationship direction and
  object materialization contract.
- Validate how noisy broad ASN searches become in larger OpenCTI datasets.
- Validate true external MISP feed samples that carry netblock metadata; real
  `AS`, `domain|ip` and `ip-src|port`/`ip-dst|port` feed shape coverage is now
  validated.
- Validate true OTX feed payloads that carry ASN/netblock metadata; unit-level
  source-provided ASN/CIDR extraction is implemented, but live feed shape
  coverage still needs evidence.
- Validate optional offline IP-to-ASN enrichment against broader external
  datasets and graph noise. The initial v0.8 implementation is opt-in for MISP
  through `NARROWCTI_IP_ASN_ENRICHMENT_FILE`; unit coverage confirms that when
  an explicit Infrastructure object anchors the IP, the enrichment emits both
  `IP -> belongs-to -> ASN` and `Infrastructure -> consists-of -> ASN`.
- Validate whether source payloads provide enough actor, malware, sector,
  location and campaign context to populate Diamond, Timeline and Knowledge
  views from the same curated bundle.

## Backlog

Safe implementation sequence:

1. Done: add unit-level STIX support for `autonomous-system` observable
   candidates.
2. Done: add OpenCTI exact lookup support for ASN/IP/CIDR cyber observables
   through `stixCyberObservables`.
3. Done: add controlled native graph export for ASN/IP/CIDR relationships when
   candidates are explicitly accepted by policy.
4. Done: add OTX single-adversary network observable infrastructure inference
   for bounded actor infrastructure validation.
5. Done: add MISP metadata extraction for ASN/netblock/domain-ip/ip-port
   objects.
6. Done: validate controlled MISP `asn`, `domain-ip` and `ip-port` object
   export against OpenCTI, including Report hygiene and direct event replay.
7. Done: add OTX source-provided ASN/CIDR metadata extraction when OTX payloads
   include `ASN`, `AS`, `CIDR` or netblock-style indicators.
8. Validate true OTX feed samples that carry ASN/netblock evidence and confirm
   OpenCTI import/UI behavior.
9. Done: add optional IP-to-ASN enrichment provider interface with
   offline-first behavior. The initial MISP integration supports CSV, JSON,
   JSONL, longest-prefix matching and strict provenance, and is disabled unless
   `NARROWCTI_IP_ASN_ENRICHMENT_FILE` is set.
10. Done: add relationship evidence for IP belongs-to ASN and Infrastructure
   consists-of ASN/IP when the source or offline enrichment supports it and an
   explicit Infrastructure anchor is present.
11. Done: add curation report sections for ASN concentration, shared
   infrastructure and actor/malware/infrastructure overlaps. The report remains
   evidence-only and derives these sections from decision-audit graph evidence.
12. Done: validate true MISP top-level `AS` and `domain|ip` feed samples
   against OpenCTI API after real export. Netblock feed-shape validation remains
   pending until a safe source event carries explicit netblock evidence.

This backlog is intentionally staged. The product value is very high, but the
risk of graph pollution is also high if ASN and IP relationships are promoted
without source-backed provenance.
