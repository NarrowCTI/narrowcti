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

## OpenCTI Reasoning Boundary

OpenCTI Rules Engine is a post-ingestion reasoning layer. It can infer new
relationships from relationships that already exist in OpenCTI. NarrowCTI is a
pre-ingestion curation gateway. It must decide what source evidence is strong
enough to export before OpenCTI receives it.

The intended sequence is:

```text
NarrowCTI curated graph export
  -> OpenCTI direct source-backed relationships
  -> optional OpenCTI inference rules
  -> inferred relationships visible in OpenCTI graph/knowledge views
```

NarrowCTI must not depend on OpenCTI inference rules for core correctness. The
Rules Engine can complement NarrowCTI by propagating safe relationships such as
parent ATT&CK technique usage, report location context and targeting through a
location or identity hierarchy. Rules that can create broad transitive
`related-to` or attribution chains must remain disabled until graph noise is
measured.

The operational posture and rule activation matrix are documented in
`docs/opencti-rules-engine-v0.8.md`.

## OpenCTI Mapping Boundary

The tab-level coverage matrix is tracked in
`docs/opencti-coverage-matrix-v0.8.md`. This section describes the architecture
boundary; the matrix shows which OpenCTI areas are validated, supported,
partial, held by design or still in backlog.

| NarrowCTI concept | STIX/OpenCTI target | Current v0.8 posture |
| --- | --- | --- |
| Report context | `report` | Deterministic report ids reduce duplicate report rows. |
| IOC indicator | `indicator` | Existing behavior remains active. |
| Observable | Concrete SCO such as `ipv4-addr`, `domain-name`, `url`, `email-addr` | Supported for graph candidates and exact OpenCTI lookup. |
| Artifact | `artifact` under `stixCyberObservables` | Controlled export and lookup validated only for explicit artifact metadata with a supported hash algorithm/value; generic file hashes are not promoted automatically. |
| Infrastructure | `infrastructure` | Controlled promotion only when explicit source evidence exists. |
| Autonomous System | `autonomous-system` under `stixCyberObservables` | Native export and lookup validated. |
| IP/CIDR to ASN | `belongs-to` relationship | Native export and GraphQL validation completed for IPv4 and CIDR. |
| Infrastructure contains IP/CIDR/ASN | `consists-of` relationship | Native export and GraphQL validation completed. |
| MITRE technique | Canonical `attack-pattern` | Prefer official MITRE connector object and link to it. |
| MITRE data source | `x-mitre-data-source` | Exportable as curated Data Source context anchored to the source technique, with exact OpenCTI lookup through `dataSources`. |
| MITRE data component | `x-mitre-data-component` | Exportable from component-aware MITRE data source strings such as `Process: Process Creation`, with exact OpenCTI lookup through `dataComponents`. |
| MITRE tactic/platform | Candidate evidence and Attack Pattern metadata | Preserved for policy, scoring, kill-chain/platform context; not in the default export gate until OpenCTI object behavior is validated. |
| Course of Action | `course-of-action` | Supported for explicit source-backed course-of-action Galaxy evidence, with exact OpenCTI lookup through `coursesOfAction`; detection guidance remains Notes. |
| Campaign | `campaign` | Supported for MISP Galaxy campaign evidence with OpenCTI lookup by name before creation. |
| Threat Actor Group | `threat-actor` | Supported for source-backed group-style actors, with exact OpenCTI lookup through `threatActorsGroup`. |
| Threat Actor Individual | Native OpenCTI `ThreatActorIndividual` via GraphQL | Controlled native export and exact lookup validated; it is intentionally excluded from generic STIX `threat-actor` import so OpenCTI does not materialize individual actors as the wrong Threats tab. Native objects are linked back to the imported Report with OpenCTI `reportEdit.relationAdd(object)`. |
| Target organization | `identity` with `organization` class | Supported only for explicit victimology/target metadata, not feed provenance; exact OpenCTI lookup uses `organizations`. |
| Target individual | `identity` with `individual` class | Supported only for explicit victimology/person metadata such as `targeted-person` or `victim-individual`; exact OpenCTI lookup uses `individuals`, and threat-actor individuals remain a separate Threats taxonomy. |
| Security Platform | Native OpenCTI `SecurityPlatform` via GraphQL | Controlled native export and exact lookup validated; it is intentionally excluded from STIX Identity import because the local OpenCTI lab materialized `identity_class=securityplatform` as Organization. After the Report bundle is imported, NarrowCTI links the native object back to the Report with OpenCTI `reportEdit.relationAdd(object)` so container context is visible without creating fake CTI semantics. |
| Detection guidance and MISP EventReport | `note` | Exportable as analyst context while preserving source provenance. |
| Detection rule | `indicator` | Exportable as pattern-aware Indicator for YARA, Sigma, Snort, Suricata and PCRE. Detection-rule Indicators use canonical names, labels, source external references and descriptions to improve OpenCTI discoverability while staying inside the native Indicator workflow. |
| MISP ObjectReference | `relationship` | Exportable only when both source and target UUIDs resolve to graph objects. |
| MISP sighting | `sighting` | Exportable only when the sighted value resolves to an Indicator SDO. |
| Malware/tool/vulnerability/actor/location/sector | Matching OpenCTI SDOs | Supported incrementally with conservative lookup and source-backed promotion; target sectors use exact lookup through `sectors`. |

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

Raw IoCs and curated Infrastructure are separate concepts. An IP, domain, URL
or hash can be valuable as an Indicator or Observable without being promoted to
`Infrastructure`. NarrowCTI should create or reuse Infrastructure only when the
source provides explicit infrastructure context, a bounded source rule supports
inferred infrastructure, or an analyst releases that promotion. When an
Infrastructure object does exist, supported network evidence such as IPs,
domains, CIDRs and ASNs should be related to it with OpenCTI-compatible
relationships such as `consists-of`; otherwise standalone IoCs should remain
standalone observations.

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

## Validated OTX Actor Infrastructure Flow

The bounded real OTX validation on June 25, 2026 used pulse
`61f9392ac64510da57b9cdf9`
(`Lazarus APT ... Windows update service and Github C2`). The payload carried
one adversary, 10 ATT&CK techniques, sector `Defense`, 12 observables and two
network observables.

NarrowCTI applied the following graph hygiene before export:

- OTX `adversary` is promoted as an `intrusion-set` candidate, not a generic
  threat actor, so ATT&CK group objects can be reused.
- The curated alias `Lazarus` resolves to existing OpenCTI `Intrusion-Set`
  `Lazarus Group` instead of creating a duplicate actor object.
- OTX `malware_families` values that equal the adversary name are held out of
  Arsenal promotion, preventing source noise such as `Malware Lazarus`.
- A source-backed inferred Infrastructure is created only when a pulse has a
  single adversary and at least one network observable.
- OTX source-provided `ASN`/`AS` indicators become Autonomous-System graph
  candidates, and `CIDR`/`netblock` style indicators become IP observables
  with normalized CIDR values.
- ASN and CIDR evidence attaches to the inferred Infrastructure with
  `consists-of` only when the pulse has one adversary. If OTX provides ASN
  evidence without a single adversary anchor, NarrowCTI keeps it as related
  evidence instead of claiming infrastructure attribution.
- OTX author/source provenance is preserved as report author and audit
  metadata, but is not promoted as a graph `Organization` object by the OTX
  entity extractor.

The imported OpenCTI graph validated:

```text
Intrusion-Set Lazarus Group
  -> uses -> Infrastructure Lazarus OTX observed infrastructure 61f9392a
  -> targets -> Sector Defense
  -> uses -> canonical ATT&CK attack-patterns

Infrastructure Lazarus OTX observed infrastructure 61f9392a
  -> consists-of -> Domain-Name markettrendingcenter.com
  -> consists-of -> Domain-Name lm-career.com
  -> related-to -> canonical ATT&CK attack-patterns
```

The report also referenced 10 canonical ATT&CK techniques with kill-chain
phases including initial-access, execution, command-and-control, persistence,
privilege-escalation, defense-evasion and stealth. When the Infrastructure is
inferred from the same single-adversary OTX pulse, NarrowCTI also exports direct
`Infrastructure -> related-to -> Attack Pattern` relationships so the OpenCTI
Infrastructure view can expose source-backed ATT&CK context without depending
on indirect traversal through the actor. Local OpenCTI 6.9.4 rejects
`Infrastructure -> uses -> Attack Pattern`, so `related-to` is the compatible
relationship for this object pair.

## Validated MISP Infrastructure Object Flow

The controlled MISP validation on June 25, 2026 used local event `4390`
(`NarrowCTI MISP infrastructure export validation 1782423797`) with official
MISP object templates for `asn`, `domain-ip` and `ip-port`.

NarrowCTI applied the following graph hygiene before export:

- MISP `asn`, `domain-ip`, `ip-port` and netblock-style values are normalized
  into Infrastructure, Autonomous-System and concrete observable candidates.
- ASN values are canonicalized inside the event, so `AS64512` and
  `AS64512 NarrowCTI Validation ASN` converge on one Autonomous-System object.
- Port fields are not treated as ASNs.
- MISP source provenance is preserved as OpenCTI Report author and NarrowCTI
  audit metadata, but is not automatically promoted as an Organization object.
- In real `export` mode, safe graph defaults hold feed bookkeeping candidates
  such as `collector`, `source_identity`, labels and markings unless the
  operator explicitly allow-lists them.

The imported OpenCTI graph validated:

```text
Infrastructure MISP domain-ip narrow-validation.example.com
  -> consists-of -> Domain-Name narrow-validation.example.com
  -> consists-of -> IPv4-Addr 203.0.113.10

Infrastructure MISP ip-port 203.0.113.20
  -> consists-of -> IPv4-Addr 203.0.113.20
  -> consists-of -> Autonomous-System AS64512 NarrowCTI Validation ASN

IPv4-Addr 203.0.113.20
  -> belongs-to -> Autonomous-System AS64512 NarrowCTI Validation ASN

IPv4-Addr 203.0.113.0/24
  -> belongs-to -> Autonomous-System AS64512 NarrowCTI Validation ASN
```

The local MISP lab did not contain real feed events with these object types in
the first 250 reviewed events. The controlled template validation proves the
NarrowCTI mapping and OpenCTI import behavior; broader external MISP feed
coverage remains a source-validation task.

## Remaining Architecture Work

- Validate true external MISP feed payloads for ASN/netblock/domain-ip/ip-port
  evidence now that controlled MISP object-template export is validated.
- Validate true OTX feed payloads that carry source-backed ASN/netblock
  evidence now that unit-level OTX ASN/CIDR extraction is implemented.
- Add optional offline-first IP-to-ASN enrichment providers.
- Extend source mapping so actor, malware, campaign, sector, location, ATT&CK,
  Diamond, Timeline and Kill Chain context can be emitted together when source
  evidence supports it.
- Keep unsupported or weakly supported relationships held, quarantined or
  audit-only instead of guessing attribution.
