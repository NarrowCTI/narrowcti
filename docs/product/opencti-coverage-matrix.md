# Current OpenCTI Coverage Matrix

This is the current v1.0 coverage view. The historical v0.8 matrix remains in
`opencti-coverage-matrix-v0.8.md`; this document prevents operators from
mistaking an old snapshot for the current product contract.

## Status Legend

- **Validated**: code path, controlled evidence and OpenCTI behavior agree.
- **Source-dependent**: implemented, but the source event must carry the
  relevant metadata.
- **Opt-in**: promotion requires an explicit switch and bounded validation.
- **Backlog**: not a v1.0 release claim.

## Matrix

| OpenCTI area | NarrowCTI representation | Status | Evidence and boundary |
| --- | --- | --- | --- |
| Threat actors / intrusion sets | `threat-actor`, `intrusion-set`, individual threat actor | Source-dependent | MISP Galaxy and explicit OTX/MISP actor evidence; ambiguous multiple actors do not create attribution edges |
| Campaigns | `campaign` | Validated, source-dependent | Explicit MISP `campaign-name` or Galaxy campaign; Report title alone is insufficient |
| Arsenal / malware | `malware` | Validated, source-dependent | MISP Galaxy, OTX extraction and canonical lookup; deduplication required |
| Arsenal / tools and channels | `tool`, `channel` | Validated, source-dependent | Explicit source metadata; Campaign context can relate a same-event capability with `uses` |
| Techniques / attack patterns | `attack-pattern` | Validated | ATT&CK ids resolve through canonical context; Kill Chain audit lists resolved techniques |
| Detection rules | Sigma/YARA/Snort/Suricata/PCRE indicators or Notes | Validated, source-dependent | Syntax validation and OpenCTI-compatible Sigma parser; multiline content is preserved |
| Sectors | OpenCTI sector identity | Source-dependent | MISP Galaxy meta and explicit target fields; no title-only sector inference |
| Organizations and systems | Victimology-scoped identity | Source-dependent | Explicit target organization/system evidence only; collector identities are not victims |
| Locations | Country, region, administrative area, city or position | Source-dependent | Explicit MISP/OTX location evidence and normalized values |
| Infrastructure | OpenCTI Infrastructure plus Observables | Validated, source-dependent | Infrastructure requires explicit source infrastructure context; raw IP/domain is not automatically promoted |
| ASN and netblock | Autonomous System and IPv4/IPv6 observable | Validated | `belongs-to` relation is retained when ASN/netblock evidence exists; enrichment is offline/configurable |
| Infrastructure Diamond | Adversary, capability, infrastructure and victimology edges | Opt-in/source-dependent | Same-event actor/campaign/capability/target propagation; missing source quadrants remain missing |
| Timeline | STIX start/stop and source dates | Source-dependent | Dates are preserved and normalized when provided by the source |
| Kill Chain | ATT&CK relationship inventory | Validated, source-dependent | Present when ATT&CK techniques resolve; no technique is invented for an ASN or raw IP |
| Sightings | STIX Sightings | Source-dependent | MISP sightings export when the Indicator target resolves |
| Object references | STIX Relationships | Source-dependent | Both UUID endpoints must resolve to promoted graph objects |

## Real Evidence Snapshot

- OTX Lumma Stealer: 36 relationships, 35 ATT&CK techniques and Kill Chain
  present. Actor, infrastructure and victimology were absent from that pulse.
- MISP event 1649: infrastructure object with 30 relationships and 24 ATT&CK
  techniques; the event did not support every Diamond quadrant directly.
- MISP event 7: explicit `campaign-name=Dust Storm` was found, but the event
  carried no structured actor, infrastructure or victimology metadata. The
  correct result is a campaign linked to its Report, not fabricated targets.
- MISP event 1578: Sandworm and target metadata produced broad ATT&CK,
  adversary and victimology relationships.
- MISP event 5505: `178.21.14.0/23 belongs-to AS49352` was confirmed.

## Propagation Rules

When a MISP event contains all required evidence in one bounded context,
NarrowCTI may emit:

```text
Campaign -> attributed-to -> one explicit actor
Campaign -> uses -> malware/tool/channel/attack-pattern
Campaign -> uses -> Infrastructure
Campaign -> targets -> sector/location/organization/system
Actor -> uses -> Infrastructure
Infrastructure -> targets -> sector/location/organization/system
```

Each relation carries `relationship_source_value`, `relationship_source_field`,
`relationship_context_scope` and `relationship_inference`. Multiple actors
prevent automatic attribution. Infrastructure victimology remains opt-in and
must be verified through the OpenCTI API and Diamond view before production
activation.

## Known v1.0 Boundaries

The following are intentionally not release claims:

- deriving a campaign, actor or sector only from a Report title;
- enriching ASN or IP objects with ATT&CK without source-backed evidence;
- automatically filling all OpenCTI tabs when a feed does not carry those
  fields;
- creating duplicate malware or Report objects to make a view look richer;
- inferring victimology from broad geopolitical language without an explicit
  source field or reviewed rule.
