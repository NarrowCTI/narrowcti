# OpenCTI Rules Engine And NarrowCTI

## Purpose

This document defines how NarrowCTI should coexist with the OpenCTI Rules
Engine.

The short distinction is:

```text
NarrowCTI
  -> pre-ingestion curation gateway
  -> decides, normalizes, scores, deduplicates and enriches before OpenCTI

OpenCTI Rules Engine
  -> post-ingestion reasoning layer
  -> infers additional relationships from knowledge already in OpenCTI
```

They are complementary. NarrowCTI should not replace OpenCTI inference rules,
and OpenCTI inference rules should not replace NarrowCTI curation.

## Current Local Observation

Local OpenCTI 6.9.4 observation on June 25, 2026:

| Item | Status |
| --- | --- |
| Rule manager | Active |
| Rule manager errors | None returned by GraphQL |
| Inference rules | 20 rules available |
| Active rules | 0 |

This means the local lab is ready to use the Rules Engine, but no inference
rule is currently enriching the graph.

## Product Boundary

NarrowCTI owns:

- Source payload interpretation.
- CTI policy and filter decisions.
- Score, TLP, age, source confidence and guardrail decisions.
- Source-backed extraction of actors, arsenal, vulnerabilities, sectors,
  locations, ATT&CK, infrastructure, ASN, observables and reports.
- Deduplication before export.
- Canonical OpenCTI lookup before creating graph objects.
- STIX bundle construction and OpenCTI ingestion.
- Audit evidence explaining why something was ingested, held, quarantined,
  skipped or exported.

OpenCTI Rules Engine owns:

- Logical inference over relationships already present in OpenCTI.
- Background scan of existing data when a rule is activated.
- Continuous inference when matching relationships are later created or
  modified.
- Marking relationships as inferred in the OpenCTI UI.
- Cleanup of objects and relationships created by a rule when the rule is
  deactivated.

The Rules Engine can create a large number of relationships. It is reversible,
but it should still be activated in a bounded, observable lab posture.

## How They Work Together

The preferred production flow is:

```text
OTX/MISP/future feed
  -> NarrowCTI curation
  -> source-backed STIX objects and relationships
  -> OpenCTI import
  -> selected OpenCTI inference rules expand safe relationships
  -> analyst validates Knowledge, Diamond, Kill Chain, Timeline and graph views
```

NarrowCTI should send the strongest supported edges. For example:

```text
Intrusion Set -> uses -> Malware
Intrusion Set -> uses -> Infrastructure
Intrusion Set -> targets -> Sector
Intrusion Set -> uses -> Attack Pattern
Infrastructure -> consists-of -> IP/CIDR/ASN
IP/CIDR -> belongs-to -> ASN
Report -> object refs -> curated graph objects
```

OpenCTI rules can then infer safe higher-level relationships from those edges,
such as parent technique usage, parent identity/report propagation, or
targeting propagation through location hierarchy.

## Rule Activation Matrix

Recommended first candidates for a NarrowCTI lab:

| Rule | NarrowCTI value | Recommended posture |
| --- | --- | --- |
| `Usage propagation of parent techniques` | Lets OpenCTI infer parent ATT&CK technique usage when NarrowCTI links a subtechnique. | Good first candidate after MITRE baseline is loaded. |
| `Locations propagation in reports` | Helps Reports carry parent location context when NarrowCTI includes country/region/city. | Good candidate for victimology validation. |
| `Identities propagation in reports` | Helps Reports carry parent identity context, such as subsector/sector hierarchy. | Good candidate if sector hierarchy is curated. |
| `Observables propagation in reports` | Helps Reports show observables linked to indicators. | Useful, but validate report volume. |
| `Indicators propagation in reports` | Helps Reports show indicators linked to observables. | Useful, but validate report volume. |
| `Targeting propagation via location` | Expands targeting from lower-level location to parent location. | Good after location data is clean. |
| `Targeting propagation when located` | Infers target location relationships when target entity is located somewhere. | Good after entity/location curation is reliable. |
| `Targeting propagation via belonging` | Expands targeting through sector/identity hierarchy. | Good after sector and organization hierarchy is clean. |

Rules that need extra caution:

| Rule | Risk | Recommended posture |
| --- | --- | --- |
| `Relation propagation via an observable` | Shared IOCs can create broad `related-to` edges between otherwise unrelated entities. | Keep disabled until graph quality and IOC volume are measured. |
| `Relation propagation testing rule` | Can create transitive `related-to` chains that are hard to explain in CTI reports. | Keep disabled by default. |
| `Usage propagation via attribution` | Can infer actor usage from attributed child entities; useful but sensitive to attribution quality. | Enable only after actor/malware/campaign attribution hygiene is validated. |
| `Attribution propagation` | Can amplify weak attribution across entity chains. | Enable only with strong source confidence and review evidence. |
| `Raise incident based on sighting` | Creates Incidents from sightings; this is operationally noisy without a mature sightings process. | Keep disabled until sightings are intentionally used. |
| `Sightings of observables via observed data` | Depends on observed data quality and identity attribution. | Pilot separately. |
| `Sightings propagation from indicator` | Propagates sightings from indicators to observables. | Pilot separately. |
| `Sightings propagation from observable` | Propagates sightings from observables to indicators. | Pilot separately. |
| `Organization propagation via participation` | More relevant for user/organization structures than threat feed curation. | Keep disabled unless a clear use case exists. |
| `Belonging propagation` | Useful for hierarchy, but can amplify poor parent/child modeling. | Enable only after hierarchy review. |
| `Location propagation` | Useful for location hierarchy, but should be validated against OpenCTI location modeling. | Enable with country/region tests first. |

## Validation Procedure

Activate one rule at a time in a bounded lab:

1. Record the current object and relationship counts for the validation target.
2. Confirm NarrowCTI export is deterministic and deduplicated.
3. Activate one OpenCTI rule.
4. Wait for the background rule task to complete.
5. Validate inferred relationships in OpenCTI Knowledge and graph views.
6. Confirm inferred relationships are visually distinguishable from direct
   source-backed relationships.
7. Record whether the rule improved analyst value or introduced noise.
8. Deactivate the rule if noise is unacceptable and confirm inferred objects
   and relationships created by that rule are cleaned up.

Initial validation targets:

| Target | Rule to test | Expected value |
| --- | --- | --- |
| ATT&CK subtechnique imported by NarrowCTI | `Usage propagation of parent techniques` | Parent technique appears without NarrowCTI creating a duplicate technique. |
| Sector/subsector relationship | `Identities propagation in reports` | Report shows parent sector context. |
| Country/region hierarchy | `Locations propagation in reports` | Report shows parent region context. |
| Actor targets city/country/region | `Targeting propagation via location` | Actor targeting expands through location hierarchy. |
| Report contains indicator based on observable | `Observables propagation in reports` | Report content becomes richer without duplicate observables. |

## NarrowCTI Product Implications

NarrowCTI should add product-level awareness of OpenCTI inference rules, but
should not depend on them for core curation correctness.

Future backlog:

- Add an operational validation section for OpenCTI Rules Engine posture.
- Add optional diagnostics that list active OpenCTI rules and rule manager
  errors.
- Add curation report evidence showing whether important relationships are
  direct NarrowCTI exports or OpenCTI-inferred relationships.
- Add recommended OpenCTI rule profiles for lab, pilot and production.
- Keep NarrowCTI graph export conservative even when OpenCTI rules are active.

## References

- OpenCTI Inferences and reasoning:
  https://docs.opencti.io/latest/usage/inferences/
- OpenCTI Rules engine:
  https://docs.opencti.io/latest/administration/reasoning/
