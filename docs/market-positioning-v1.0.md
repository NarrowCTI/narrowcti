# Market Positioning - v1.0.0

## Purpose

This document records the v1.0 market positioning that should guide release
messaging, product packaging and roadmap validation. The goal is to make
NarrowCTI enter v1.0 with a clear brand: not as another connector, and not as a
replacement for OpenCTI or MISP, but as an OpenCTI-native curation gateway that
improves the quality, governance and usefulness of intelligence before it enters
the graph.

## Brand Position

NarrowCTI is an OpenCTI-native CTI curation gateway.

It sits between intelligence sources and OpenCTI to decide what should be
ingested, why it should be ingested, what should be quarantined, and how the
accepted intelligence should be shaped into useful graph knowledge.

Recommended v1.0 product statement:

```text
NarrowCTI is an OpenCTI-native threat intelligence curation gateway that turns
raw feeds into governed, explainable and graph-ready intelligence before
OpenCTI ingestion.
```

Short form:

```text
NarrowCTI is the pre-ingestion intelligence decision layer for OpenCTI.
```

## Category

NarrowCTI should define its own narrow category instead of being positioned as a
full Threat Intelligence Platform.

| Category | NarrowCTI stance |
| --- | --- |
| Threat Intelligence Platform | Adjacent, but not a replacement for OpenCTI, MISP or commercial TIPs. |
| Feed connector | Too small. NarrowCTI must do more than move IoCs. |
| Feed aggregator | Too generic. NarrowCTI must decide, score, quarantine and enrich. |
| Enrichment service | Partial fit, but NarrowCTI also governs ingestion and graph hygiene. |
| CTI curation gateway | Best fit for the v1.0 brand. |

The product category to carry into v1.0 is:

```text
OpenCTI-native CTI curation gateway
```

## Market Differentiation

A market review found several adjacent capabilities across TIPs, CTI providers,
OpenCTI, MISP and enrichment platforms. Those products can aggregate, correlate,
score, enrich, visualize, store or distribute intelligence. NarrowCTI should not
claim that those capabilities do not exist elsewhere.

The differentiated lane is more specific:

- OpenCTI-native by design, not only OpenCTI-compatible.
- Focused on pre-ingestion governance before graph pollution happens.
- Designed to keep OpenCTI as the graph and knowledge platform while NarrowCTI
  owns curation, policy, deduplication, quarantine and enrichment before import.
- Built around explainable decisions instead of blind feed forwarding.
- Designed for actor, arsenal, MITRE ATT&CK, victimology, infrastructure,
  vulnerability and detection context when source evidence supports it.
- Able to preserve rejected or uncertain intelligence through quarantine and
  analyst release instead of dropping it silently.
- Able to transform repeated sightings into source evidence and confidence
  signals instead of duplicate graph objects.

## Approved Claims

These claims are safe for release messaging when the corresponding v1.0
capabilities are implemented and validated:

- NarrowCTI is an OpenCTI-native CTI curation gateway.
- NarrowCTI reduces feed noise before intelligence reaches the OpenCTI graph.
- NarrowCTI turns raw feed data into explainable ingestion decisions.
- NarrowCTI helps protect OpenCTI graph hygiene through scoring,
  deduplication, policy and quarantine.
- NarrowCTI enriches OpenCTI with curated context such as actors, arsenal,
  TTPs, victimology, infrastructure and vulnerabilities when source evidence
  supports those relationships.
- NarrowCTI complements OpenCTI and MISP instead of replacing them.

## Claims To Avoid

These claims should not be used without a formal, refreshed competitive review
and legal approval:

- NarrowCTI is the first product of its kind.
- NarrowCTI is the only product that does CTI curation.
- NarrowCTI replaces OpenCTI, MISP or commercial TIPs.
- NarrowCTI is equivalent to Kaspersky, Recorded Future, Anomali, ThreatQ or
  EclecticIQ.
- NarrowCTI eliminates false positives.
- NarrowCTI guarantees that all important intelligence will be ingested.

The stronger and safer message is that NarrowCTI occupies a focused product
lane: an OpenCTI-native gateway for governed pre-ingestion curation and graph
enrichment.

## v1.0 Release Mark

The v1.0 release should carry this brand identity only when these product
capabilities are present and validated:

- Unified gateway runtime for enabled sources.
- Visible and documented curation configuration.
- Explainable scoring and policy decisions.
- Source and artifact deduplication with graph hygiene controls.
- Quarantine repository and analyst release workflow.
- Richer STIX/OpenCTI graph export beyond isolated indicators.
- Entity extraction and mapping for actors, malware, tools, ATT&CK techniques,
  sectors, locations, infrastructure and vulnerabilities where source payloads
  support them.
- Audit records that explain ingest, drop, quarantine, release, skip and error
  outcomes.
- Installation and upgrade guidance suitable for controlled customer delivery.
- Value reporting that can show noise reduction, accepted intelligence,
  quarantined intelligence and graph-quality outcomes.
- Enterprise CTI report output that can summarize what was ingested, how it was
  curated, which policy controls shaped the result, which sources contributed,
  and what graph-quality value was produced.

The v0.5 operational reports are the evidence foundation for this capability.
They should not be marketed as the final enterprise report. The v1.0 or
post-UI product should turn gateway run summaries, decision audit, quarantine
release history, artifact correlation and graph-quality metrics into an
analyst-facing CTI curation report suitable for leadership, CTI operations and
platform governance.

## Relationship To OpenCTI And MISP

OpenCTI remains the graph, knowledge, investigation and visualization platform.
MISP can remain a source hub, sharing platform and operational IoC/event store.
NarrowCTI should sit between these systems and other feeds as the decision layer
that shapes what becomes graph knowledge.

Target flow:

```text
Feeds / MISP / OTX / MITRE / future providers
  -> NarrowCTI curation gateway
  -> OpenCTI graph and knowledge base
```

NarrowCTI should make OpenCTI more valuable by reducing noise, preserving
provenance, enriching relationships and making ingestion decisions auditable.

## Research References

The v1.0 positioning is based on the product direction already documented for
NarrowCTI and a market scan of adjacent public products and platforms. These
references should be refreshed before public launch messaging is finalized:

- OpenCTI / Filigran: https://filigran.io/platform/opencti/
- OpenCTI documentation: https://docs.opencti.io/latest/usage/overview/
- MISP project: https://www.misp-project.org/
- EclecticIQ Intelligence Center: https://www.eclecticiq.com/threat-intelligence-platform
- ThreatQ Platform: https://www.threatq.com/platform/threatq-platform
- Anomali ThreatStream: https://www.anomali.com/products/threatstream
- Recorded Future Platform: https://www.recordedfuture.com/platform
- Kaspersky Cyber Threat Intelligence Services: https://www.kaspersky.com/enterprise-security/threat-intelligence
- MITRE ATT&CK Data and Tools: https://attack.mitre.org/resources/attack-data-and-tools/
- OASIS STIX documentation: https://oasis-open.github.io/cti-documentation/stix/intro.html

## Decision

NarrowCTI v1.0 should enter release planning as an OpenCTI-native CTI curation
gateway. The market message should emphasize governed pre-ingestion decisioning,
graph hygiene, explainable curation, quarantine/release and enriched OpenCTI
context. This is the product lane that makes NarrowCTI more than a connector and
keeps the brand aligned with the enterprise architecture.
