# Source Ingestion Modes - v0.7.0

## Purpose

This document records the NarrowCTI ingestion architecture for environments
with and without MISP.

NarrowCTI must not depend on MISP to be useful. MISP is a strong collector and
event hub when an organization already has it, but NarrowCTI's product role is
broader: it is the pre-ingestion curation gateway that decides what should
enter OpenCTI and how that intelligence should populate the graph.

## Product Decision

NarrowCTI should support three ingestion modes:

```text
Direct source mode
  External source -> NarrowCTI -> OpenCTI

MISP collector mode
  External sources -> MISP -> NarrowCTI -> OpenCTI

Hybrid mode
  Some sources -> MISP -> NarrowCTI
  Other sources -> NarrowCTI directly
  NarrowCTI -> OpenCTI
```

The product must make all three modes valid. This prevents NarrowCTI from being
limited to labs that have MISP, while still supporting mature teams that use
MISP as a central IoC/event hub.

## Why Official Connectors Still Matter

Official OpenCTI connectors remain valuable for mapping validation, but they
should not bypass NarrowCTI in the target product flow.

Direct official connector flow:

```text
External source -> official OpenCTI connector -> OpenCTI
```

This is useful for:

- Lab comparison.
- Understanding how OpenCTI expects STIX objects and relationships.
- Finding source-specific metadata fields and relationship patterns.
- Validating graph compatibility.

It is not the preferred product ingestion path because it bypasses:

- Scoring.
- Deduplication.
- Quarantine.
- TLP and policy controls.
- Contextual scoring.
- Graph hygiene.
- Release audit.
- Source-to-source correlation.
- Enterprise curation reporting.

The correct NarrowCTI use of official connectors is:

```text
official connector behavior
  -> mapping reference
  -> NarrowCTI source adapter design
  -> curated STIX/OpenCTI graph export
```

## Mode 1 - Direct Source Mode

Direct source mode is required for organizations that do not run MISP.

```text
MalwareBazaar / URLHaus / AbuseIPDB / NVD / OTX / other feeds
  -> NarrowCTI source adapter
  -> source metadata validation
  -> graph evidence
  -> scoring, policy, deduplication and quarantine
  -> STIX/OpenCTI graph builder
  -> OpenCTI
```

This mode makes NarrowCTI the source intake and curation layer. It should be
the default product model for customers who want a compact OpenCTI-native CTI
gateway without deploying MISP.

## Mode 2 - MISP Collector Mode

MISP collector mode is useful when an organization already centralizes many
feeds in MISP.

```text
External feeds
  -> MISP
  -> NarrowCTI MISP adapter
  -> source and collector provenance preservation
  -> scoring, policy, deduplication and quarantine
  -> STIX/OpenCTI graph builder
  -> OpenCTI
```

In this mode, NarrowCTI must preserve both:

- The collector context, such as `misp:misp`.
- The original source context, such as AlienVault OTX, MalwareBazaar or an
  internal MISP organization, when MISP provides it.

MISP does not remove the need for NarrowCTI. It gives NarrowCTI a consolidated
source surface, but NarrowCTI still owns final curation and OpenCTI graph
quality.

## Mode 3 - Hybrid Mode

Hybrid mode is the enterprise target.

```text
High-volume or existing feeds -> MISP -> NarrowCTI
Strategic direct feeds        -> NarrowCTI
NarrowCTI                     -> OpenCTI
```

This mode lets an organization keep MISP for operational collection while
using direct NarrowCTI adapters for sources where richer source metadata,
better rate control, commercial licensing, latency or graph enrichment matters.

Examples:

- MISP receives community OSINT feeds and local analyst events.
- NarrowCTI connects directly to NVD/CVE, MITRE ATT&CK, MalwareBazaar or
  URLHaus when source-specific metadata is useful for graph enrichment.
- NarrowCTI deduplicates and correlates artifacts across both paths before
  export.

## Source Adapter Contract

The current code already has the foundation in `core/feed_contract.py`:

```text
FeedSource
FeedCandidate
FeedRunSummary
FeedAdapter.search(query)
FeedAdapter.enrich(candidate)
```

Future direct source adapters should follow this contract and add a
source-specific metadata extractor.

Target adapter shape:

```text
connectors/<source>/
  client.py
  feed_adapter.py
  processor.py
  settings.py
  models.py
  .env.example
```

Each adapter should produce:

- Source-scoped identity and state key.
- Lightweight search candidates.
- Enriched raw source payload.
- Normalized indicators.
- Extracted source metadata.
- Graph evidence records.
- Guardrail metadata.
- Decision audit metadata.
- Quarantine payload snapshot.

## Future Graph Translation Layer

The target architecture should avoid each source exporting arbitrary STIX
directly. Instead, sources should produce normalized graph candidates.

```text
source payload
  -> source metadata extractor
  -> graph evidence
  -> graph candidates
  -> policy/scoring/dedup/quarantine
  -> STIX/OpenCTI graph builder
```

Candidate object families:

```text
ThreatActorCandidate
IntrusionSetCandidate
MalwareCandidate
ToolCandidate
AttackPatternCandidate
SectorCandidate
LocationCandidate
VulnerabilityCandidate
InfrastructureCandidate
IndicatorCandidate
ObservableCandidate
RelationshipCandidate
```

This layer is the correct place to translate diverse source metadata into what
OpenCTI understands. It also prevents a new source adapter from becoming a
one-off exporter that bypasses product policy.

## Strategic Source Priorities

Future adapters should be prioritized by graph value and operational demand.

| Priority | Source | Reason |
| --- | --- | --- |
| High | OTX | Existing direct adapter and rich pulse metadata. |
| High | MISP | Existing collector adapter and common enterprise hub. |
| High | MITRE ATT&CK | Reference graph for TTP, groups, software and campaigns. |
| High | NVD/CVE | Vulnerability context, exploitation workflows and CVE graph enrichment. |
| High | MalwareBazaar | Malware samples, families, tags and hash intelligence. |
| High | URLHaus | URL/domain infrastructure, malware tags and takedown context. |
| Medium | AbuseIPDB | IP reputation and abuse categories. |
| Medium | Shodan/Censys | Infrastructure enrichment, exposed services and asset context. |
| Later | VirusTotal | Broad enrichment value, but licensing/API constraints require care. |

These are product priorities, not implementation commitments for v0.7.

## v0.7 Scope

v0.7 should not try to implement every direct source adapter.

The safe v0.7 scope is:

1. Document the three ingestion modes.
2. Keep OTX direct mode and MISP collector mode as the first two validated
   source patterns.
3. Define the source adapter and graph candidate direction for future direct
   feeds.
4. Use official OpenCTI connectors as mapping references only.
5. Keep graph enrichment focused on metadata validation, graph evidence,
   graph candidates, relationship policy, contextual scoring and export
   dry-run behavior.

## Backlog

1. Add a source adapter onboarding checklist.
2. Add a source mapping validation template based on the MISP and OTX official
   connector mapping documents.
3. Create the shared graph candidate model. Initial model and OTX/MISP
   audit metadata attachment are implemented.
4. Add adapter-level metadata extractor conventions.
5. Add preflight output showing enabled ingestion mode:
   `direct`, `misp-collector` or `hybrid`.
6. Add future `NARROWCTI_ENABLED_SOURCES` examples for direct sources such as
   `otx,misp,nvd,malwarebazaar,urlhaus,abuseipdb`.
7. Add direct adapters incrementally after the graph candidate model and STIX
   graph builder are stable.

## Decision

NarrowCTI should be deployable with or without MISP.

MISP is an optional collector path, not a product dependency. Official OpenCTI
connectors are compatibility references, not substitutes for the NarrowCTI
curation engine. Future sources should enter through NarrowCTI source adapters
so all intelligence receives the same governance, scoring, deduplication,
quarantine, graph translation and audit treatment before it reaches OpenCTI.
