# Contextual Scoring Reference - v0.7.0

## Purpose

This document records how the OpenCTI `scoring-calculator` internal enrichment
connector can inform NarrowCTI's enterprise scoring model.

The connector is not a feed connector and should not be copied directly into
NarrowCTI. It is valuable because it validates an important product idea:
indicator score should increase when the indicator is connected to context that
matters to the organization, such as monitored threat actors, malware, tools,
sectors, locations, ATT&CK techniques and trusted authors.

## Reference

Official OpenCTI connector:

```text
https://github.com/OpenCTI-Platform/connectors/tree/master/internal-enrichment/scoring-calculator
```

The connector is an internal enrichment connector for `Indicator`. It
recomputes `x_opencti_score` after looking at the indicator's related OpenCTI
entities and their priority labels.

## How The Official Connector Works

The official connector follows this high-level flow:

```text
Indicator created or updated in OpenCTI
  -> verify connector scope and supported observable type
  -> fetch direct graph relationships
  -> optionally fetch related reports and contained entities
  -> fetch indicator author
  -> evaluate priority labels on related entities and author
  -> calculate score impact
  -> send updated Indicator back to OpenCTI
```

Supported relationship context categories:

| Category | Entity types |
| --- | --- |
| Threat | Intrusion Set, Threat Actor, Threat Actor Individual, Threat Actor Group |
| Toolbox | Malware, Tool |
| Location | Country, Region |
| Sector | Sector |
| TTP | Attack Pattern |
| Author | Organization, Individual |

The connector only enriches STIX-pattern indicators whose
`x_opencti_main_observable_type` is in the configured allowlist. The referenced
documentation lists `IPv4-Addr`, `IPv6-Addr`, `Domain-Name` and `StixFile` as
the default enrichable observable types.

## Scoring Formula

The official connector uses a relative margin formula:

```text
new_score = current_score + ((100 - current_score) * impact_ratio)
```

Where:

- `impact_ratio` is the sum of matching category impacts divided by `100`.
- The ratio is capped at `1.0`.
- The final score is clamped to `0..100`.
- The formula is forward-only and should not lower the current score.

This behavior is useful because it rewards high-value context without turning
every match into score `100`.

Example:

```text
current_score=30
impact_ratio=0.70
new_score = 30 + ((100 - 30) * 0.70)
new_score = 79
```

The same impact against a high-score indicator has a smaller absolute effect:

```text
current_score=80
impact_ratio=0.70
new_score = 80 + ((100 - 80) * 0.70)
new_score = 94
```

## Fit For NarrowCTI

NarrowCTI should use this as a scoring design reference, not as a runtime
dependency.

Current NarrowCTI scoring in `core/scoring.py` is pre-ingestion scoring. It
uses source confidence, query match, tag match, indicator volume and recency to
decide whether a candidate should be ingested, dropped or quarantined.

The OpenCTI scoring calculator is post-ingestion graph-context scoring. It uses
relationships that already exist in OpenCTI.

The NarrowCTI enterprise model needs both:

```text
Base source score
  -> source confidence, query relevance, age, volume, artifact class

Contextual graph score
  -> actor, arsenal, TTP, sector, location, vulnerability, source author,
     cross-source corroboration and existing OpenCTI graph state

Final curation decision
  -> ingest, quarantine, drop, skip, release, dry-run
```

## NarrowCTI Design Decision

NarrowCTI should implement contextual scoring before export, using
`graph_evidence` and graph candidates rather than waiting for OpenCTI to create
relationships first.

The design should be:

```text
source payload
  -> normalize and extract graph evidence
  -> base score
  -> contextual score impact
  -> policy decision
  -> graph-aware STIX export
```

This keeps the product aligned with its gateway role: NarrowCTI decides what is
worthy before OpenCTI is populated.

## Candidate Configuration

The v0.7/v1.0 backlog should use visible gateway-level configuration names:

```env
NARROWCTI_CONTEXTUAL_SCORING_ENABLED=true
NARROWCTI_CONTEXTUAL_SCORING_MODE=dry-run

NARROWCTI_SCORING_THREAT_IMPACT=true
NARROWCTI_SCORING_THREAT_HIGH_PRIORITY=40
NARROWCTI_SCORING_THREAT_MEDIUM_PRIORITY=25
NARROWCTI_SCORING_THREAT_LOW_PRIORITY=10

NARROWCTI_SCORING_TOOLBOX_IMPACT=true
NARROWCTI_SCORING_TOOLBOX_HIGH_PRIORITY=35
NARROWCTI_SCORING_TOOLBOX_MEDIUM_PRIORITY=20
NARROWCTI_SCORING_TOOLBOX_LOW_PRIORITY=10

NARROWCTI_SCORING_LOCATION_IMPACT=true
NARROWCTI_SCORING_LOCATION_HIGH_PRIORITY=30
NARROWCTI_SCORING_LOCATION_MEDIUM_PRIORITY=15
NARROWCTI_SCORING_LOCATION_LOW_PRIORITY=5

NARROWCTI_SCORING_SECTOR_IMPACT=true
NARROWCTI_SCORING_SECTOR_HIGH_PRIORITY=30
NARROWCTI_SCORING_SECTOR_MEDIUM_PRIORITY=15
NARROWCTI_SCORING_SECTOR_LOW_PRIORITY=5

NARROWCTI_SCORING_TTP_IMPACT=true
NARROWCTI_SCORING_TTP_HIGH_PRIORITY=25
NARROWCTI_SCORING_TTP_MEDIUM_PRIORITY=15
NARROWCTI_SCORING_TTP_LOW_PRIORITY=5

NARROWCTI_SCORING_AUTHOR_IMPACT=true
NARROWCTI_SCORING_AUTHOR_HIGH_PRIORITY=20
NARROWCTI_SCORING_AUTHOR_MEDIUM_PRIORITY=10
NARROWCTI_SCORING_AUTHOR_LOW_PRIORITY=5
```

Priority membership can be configured in two ways:

- Explicit allowlists, such as `NARROWCTI_HIGH_PRIORITY_THREAT_ACTORS`.
- Labels imported from OpenCTI or source metadata, when OpenCTI lookup is
  enabled.

The first implementation should prefer explicit allowlists and dry-run evidence
because NarrowCTI is pre-ingestion. OpenCTI label lookup can be added later as
an optional graph-state enrichment.

## Candidate Scoring Inputs

| NarrowCTI context | Category | Example impact |
| --- | --- | --- |
| OTX `adversary` or MISP threat-actor galaxy | Threat | Increase score for monitored actors. |
| OTX `malware_families` or MISP malware/tool galaxy | Toolbox | Increase score for relevant arsenal. |
| OTX/MISP ATT&CK technique or MITRE-resolved tactic | TTP | Increase score for monitored behaviors. |
| OTX `industries` or MISP sector taxonomy | Sector | Increase score for exposed sectors. |
| OTX target country or MISP country/region galaxy | Location | Increase score for relevant geographies. |
| CVE evidence | Vulnerability | Increase score for exploited or monitored CVEs. |
| Source author/provider | Author | Increase score for trusted intelligence producers. |
| Cross-source artifact sighting | Graph state | Increase confidence and score when corroborated. |

## Guardrails

Contextual scoring must not become a hidden auto-approval mechanism.

Required guardrails:

- Keep base score and contextual score separate in audit evidence.
- Store every contextual adjustment with category, matched value, priority,
  impact and source field.
- Cap total contextual impact at `100%` of remaining score margin.
- Do not let contextual scoring bypass TLP/marking policy.
- Do not let weak generic tags create high-priority boosts without taxonomy or
  allowlist confirmation.
- Keep `dry-run` as the first operational mode.
- Explain whether a candidate was ingested because of base score, contextual
  score, analyst release or policy override.

## Backlog

1. Add a pure contextual scoring module that implements the relative margin
   formula and records structured adjustments.
2. Add unit tests for score coercion, clamping, impact capping, priority
   resolution and no-hidden-decrease behavior.
3. Extend `graph_evidence` records with scoring category hints where relevant:
   Threat, Toolbox, Location, Sector, TTP, Author, Vulnerability and Graph
   State.
4. Add dry-run contextual score evidence into decision audit and quarantine
   metadata.
5. Add gateway-level configuration for contextual scoring categories and
   priority impacts.
6. Integrate contextual scoring into the candidate decision path after base
   scoring and before policy decision.
7. Add optional OpenCTI lookup mode to read existing labels and relationships
   only after local scoring is stable.
8. Include contextual scoring impact in future enterprise CTI reports so users
   can see why specific intelligence was promoted or held back.

## Release Placement

| Version | Placement |
| --- | --- |
| v0.7 | Document reference, define model, add dry-run candidate scoring if graph candidates are stable. |
| v0.8 | Expose contextual scoring through review/API/UI workflows. |
| v1.0 | Ship stable enterprise scoring policy with reports, governance and graph-quality metrics. |

## Decision

The OpenCTI scoring calculator validates a direction NarrowCTI already needs:
score must become contextual, not only source-and-recency based.

NarrowCTI should implement this as an enterprise pre-ingestion scoring layer
using source evidence and graph candidates. OpenCTI relationship and label
lookup can become an optional enrichment later, but the core decision must
remain inside NarrowCTI so the gateway continues to protect the OpenCTI graph
before ingestion.
