# Post-v1.0 ML-Assisted Curation Roadmap

## Purpose

This document records the post-v1.0 machine learning direction for NarrowCTI.
The goal is not to replace the deterministic curation engine. The goal is to
add an adaptive assistance layer that helps analysts and operators discover
relationships, aliases, priorities and weak signals faster while preserving
NarrowCTI's core product principles: explainability, provenance, auditability,
policy control and OpenCTI graph hygiene.

ML should enter the product only after the v1.0 foundation is stable:

- Source adapters and payload mapping are mature.
- Graph-aware STIX export is validated against OpenCTI.
- Quarantine, release and audit workflows are reliable.
- Enterprise scoring and policy controls are documented.
- Decision records contain enough historical data to train or evaluate models.

## Product Position

Post-v1.0 ML should make NarrowCTI an adaptive CTI curation gateway.

Recommended future statement:

```text
NarrowCTI uses governed ML-assisted curation to suggest aliases,
relationships, priorities and weak-signal enrichment before intelligence is
promoted into OpenCTI.
```

The ML layer must be a copilot, not an oracle:

```text
source data + historical decisions + graph evidence
  -> ML suggestion
  -> confidence and evidence
  -> policy and guardrails
  -> optional analyst review
  -> controlled OpenCTI promotion
```

## Can This Be Built In Python?

Yes. The ML logic can be built on top of Python.

Python is the right implementation language for the first ML layer because the
existing NarrowCTI codebase is already Python and the ML ecosystem is mature.
The product can start with lightweight local models and feature pipelines
before introducing heavier model-serving infrastructure.

Python alone is enough for early versions such as:

- Feature extraction from graph candidates and decision audit records.
- Similarity scoring for aliases, reports, campaigns and artifacts.
- Lightweight classifiers using libraries such as scikit-learn.
- Embedding-based semantic matching using local or remote embedding models.
- Offline evaluation scripts and model-quality reports.

Python is not the whole product requirement. A production ML capability also
needs:

- Training and evaluation datasets.
- Feature versioning.
- Model versioning.
- Model-quality metrics.
- Explainability metadata.
- Drift monitoring.
- Privacy and secret-handling rules.
- Operator configuration.
- Safe fallback to deterministic behavior.
- Audit records for every ML-assisted suggestion.

The safest architecture is to keep the deterministic curation pipeline as the
source of truth and add ML as an optional scoring and suggestion layer.

## v0.7 Deterministic Curation Versus Future ML

| Area | v0.7 deterministic foundation | Post-v1.0 ML-assisted future |
| --- | --- | --- |
| Entity extraction | Field-driven extraction from OTX, MISP and MITRE metadata | Entity suggestions from text, references, reports and weak metadata |
| Relationships | Created only when source evidence and anchors are trusted | Suggests probable relationships for review when evidence is scattered |
| Scoring | Configurable policy, confidence and contextual score | Adaptive relevance score learned from historical decisions and graph outcomes |
| Deduplication | Fingerprints, source keys and graph keys | Semantic dedup for aliases, similar reports, campaigns and related artifacts |
| Victimology | Sectors, countries and regions from explicit source fields | Inferred target sectors and regions from narrative, tags and prior campaigns |
| Arsenal | Malware, tools and ATT&CK from mapped fields | Classification of malware/tool families and likely capability clusters |
| Hunting value | Deterministic indicator and graph context | Prioritized hunting queue based on observed usefulness and analyst feedback |
| Explainability | Rule, score and provenance trail | Suggestion evidence, model confidence, feature contributions and review trail |

## Candidate ML Capabilities

### Alias And Entity Resolution

Use ML or embedding similarity to detect likely aliases across actor, malware,
tool, campaign and intrusion-set names.

Examples:

- `APT Example`, `Example Group` and `ExampleGroup` may represent the same
  actor.
- Different malware family spellings may collapse into one curated entity.
- Duplicate reports from multiple sources may be grouped as the same campaign
  evidence.

Promotion rule:

- ML may suggest a merge or alias.
- NarrowCTI must record confidence and supporting evidence.
- High-risk merges should require analyst review before graph promotion.

### Relationship Recommendation

Use ML to suggest graph relationships when the source payload carries weak or
scattered evidence.

Examples:

- `actor -> uses -> malware`
- `actor -> targets -> sector`
- `malware -> uses -> attack-pattern`
- `campaign -> attributed-to -> intrusion-set`

Promotion rule:

- Deterministic relationships remain preferred.
- ML-only relationships should start in quarantine or review.
- Every suggestion must retain source snippets, fields, references or feature
  evidence.

### Priority And Hunting Value Ranking

Use ML to rank intelligence by likely operational value.

Signals may include:

- Source reliability.
- Recency.
- Graph context richness.
- Overlap with monitored sectors, actors and ATT&CK techniques.
- Prior analyst release/reject decisions.
- Indicator type and historical detection utility.
- Cross-source corroboration.

Promotion rule:

- Ranking can influence queue order and contextual score.
- Ranking must not bypass TLP, source policy, deduplication or quarantine.

### Text And Report Understanding

Use NLP to extract candidate entities and relationships from unstructured text:

- MISP EventReports.
- OTX descriptions.
- External references.
- Analyst notes.
- Future source reports.

Initial targets:

- Actor names.
- Malware and tools.
- CVEs.
- ATT&CK techniques and tactics.
- Target sectors and countries.
- Infrastructure hints.
- Detection guidance.

### Feedback Learning

Use analyst actions as supervised feedback:

- Released records become positive examples.
- Rejected records become negative examples.
- Partially released records teach which indicators or graph candidates are
  useful.
- Repeated overrides identify policy or model gaps.

Promotion rule:

- Feedback should improve future suggestions.
- Feedback must be source-scoped and tenant-safe before any multi-environment
  learning exists.

## Architecture Direction

The post-v1.0 architecture should keep ML modular:

```text
source adapters
  -> deterministic normalization
  -> graph evidence
  -> graph candidates
  -> deterministic policy and score
  -> ML suggestion layer
  -> combined curation decision
  -> quarantine / release / export
  -> OpenCTI
```

Recommended modules:

```text
ml/
  features.py          -> feature extraction from candidates and decisions
  similarity.py        -> alias, report and artifact similarity
  classifiers.py       -> supervised relevance and category models
  suggestions.py       -> candidate relationship and enrichment suggestions
  evaluation.py        -> precision, recall and drift reports
  model_registry.py    -> model metadata and version loading
```

The first implementation should work offline and locally before adding model
serving.

## Governance Requirements

ML-assisted curation must remain enterprise-safe:

- Disabled by default until configured.
- Dry-run first.
- Evidence-preserving.
- Confidence-scored.
- Source-scoped.
- Versioned by model id and feature schema.
- Auditable in decision records.
- Reversible through quarantine and release controls.
- Explainable enough for CTI and platform governance.

Do not allow ML to silently promote graph relationships into OpenCTI without a
policy path.

## Recommended Phasing

| Phase | Scope | Target |
| --- | --- | --- |
| post-v1.0 research | Offline experiments over decision audit and quarantine data | Validate feasibility without changing ingest behavior |
| post-v1.1 | Similarity and alias suggestion dry-run | Help analysts detect duplicate actors, malware and reports |
| post-v1.2 | ML-assisted priority ranking | Improve review queue and hunting value prioritization |
| post-v1.3 | Relationship recommendation quarantine | Suggest weak relationships for analyst review |
| post-v1.x | Optional controlled promotion | Allow high-confidence ML suggestions only with strict policy and audit |

## Decision

ML is a strong post-v1.0 direction for NarrowCTI, but it should not replace the
v1.0 deterministic curation engine. The right product path is to make ML an
explainable assistant that proposes enrichment, prioritization and correlation
while NarrowCTI continues to own policy, provenance, quarantine and OpenCTI
graph hygiene.
