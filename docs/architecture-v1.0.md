# NarrowCTI Architecture - v1.0.0

## Status

Status: in development.

v1.0 is the first production-ready NarrowCTI Community Edition target. It does
not expand the source catalog. It hardens the deterministic curation gateway
already validated with OTX and MISP.

## Product Boundary

NarrowCTI remains the pre-ingestion decision layer for OpenCTI:

```text
OTX / MISP
  -> source normalization and evidence
  -> base score and contextual score
  -> policy, TLP, age and type controls
  -> source and artifact deduplication
  -> quarantine and governed analyst review
  -> canonical OpenCTI entity and relationship lookup
  -> graph-safe STIX/OpenCTI export
  -> decision audit and Community operational report
```

OpenCTI remains the knowledge graph, investigation and visualization platform.
The official MITRE ATT&CK connector remains the preferred canonical ATT&CK
loader. NarrowCTI uses that context to curate and relate source intelligence.

## Frozen Scope

- OTX and MISP are the v1.0 ingestion sources.
- No new direct adapter is required for v1.0.
- MalwareBazaar and URLHaus move to v1.1.
- Machine learning remains post-v1.0.
- Automatic quarantine release remains prohibited.
- Advanced executive reporting, tenant-specific templates and polished PDF
  packs remain outside the Community v1.0 scope.
- A browser UI is not a release blocker; the governed API and CLI remain the
  operator control boundaries.

## Decision Engine

The decision path must remain deterministic and explainable:

```text
base score
  -> contextual scoring mode
  -> explicit policy checks
  -> ingest / quarantine / drop / skip / dry-run
```

Contextual scoring modes:

| Mode | Behavior |
| --- | --- |
| `off` | Preserve base scoring and emit no contextual adjustment. |
| `shadow` | Calculate and audit contextual score without changing the decision. |
| `enforce` | Use contextual score in the decision path while preserving base score, delta and reasons. |

Contextual scoring must never bypass TLP, marking, the hard age cutoff,
indicator-type or explicit deny policy. Every applied adjustment must record
its category, source-backed value, impact, cap, version and final decision
effect.

Target configuration:

```text
NARROWCTI_CONTEXTUAL_SCORING_MODE=shadow
NARROWCTI_CONTEXTUAL_SCORING_MAX_IMPACT=100
NARROWCTI_CONTEXTUAL_SCORING_IMPACTS=threat:20,toolbox:15,ttp:15,sector:10,location:10,vulnerability:15,author:5,graph_state:5
```

## Graph Quality

v1.0 keeps graph promotion source-backed and convergent:

- resolve canonical entities before creation;
- deduplicate relationships by source, target and relationship type;
- preserve logical source authors as `<Source display name> via NarrowCTI`;
- keep weak or ambiguous relationships in Report, Note, quarantine or audit;
- never promote raw IoCs into Infrastructure without explicit infrastructure
  evidence or governed review;
- measure object reuse, relationship reuse, held candidates and duplicate
  prevention;
- validate Infrastructure victimology before broad activation;
- validate Diamond, Timeline and Kill Chain claims through OpenCTI API and UI.

### Context Propagation Contract

MISP context propagation is same-event and evidence-bound. When the event has an
explicit campaign, one unambiguous actor, explicit infrastructure and explicit
victimology, the graph plan may emit:

```text
campaign -> attributed-to -> actor
campaign -> uses -> infrastructure, malware, tool, channel or attack-pattern
campaign -> targets -> sector, location, organization or system
actor -> uses -> infrastructure
infrastructure -> targets -> sector, location, organization or system
```

Every propagated edge carries the original source value, source field,
`same-misp-event` scope and a named `relationship_inference`. Multiple
actors, missing quadrants or title-only campaign language suppress the inferred
edge. In particular, an event whose only signal is
`campaign-name=Dust Storm` must produce the explicit campaign and Report
relation, not invented actor, infrastructure or victimology. This is a
correctness boundary, not an ingestion failure.

Infrastructure victimology export remains opt-in through
`NARROWCTI_ENABLE_INFRASTRUCTURE_VICTIMOLOGY_EXPORT`. Before enabling it for a
production-like instance, inspect the OpenCTI relationship audit and Diamond
view and retain the result with the run evidence.

Real source absence must be explicit. Contract or synthetic validation may
prove supported behavior, but it cannot be described as real-feed validation.

## Runtime Resilience

The unified runtime must provide:

- source-isolated failures;
- bounded retries with backoff and jitter;
- explicit request, processing and shutdown timeouts;
- durable checkpoints written only after successful handling;
- atomic state replacement so interrupted JSON writes do not destroy the last
  complete checkpoint or deduplication index;
- bounded batches and resource guardrails;
- health and readiness evidence;
- restart-safe state and idempotent replay;
- observable retry, failure, checkpoint and backlog metrics.

One failing source must not corrupt another source state or silently advance a
checkpoint.

## Community Reporting

The v1.0 Community report remains concise and audit-ready. Text, JSON and HTML
output should summarize:

- ingest, quarantine, drop, skip, release and failure outcomes;
- base and contextual scoring effects;
- source contribution and policy reasons;
- object and relationship reuse;
- graph-quality and Diamond/Kill Chain coverage evidence;
- runtime failures, retries and incomplete validation.

The report must describe evidence, not invent an executive threat narrative.

## Deployment And Upgrade

Release validation must cover:

- clean installation with immutable image tags;
- upgrade from v0.9 without losing audit, quarantine or deduplication state;
- backup and restore of persistent NarrowCTI state;
- restart and interrupted-run recovery;
- supported OpenCTI compatibility;
- secrets, filesystem permissions and container hardening;
- rollback instructions.

## Security And Supply Chain

All applicable release gates are blocking:

- unit and integration tests;
- Ruff, Bandit and dependency audit;
- secret and repository hygiene checks;
- exact-image build and smoke validation;
- Trivy image scan and CycloneDX SBOM;
- DAST against a disposable analyst API deployment;
- controlled OpenCTI end-to-end validation;
- clean-install, upgrade and recovery validation.

Image signing or equivalent provenance attestation is a v1.0 target. If it is
not implemented, the release notes must record the residual supply-chain gap.

## Implementation Backlog

1. Done: correct v0.9 publication metadata and freeze v1.0 scope.
2. Done: establish v1.0 architecture, release notes and Definition of Done.
3. Done: implement contextual scoring `off`, `shadow` and `enforce` modes.
4. Done: document and validate contextual scoring configuration and decision
   effects.
5. Close priority Diamond, victimology, Timeline and Kill Chain gaps.
6. Add runtime retry, backoff, timeout, checkpoint and health controls.
7. Consolidate the Community curation report.
8. Validate clean install, v0.9 upgrade, backup, restore and restart recovery.
9. Run the complete security, quality, image and OpenCTI validation gates.
10. Finalize public documentation, changelog, image tags and release evidence.

## Definition Of Done

- The deterministic decision engine exposes tested `off`, `shadow` and
  `enforce` contextual scoring modes.
- Configuration reference explains every new option and its decision effect.
- TLP and explicit deny policy cannot be bypassed by contextual score.
- OTX and MISP runs remain idempotent and source-isolated.
- Priority graph relationships are canonical, deduplicated and source-backed.
- Real OpenCTI evidence supports every graph claim in the release notes.
- Missing real source shapes are documented without inflated claims.
- Community reports expose decision, scoring, quarantine and graph-quality
  evidence.
- Clean install, upgrade, backup, restore and interrupted-run recovery pass.
- CI, SAST, DAST, dependency, image and SBOM gates pass on the release commit.
- Public docs, source archive, image tags, changelog and GitHub Release are
  current and contain no local secrets or development-only evidence.

## Non-Goals

- New source adapters.
- ML-assisted or ML-driven ingestion.
- Unsupported relationship inference.
- Automatic quarantine release.
- Full browser administration UI.
- Advanced commercial or executive report packs.
