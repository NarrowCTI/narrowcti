# Source Adapter Onboarding - v0.7.0

## Purpose

This checklist defines how new NarrowCTI source adapters should be evaluated
before they are allowed to feed OpenCTI through the gateway.

The product rule is simple: a source adapter must not be only a transport
wrapper. It must preserve source evidence, expose guardrails, support audit
metadata and produce graph candidates that can be curated before OpenCTI is
populated.

## Source Intake Checklist

Before implementing a new adapter, document:

- Source name, provider and trust boundary.
- Source access model, such as API key, TAXII, MISP sync, local file or manual
  import.
- Rate limits, pagination behavior, query model and expected volume.
- License, usage restrictions and redistribution constraints.
- Whether the source is a direct source, a collector source or usable in hybrid
  mode.
- Raw payload examples for low, normal and high-volume records.
- Stable identifiers, timestamps, update semantics and deletion semantics.
- Source-specific freshness and historical backfill controls.
- Source-specific dry-run and run-once controls.
- Source-specific max records, max attributes and oversize handling controls.
- Required secrets and the local-only environment variables that hold them.

## Metadata Mapping Checklist

For each source, validate whether payload fields can map to:

- Report or incident narrative.
- Indicators and observables.
- Threat actors or intrusion sets.
- Malware, tools and detection rules.
- Campaigns, vulnerabilities and exploited products.
- ATT&CK techniques, tactics, platforms, data sources and kill chain phases.
- Target sectors, countries, regions and victimology.
- TLP, markings, tags, taxonomies and sharing constraints.
- References, external ids, source authors and provider identities.
- Sightings, object references and relationship evidence.

Each mapping must state whether the field becomes:

- A stable STIX/OpenCTI object candidate.
- A relationship candidate.
- A label, note, marking or external reference.
- Scoring evidence.
- Quarantine-only evidence.
- Raw snapshot context only.

## Metadata Extractor Conventions

Each adapter should keep source-specific extraction small, explicit and
testable.

Recommended conventions:

- Keep source-specific extraction inside the adapter package.
- Name extraction functions after the source and output, such as
  `extract_source_galaxies`, `extract_source_detection_rules` or
  `extract_source_observables`.
- Return normalized plain dictionaries and lists, not STIX objects.
- Preserve the original source field name in `source_field`.
- Preserve source ids, UUIDs, tags and references when available.
- Add `confidence` only when the source field has a clear default confidence.
- Avoid creating actor, malware or campaign claims from generic text unless
  there is taxonomy, allowlist, galaxy, ATT&CK or provider evidence.
- Deduplicate inside the extractor by stable semantic keys before graph
  evidence is built.
- Keep weak hints as audit metadata until policy, scoring or analyst review can
  promote them.
- Add focused fixtures for nested, missing, duplicated and malformed source
  payloads.

Extractor output should be consumed by `core.graph_evidence`, which turns
source-normalized dictionaries into shared graph evidence records. This keeps
the gateway architecture source-aware at the edge and source-neutral in the
curation core.

## Adapter Contract

New adapters should produce normalized feed candidates compatible with the
shared gateway pipeline.

Minimum adapter output:

- `source.key` and `source.name`.
- Source identity display mapping for OpenCTI Author auditing.
- Stable `external_id`.
- Human-readable title.
- Description or narrative when available.
- Created, modified or published timestamps when available.
- Indicator or artifact list when the source has IoCs.
- Raw source snapshot bounded for audit.
- Source provenance and original provider metadata.
- Source guardrail metadata.

The adapter should not create arbitrary STIX objects directly. It should first
normalize source evidence so the shared graph evidence, candidate policy,
contextual scoring, deduplication, quarantine and STIX preview layers can make
the final decision.

## Mapping Validation Template

Use this table before promoting a new source beyond prototype status:

| Source field | Example value | Meaning | Confidence | Target use | Guardrail |
| --- | --- | --- | --- | --- | --- |
| `field_name` | `value` | What the field means | High/Medium/Low | STIX object, relationship, label, note, scoring, quarantine or raw context | Validation rule |

Use this table for graph candidates:

| Evidence | Entity type | STIX/OpenCTI target | Relationship | Default confidence | Promotion rule |
| --- | --- | --- | --- | --- | --- |
| Actor field | `threat_actor` | `threat-actor` | `attributed-to` | Medium | Require source field plus allowlist or corroboration |

Use this table for operational controls:

| Control | Environment variable | Default | Required before non-dry-run |
| --- | --- | --- | --- |
| Dry run | `SOURCE_DRY_RUN` | `true` | Must be explicitly set to `false` |
| Run once | `SOURCE_RUN_ONCE` | `true` for validation | Required for first local validation |
| Max records | `SOURCE_MAX_RECORDS_PER_RUN` | Source-specific safe cap | Required |

## Required Tests

Each new adapter should add focused tests for:

- Settings loading and required configuration validation.
- Source identity mapping, including deterministic author identity behavior in
  exported STIX bundles.
- Feed search/list behavior with pagination or limits.
- Enrichment of one source record into a normalized candidate.
- Guardrail behavior for oversized or unsafe records.
- Decision metadata with provenance and source guardrails.
- Graph evidence and graph candidate extraction.
- Contextual scoring dry-run metadata when graph candidates exist.
- Graph export plan and graph STIX preview metadata.
- Quarantine behavior for held records.
- Safe dry-run behavior without OpenCTI writes.

## Required Documentation

Each new adapter should update:

- `README.md` when the source becomes operator-visible.
- `docs/source-ingestion-modes-v0.7.md` when it changes the supported mode
  matrix.
- A source-specific mapping document under `docs/`.
- Release notes for the current development version.
- Configuration reference for all new environment variables.

## Promotion Gates

A new source should not move from prototype to supported adapter until:

- Unit tests cover settings, normalization, guardrails and metadata.
- Dry-run decision audit records show source evidence.
- Graph candidates are explainable and policy-filterable.
- `graph_stix_preview` can build a valid in-memory preview for accepted
  candidates when the source has graph context.
- Preflight exposes the enabled source posture.
- No real secrets or local runtime state are committed.

## Decision

Future sources must enter NarrowCTI as governed intelligence sources, not as
raw feed forwarders. The adapter's job is to preserve source truth and expose
the evidence NarrowCTI needs to decide, score, quarantine, deduplicate and
shape OpenCTI graph knowledge.
