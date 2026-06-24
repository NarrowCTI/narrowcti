# MITRE Curation Architecture - v0.7.0

## Purpose

This document records the v0.7 architecture decision for MITRE ATT&CK usage in
NarrowCTI.

NarrowCTI must not compete with the official MITRE/OpenCTI connector as a simple
ATT&CK importer. The value of NarrowCTI is to use MITRE as curation context for
raw intelligence sources, then decide what should become OpenCTI graph knowledge.

## Architecture Decision

The ideal architecture separates canonical reference loading from curated source
enrichment:

```text
Official MITRE connector
  -> populates OpenCTI with the canonical ATT&CK baseline

NarrowCTI
  -> uses MITRE to enrich OTX, MISP and future source evidence
  -> creates curated relationships only when source evidence supports them
```

This keeps OpenCTI as the protected intelligence graph and avoids turning
NarrowCTI into a duplicate ATT&CK loader.

## NarrowCTI MITRE Flow

The target NarrowCTI flow is:

```text
OTX / MISP / raw feed
  -> source metadata extraction
  -> find ATT&CK id such as T1059
  -> resolve technique name, tactic, kill chain, platform, data sources and
     detection guidance through MITRE reference data
  -> relate the technique to actor, malware, sector or geography only when the
     source metadata provides enough provenance
  -> apply score, filters, TLP, deduplication, policy and audit
  -> send contextualized intelligence to OpenCTI
```

The important product behavior is that MITRE context improves the quality of
curation before OpenCTI ingestion. MITRE evidence should help NarrowCTI explain
why an object or relationship is useful, not bypass policy controls.

## v0.7 Closure Boundary

v0.7 closes this architecture as an audit-first foundation:

- Local MITRE ATT&CK cache parsing and technique resolution are implemented.
- Technique metadata includes name, description, external references, kill chain
  phases, platforms, data sources, detection guidance, domains and lifecycle
  fields.
- OTX and MISP metadata can produce graph evidence and graph candidates from
  resolved ATT&CK context.
- OTX pulses with exactly one adversary can preview actor-anchored relationships
  such as `threat-actor -> uses -> attack-pattern`.
- The STIX preview can build supported graph objects and controlled
  relationships in memory for audit and validation.
- Decision audit summaries expose object counts, relationship counts, semantic
  relationship counts, report-context relationship counts and skipped
  candidates.

v0.7 does not yet promote canonical ATT&CK graph relationships into OpenCTI. It
does not query OpenCTI for existing ATT&CK objects, and it does not mark graph
objects or relationships as exported knowledge.

## Next Promotion Gate

The next controlled implementation step is OpenCTI canonical graph linking:

1. Keep the official MITRE connector responsible for loading the canonical
   ATT&CK baseline into OpenCTI.
2. Before graph promotion, look up existing OpenCTI ATT&CK objects by stable
   identifiers such as `external_id=T1059` or STIX id.
3. When a canonical object exists, create curated relationships to that object
   instead of creating a duplicate attack-pattern.
4. When a canonical object is missing, hold the candidate, keep it in dry-run,
   or create it only if policy explicitly allows that behavior.
5. Persist successful graph promotions in the local graph deduplication state
   and preserve source sightings for later audit and reporting.

## Non-Goals

NarrowCTI should not:

- Import the full ATT&CK corpus into OpenCTI as a competing MITRE connector.
- Create strong attribution from weak ATT&CK tags without source provenance.
- Create duplicate OpenCTI attack-pattern objects when the canonical MITRE
  object already exists.
- Bypass score, TLP, quarantine, policy, deduplication or audit because a source
  mentions a valid ATT&CK technique.

## Product Outcome

This decision preserves the intended enterprise product posture:

```text
canonical ATT&CK baseline in OpenCTI
  + curated feed evidence through NarrowCTI
  + explicit policy and provenance
  = cleaner, richer OpenCTI graph intelligence
```

The result is a gateway that can enrich actor, arsenal, TTP, victimology,
infrastructure, vulnerability and detection context without flooding OpenCTI
with low-confidence or duplicate feed artifacts.
