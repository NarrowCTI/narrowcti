# MIG-ADR-005 — Domain primitives

- Status: accepted for W1 / PR-05
- Context: The characterized feed contract, scoring, contextual scoring, TLP,
  policy and indicator filtering primitives are currently implemented under
  `core`. They are consumed by MISP/OTX orchestration, gateway configuration,
  graph evidence and audit paths. The migration must establish a pure domain
  owner without moving orchestration or persistence into the domain.
- Proposed Decision: Introduce only the characterized domain primitives under
  `src/narrowcti/domain/intelligence`: `FeedSource`, `FeedCandidate` and
  `slugify`; scoring; pure contextual scoring; TLP; policy; indicator types;
  and indicator policy. `FeedAdapter`, `FeedRunSummary`, decision records,
  persistence, graph runtime and source orchestration remain in their current
  layers. The domain may depend on sibling domain modules, but never on
  `core`, connectors, gateway, exporters, infrastructure or adapters.
- Alternatives: Move the full feed/application stack at once; keep domain
  logic permanently in `core`; introduce runtime import hooks to hide the
  boundary.
- Consequences: The selected primitives gain one canonical implementation and
  legacy `core.*` modules reexport the same objects. Existing behavior,
  serialized outputs and import compatibility remain characterization
  contracts. No new orchestration API is introduced by PR-05.
- Dependencies: W0 golden fixtures, MIG-ADR-001, MIG-ADR-002 and
  MIG-ADR-014. MIG-ADR-006 is related to the evidence contract but is not a
  prerequisite dependency for these domain primitives.
- Target Wave: W1 / PR-05.

## PR-05 characterization contract

The domain does not orchestrate the ingestion pipeline. Existing processors
must continue to characterize these stages independently:

```text
prechecks:
normalize/id → processed-state → enrichment

decision chain:
TLP
→ contextual scoring
→ policy (hard age first)
→ indicator type
→ artifact dedup
→ dry-run/export
```

Side effects remain outside the domain and are tested separately:

```text
successful export → artifact mark → source checkpoint
dry-run           → no source checkpoint
export error      → no source checkpoint
all paths         → existing evidence/DecisionRecord contract
```

`age_days()` retains its current temporal semantics and outputs. Clock
abstraction is outside PR-05.
