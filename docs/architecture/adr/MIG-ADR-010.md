# MIG-ADR-010 — Decision and audit record

- Status: proposed
- Context: Decisions record source, query, score, action, reason and metadata in JSONL audit evidence.
- Proposed Decision: Preserve a serializable DecisionRecord as the audit boundary for policy and graph outcomes.
- Alternatives: Log free-form text only; store decisions solely in OpenCTI.
- Consequences: Dry-run, review and production outcomes remain comparable and export-independent.
- Dependencies: DecisionRecord golden fixture and existing audit tests; ADR-005 and ADR-012.
- Target Wave: W1 architecture foundation; implementation deferred.

The W0 branch only freezes the contract.
