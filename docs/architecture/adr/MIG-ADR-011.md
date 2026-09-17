# MIG-ADR-011 — Quarantine and review boundary

- Status: proposed
- Context: Low-confidence candidates can be held in a persistent quarantine repository and released by review.
- Proposed Decision: Keep quarantine transitions explicit, reasoned and idempotent, with export separate from release approval.
- Alternatives: Drop low scores irreversibly; export first and review later.
- Consequences: Analysts can release, partially release or reject with evidence and without bypassing policy.
- Dependencies: Quarantine and review API tests; ADR-007 and ADR-010.
- Target Wave: W1 architecture foundation; implementation deferred.

No quarantine state or endpoint changes are included.
