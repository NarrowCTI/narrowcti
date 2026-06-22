# NarrowCTI v0.4.0 Release Notes

## Status

`v0.4.0` is the multi-feed expansion release. It promotes NarrowCTI from an
OTX-only gateway foundation into a validated two-source architecture with OTX as
the reference adapter and MISP as the first controlled second-source foundation.

This release keeps MISP opt-in, bounded and dry-run-first. It does not promote
broad scheduled MISP ingestion.

## Highlights

- Adds the MISP adapter foundation with client, feed adapter, processor,
  settings and source-specific state.
- Reuses the shared feed contract, scoring, policy, decision audit and OpenCTI
  export paths across OTX and MISP.
- Preserves MISP collector context and original-source provenance when available.
- Adds MISP metadata-first guardrails for event volume and oversized attribute
  payloads.
- Adds `MISP_MAX_EVENTS_PER_RUN`, `MISP_MAX_ATTRIBUTES_PER_EVENT`,
  `MISP_MAX_IOCS_PER_EVENT`, `MISP_OVERSIZED_EVENT_ACTION`, date filters, tag
  filters and published-only filters.
- Adds dry-run and run-once execution for controlled local validation.
- Adds a safe MISP backfill helper with preview mode and capped run limits.
- Adds operational summaries for skipped, error and dry-run outcomes.
- Documents bounded operational validation with OpenCTI, MISP, Caddy and
  Elasticsearch staying healthy after opt-in MISP runs.

## Validation

Final v0.4 validation should include:

```powershell
docker run --rm -e PYTHONDONTWRITEBYTECODE=1 -v "${LAB_ROOT}\NarrowCTI:/repo" -w /repo opencti-connector-narrowcti python -m py_compile connectors/otx/connector.py connectors/otx/feed_adapter.py connectors/otx/models.py connectors/otx/processor.py connectors/otx/runtime.py connectors/otx/settings.py connectors/otx/otx_client.py connectors/misp/client.py connectors/misp/connector.py connectors/misp/feed_adapter.py connectors/misp/models.py connectors/misp/processor.py connectors/misp/runtime.py connectors/misp/settings.py core/decision_audit.py core/feed_contract.py core/scoring.py core/policy.py core/state_repository.py exporters/opencti.py exporters/stix_builder.py

docker run --rm -e PYTHONDONTWRITEBYTECODE=1 -v "${LAB_ROOT}\NarrowCTI:/repo" -w /repo opencti-connector-narrowcti python -m unittest discover -s tests -v
```

The bounded local MISP operational evidence is documented in
`docs/misp-validation-v0.4.md`.

## Release Boundaries

- MISP remains a foundation runtime path, not a production scheduled ingestion
  default.
- Direct OTX remains supported as the reference adapter.
- Runtime containers remain split by source in v0.4.
- The unified gateway runtime begins in v0.5.
- No customer-facing admin UI or license enforcement is added in this release.