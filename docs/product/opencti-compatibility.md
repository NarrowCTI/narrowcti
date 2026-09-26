# OpenCTI Compatibility

This document defines the supported OpenCTI client boundary and the validation
required before NarrowCTI claims compatibility with a platform version.

## Supported Matrix

| OpenCTI platform | NarrowCTI client | Status |
| --- | --- | --- |
| `6.9.x` | `pycti 7.260710.0` through the NarrowCTI compatibility client | Supported and live-validated against `6.9.4`. |
| `7.x` | Native `pycti 7.260710.0` schema | Planned validation target; do not claim live compatibility until the release evidence passes. |
| Other `6.x` versions | No schema adaptation | Not validated. Upgrade to a supported platform or validate explicitly before ingestion. |

The dependency version remains pinned so source builds, CI and release images
use the same client behavior.

## OpenCTI 6.9 Boundary

`pycti 7` adds GraphQL input fields that OpenCTI `6.9.x` does not recognize.
NarrowCTI handles that difference in `gateway/opencti_client.py` rather than
scattering version checks across source adapters.

For a detected `6.9.x` platform, the client removes these fields only when
their values are empty:

- `files`
- `filesMarkings`
- `noTriggerImport`
- `embedded`
- `upsertOperations`
- observable inputs `AIPrompt`, `IMEI`, `ICCID` and `IMSI`, including their
  GraphQL declarations and arguments because those types do not exist in the
  OpenCTI `6.9.x` schema;

If any unsupported field contains data, the operation fails before sending the
request. NarrowCTI does not silently discard attachments, embedded content or
upsert instructions to preserve compatibility.

The exporter also treats every object returned in pycti's failed-import list as
a failed export. Source state, artifact deduplication and graph deduplication are
therefore not marked successful after a partial OpenCTI import.

For Sigma Indicators, NarrowCTI applies the same `sigmatools 0.23.1`
`SigmaCollectionParser` syntax gate used by OpenCTI `6.9.4`. A source rule that
passes basic YAML checks but fails that parser is preserved as a labeled Note
with its raw content and compatibility reason. If the parser is unavailable,
the gate fails closed to a Note instead of attempting an unverified Indicator.

OpenCTI `7.x` does not use this adaptation. The variables are sent through the
native `pycti 7` path.

## Validation Commands

The default check is read-only:

```powershell
python -m gateway.opencti_client_validation
```

The explicit write test is intended for a controlled validation environment:

```powershell
python -m gateway.opencti_client_validation --write-test
```

The write test imports one deterministic Report twice and then queries OpenCTI.
It passes only when authentication succeeds, no object is rejected and exactly
one matching Report exists. This proves the client can write through the
detected schema without introducing a duplicate Report.

## v0.9 Evidence

On July 10, 2026, the v0.9 development image was validated with:

- OpenCTI platform `6.9.4`;
- `pycti 7.260710.0`;
- authenticated GraphQL access;
- two imports of the same controlled STIX bundle;
- zero rejected objects;
- exactly one resulting Report;
- 503 passing containerized tests;
- no known dependency vulnerabilities reported by `pip-audit`.

This evidence must be refreshed against the final release commit and image.
