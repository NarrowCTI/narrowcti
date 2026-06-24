# Support Diagnostics - v0.8.0

## Purpose

This document defines the v0.8 support diagnostics foundation.

The goal is to give operators and support teams one read-only snapshot that
shows whether NarrowCTI is configured safely, where evidence is expected to be
written and what the current curation report says.

This is not a log collector, secret exporter or managed installer. It does not
call source APIs, query OpenCTI, mutate quarantine records or promote graph
objects.

## Current Implementation

v0.8 introduces `gateway.diagnostics`.

The module composes:

- `gateway.preflight` for runtime configuration, feature gates and issues.
- `gateway.curation_report` for curation, review and graph-readiness evidence.
- A local evidence inventory for configured state, audit, quarantine, release
  audit, deduplication and MITRE cache paths.

It exposes:

- `build_support_diagnostics`
- `collect_evidence_inventory`
- `redact_snapshot_dict`
- `format_text_snapshot`
- CLI entrypoint: `python -m gateway.diagnostics`

## CLI Usage

Text snapshot:

```powershell
python -m gateway.diagnostics `
  --summary-file state\gateway_runs.jsonl `
  --decision-path state\audit `
  --quarantine-file state\quarantine.jsonl `
  --release-audit-file state\audit\releases.jsonl
```

JSON snapshot:

```powershell
python -m gateway.diagnostics `
  --summary-file state\gateway_runs.jsonl `
  --decision-path state\audit `
  --quarantine-file state\quarantine.jsonl `
  --release-audit-file state\audit\releases.jsonl `
  --json
```

When arguments are omitted, the command falls back to the corresponding
`NARROWCTI_*` settings.

Support-safe redaction:

```powershell
python -m gateway.diagnostics `
  --redaction-profile support `
  --json
```

`--redaction-profile none` is the default and is intended for local use.
`--redaction-profile support` masks local paths and customer identifiers,
removes detailed query/failure/quarantine lists from the embedded curation
report and keeps aggregate counts, graph-readiness counters, preflight posture
and evidence availability. This profile is intended for sharing with support
without exposing local workstation paths or customer context.

## Snapshot Sections

The current snapshot contains:

- `preflight`: configuration posture, enabled sources, evidence paths, feature
  gates and preflight issues.
- `evidence_inventory`: configured local evidence paths with existence, kind,
  size and modification metadata.
- `curation_report`: executive curation summary, decisions, analyst review and
  graph-readiness evidence.
- `support_warnings`: deterministic support hints for blocking preflight
  errors, preflight warnings, missing evidence and empty curation evidence.
- `redaction_profile`: selected redaction mode, currently `none` or `support`.

## Product Boundary

The support snapshot is intentionally local and evidence-driven. It helps a
customer or support engineer answer:

- Is the gateway configured as expected?
- Are run summaries and decision audit files being written?
- Is quarantine/release audit evidence available?
- Does the curation report have enough data to explain what happened?
- Is graph promotion still held behind audit and validation controls?
- Can this snapshot be shared safely with support using the `support` redaction
  profile?

This preserves the NarrowCTI product boundary: the gateway remains the
curation, governance and explanation layer before OpenCTI graph promotion.

## Future Work

- Add optional archive generation once the safe file allowlist is stable.
- Add HTML/PDF diagnostic summaries after the report schema matures.
- Add UI/API access once analyst review surfaces are introduced.
