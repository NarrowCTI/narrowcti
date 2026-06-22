# NarrowCTI v0.6.0 Release Notes

## Status

`v0.6.0` is the quarantine and enrichment foundation release. It
extends the v0.5 gateway runtime with reviewable quarantine, release audit,
controlled replay, source entity extraction and local MITRE ATT&CK reference
resolution.

## Product Value

This release turns quarantine into an operational workflow. Held intelligence is
no longer only an audit outcome; it can be reviewed, released, partially
released, rejected and replayed through the same OpenCTI export path with
deduplication controls.

It also starts the enrichment foundation for the NarrowCTI product direction:
OTX source payloads now preserve adversary, malware family, ATT&CK, industry,
country, TLP, reference and tag evidence, and ATT&CK ids can be resolved through
a local cache without treating MITRE as an IoC feed.

## Highlights

- Adds a local append-friendly quarantine repository.
- Adds quarantine CLI commands for list, show, reject, release,
  partial release and export replay.
- Adds release audit records with reviewer, reason, released indicators,
  held indicators and export evidence.
- Adds CLI inspection for release, reject and export audit events, including
  `audit --action export`.
- Makes release/reject/partial-release CLI reason enforcement follow
  `NARROWCTI_RELEASE_QUARANTINE_REQUIRES_REASON`.
- Automatically queues OTX and MISP policy-quarantined candidates when a
  quarantine repository is configured.
- Replays released quarantine records through the existing STIX/OpenCTI export
  path, dry-run by default and `--execute` for real export.
- Preserves deduplication behavior during released-record replay.
- Adds OTX entity extraction metadata for actor, malware family, ATT&CK ids,
  industries, countries, TLP, references and tags.
- Adds local MITRE ATT&CK cache parsing, refresh tooling and technique/tactic
  resolution.
- Adds missing-cache evidence when ATT&CK enrichment is unavailable instead of
  blocking ingestion.
- Extends gateway operational reporting with quarantine review metrics.
- Extends preflight health checks for release audit, MITRE cache and ATT&CK
  resolver posture.

## Configuration Added

The v0.6 configuration reference is tracked in
`docs/configuration-reference-v0.6.md`.

```env
NARROWCTI_QUARANTINE_REPOSITORY=/app/state/quarantine.jsonl
OTX_QUARANTINE_REPOSITORY=/app/state/quarantine.jsonl
MISP_QUARANTINE_REPOSITORY=/app/state/quarantine.jsonl
NARROWCTI_RELEASE_AUDIT_FILE=/app/state/audit/releases.jsonl
NARROWCTI_RELEASE_QUARANTINE_REQUIRES_REASON=true
NARROWCTI_REVIEWER=operator
NARROWCTI_QUARANTINE_RAW_SNAPSHOT_MAX_BYTES=65536
NARROWCTI_ENABLE_OTX_ENTITY_EXTRACTION=true
NARROWCTI_ENABLE_MITRE_ATTACK_RESOLUTION=true
NARROWCTI_MITRE_CACHE_FILE=/app/state/mitre_attack_cache.json
NARROWCTI_MITRE_STIX_URL=https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json
```

## Operational Commands

Quarantine review:

```powershell
python -m gateway.quarantine --repository state\quarantine.jsonl list --status pending
python -m gateway.quarantine --repository state\quarantine.jsonl show --id <quarantine-id>
python -m gateway.quarantine --repository state\quarantine.jsonl --release-audit-file state\audit\releases.jsonl reject --id <quarantine-id> --reason "Out of scope"
python -m gateway.quarantine --repository state\quarantine.jsonl --release-audit-file state\audit\releases.jsonl release --id <quarantine-id> --reason "Relevant to monitored actor"
python -m gateway.quarantine --repository state\quarantine.jsonl --release-audit-file state\audit\releases.jsonl release-indicators --id <quarantine-id> --type filehash-sha256,url --reason "High-value indicators"
python -m gateway.quarantine --repository state\quarantine.jsonl export-released --id <quarantine-id>
python -m gateway.quarantine --repository state\quarantine.jsonl export-released --id <quarantine-id> --execute --dedup-state-file state\dedup_index.json
python -m gateway.quarantine --release-audit-file state\audit\releases.jsonl audit --limit 20
```

MITRE cache:

```powershell
python -m gateway.mitre build-cache --bundle enterprise-attack.json --cache-file state\mitre_attack_cache.json
python -m gateway.mitre refresh-cache --cache-file state\mitre_attack_cache.json
python -m gateway.mitre resolve --cache-file state\mitre_attack_cache.json T1059 T1059.001
```

Readiness and reporting:

```powershell
python -m gateway.preflight
python -m gateway.preflight --json
python -m gateway.report --file state\gateway_runs.jsonl --quarantine-file state\quarantine.jsonl
python -m gateway.report --file state\gateway_runs.jsonl --quarantine-file state\quarantine.jsonl --json
```

## Test Validation

Release validation was performed with the existing
`opencti-connector-narrowcti` test image:

```powershell
.\scripts\validate-v0.6.ps1
```

The helper executes the Docker-based syntax and unit validation. Use
`.\scripts\validate-v0.6.ps1 -Preview` to inspect the Docker commands without
running them.

Manual equivalent:

```powershell
docker run --rm -v "${PWD}:/repo" -w /repo opencti-connector-narrowcti python -m py_compile gateway/settings.py gateway/preflight.py
docker run --rm -v "${PWD}:/repo" -w /repo opencti-connector-narrowcti python -m unittest tests.test_gateway_preflight tests.test_gateway_runtime -v
docker run --rm -v "${PWD}:/repo" -w /repo opencti-connector-narrowcti python -m unittest discover -s tests -v
```

Latest complete suite result:

```text
.\scripts\validate-v0.6.ps1
Ran 190 tests
OK
```

Safe operational validation performed on the release:

```text
python -m gateway.mitre refresh-cache --cache-file state/mitre_attack_cache.json
technique_count=858

python -m gateway.preflight
ok=true
enabled_sources=otx
dedup_mode=hybrid
enable_mitre_attack_resolution=true
mitre_cache_file=/repo/state/mitre_attack_cache.json
issues=none

controlled OTX dry-run
query=lummac2 reviewed=1 ingested=0 dropped=1 quarantined=0 skipped=0 errors=0

controlled MISP dry-run
query=* reviewed=1 ingested=0 dropped=0 quarantined=1 skipped=0 errors=0

quarantine workflow validation
list_pending=1
release_audit=ok
reject_audit=ok
export_dry_run=ok
export_execute_dedup_skip=ok
audit_action_export=ok
```

Final release validation should also run:

```powershell
.\scripts\validate-v0.6.ps1
```

Manual equivalent:

```powershell
docker run --rm -v "${LAB_ROOT}\NarrowCTI:/repo" -w /repo opencti-connector-narrowcti python -m py_compile connectors/otx/connector.py connectors/otx/entity_extraction.py connectors/otx/feed_adapter.py connectors/otx/models.py connectors/otx/processor.py connectors/otx/runtime.py connectors/otx/settings.py connectors/otx/otx_client.py connectors/misp/client.py connectors/misp/connector.py connectors/misp/feed_adapter.py connectors/misp/models.py connectors/misp/processor.py connectors/misp/runtime.py connectors/misp/settings.py core/decision_audit.py core/feed_contract.py core/indicator_policy.py core/mitre_attack.py core/quarantine.py core/scoring.py core/policy.py core/state_repository.py core/tlp.py exporters/opencti.py exporters/stix_builder.py
docker run --rm -v "${LAB_ROOT}\NarrowCTI:/repo" -w /repo opencti-connector-narrowcti python -m py_compile gateway/preflight.py gateway/report.py gateway/decisions.py gateway/correlation.py gateway/mitre.py gateway/quarantine.py gateway/quarantine_export.py
docker run --rm -v "${LAB_ROOT}\NarrowCTI:/repo" -w /repo opencti-connector-narrowcti python -m unittest discover -s tests -v
```

## Release Boundaries

- v0.6 is CLI-first and local-state-first.
- Customer-facing UI is not included.
- Full graph enrichment for actors, malware, sectors, locations and
  relationships is deferred to v0.7.
- Enterprise policy filters for actor, arsenal, tactic, sector and geography are
  deferred to v0.7.
- MITRE ATT&CK is used as reference data, not as an intelligence feed.
- Missing MITRE cache does not block ingestion; it records missing enrichment
  evidence.
- Broad MISP historical backfill remains out of scope by default.
- License enforcement remains out of scope for this release.

## Final Release Checklist Status

- [x] Run full test validation.
- [x] Run preflight with the intended lab `.env`.
- [x] Build or refresh the MITRE cache when ATT&CK enrichment is expected.
- [x] Run one controlled OTX dry-run that produces decision audit evidence.
- [x] Run one controlled MISP dry-run when MISP is enabled.
- [x] Confirm at least one quarantine record can be listed and inspected.
- [x] Confirm release and reject write release audit evidence.
- [x] Confirm release, reject and export audit events can be inspected with
  `gateway.quarantine audit`.
- [x] Confirm `export-released` dry-run reports export intent without importing.
- [x] Confirm controlled `export-released --execute` behavior after validating
  OpenCTI capacity and deduplication posture.

The `export-released --execute` validation used a dedup-skip record so the
export execution path, exported-state marking and `action=export` audit evidence
were validated without importing synthetic validation data into OpenCTI.

## Next Release Direction

v0.7 should use this foundation to move from metadata and review workflow into
graph enrichment and enterprise filters. The centralized v0.7 design is tracked
in `docs/graph-enrichment-v0.7.md`.

- STIX/OpenCTI objects for actors, malware, tools, sectors, locations and
  attack patterns.
- Relationship evidence with confidence and provenance.
- Enterprise policy variables for actor, arsenal, ATT&CK tactic/technique,
  target sector and geography.
- Graph hygiene beyond indicator deduplication.
- Broader source metadata validation so OTX, MISP and MITRE evidence can
  populate richer OpenCTI graph views with enterprise CTI context.
