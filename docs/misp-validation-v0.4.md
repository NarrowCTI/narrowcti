# MISP Runtime Validation - v0.4.0

Validation date: 2026-06-21.

## Scope

This validation checked the local OpenCTI, MISP and official OpenCTI MISP
connector runtime before finalizing the NarrowCTI MISP adapter mapping.

The goal was to observe real MISP event structure and connector behavior without
running an uncontrolled historical import on a resource-limited workstation.

## Environment

- OpenCTI platform: 6.9.4.
- OpenCTI MISP connector image: opencti/connector-misp:6.9.4.
- MISP core exposed locally through Caddy as `misp.local` and directly on port
  8081.
- OpenCTI exposed locally through Caddy as `opencti.local` and directly on port
  8080.

## Service Validation

OpenCTI core was started first. Elasticsearch became healthy, then OpenCTI and
the worker came online.

Validated signals:

- `http://localhost:8080` returned HTTP 200.
- `https://opencti.local` returned HTTP 200 through Caddy.
- GraphQL `about.version` returned `6.9.4`.
- MISP UI returned HTTP 302, which is expected for unauthenticated browser
  access.
- MISP API calls succeeded through `http://localhost:8081` using the configured
  local API key.

## Real MISP Payload Shape

A metadata query with no narrow filter showed why MISP must be handled more
carefully than OTX. One event can represent a very large feed.

Observed examples:

| Event | Info | Published | Attribute count | Tags |
| --- | --- | --- | ---: | --- |
| 1 | URLHaus Malware URLs feed | false | 16922 | `osint:source-type="block-or-filter-list"` |
| 2 | MalwareBazaar malware samples for 2026-01-02 | true | 7652 | `type:OSINT` |
| 3 | ThreatFox IOCs for 2022-05-17 | true | 11367 | `type:OSINT` |
| 12 | OSINT - New Hacking team samples (OSX) | true | 10 | `type:OSINT`, `circl:incident-classification="malware"`, `tlp:green` |

The event used as the safe mapping sample was event `12`.

Observed event keys:

```text
analysis, Attribute, attribute_count, CryptographicKey, date,
disable_correlation, distribution, event_creator_email, EventReport,
extends_uuid, first_publication, Galaxy, id, info, locked, Object, Org,
org_id, Orgc, orgc_id, proposal_email_lock, protected, publish_timestamp,
published, RelatedEvent, ShadowAttribute, sharing_group_id, Tag,
threat_level_id, timestamp, uuid
```

Observed attribute keys:

```text
category, comment, deleted, disable_correlation, distribution, event_id,
first_seen, Galaxy, id, last_seen, object_id, object_relation,
ShadowAttribute, sharing_group_id, timestamp, to_ids, type, uuid, value
```

Event `12` attribute type distribution:

| Attribute type | Count | Mapping decision |
| --- | ---: | --- |
| `sha256` | 2 | `filehash-sha256` indicator when `to_ids=true` |
| `sha1` | 2 | `filehash-sha1` indicator when `to_ids=true` |
| `md5` | 2 | `filehash-md5` indicator when `to_ids=true` |
| `ip-dst` | 1 | `ipv4` or `ipv6` indicator when `to_ids=true` |
| `link` | 3 | context/external analysis; not an IoC when `to_ids=false` |

## Official Connector Behavior

The official connector was started with a narrow local filter:

```text
MISP_IMPORT_FROM_DATE=2016-02-29
MISP_IMPORT_TAGS=tlp:green
MISP_IMPORT_ONLY_PUBLISHED=true
MISP_IMPORT_LIMIT=1
```

The connector registered successfully and imported event `12`, but then
continued to event `21` and started event `287` before it was stopped manually.
This happened because `MISP_IMPORT_LIMIT` is not supported by
`opencti/connector-misp:6.9.4`.

Evidence from the connector image:

- `config.yml.sample` does not define `MISP_IMPORT_LIMIT`.
- `connector/config_loader.py` has no `import_limit` field.
- `api_client/client.py` hardcodes `limit=10` per API page and keeps paginating
  until no more events are returned.

The connector was stopped to protect the local machine. RabbitMQ queue
`push_misp-connector` drained to `0` ready and `0` unacknowledged messages.
After draining, OpenCTI remained healthy and resource usage returned to a safe
baseline.

Final observed baseline after drain:

- OpenCTI HTTP: 200.
- Elasticsearch CPU: about 2 percent.
- OpenCTI CPU: about 2 percent.
- Worker CPU: below 1 percent.

## Local Stack Guardrail

After validation, the local OpenCTI compose was corrected:

- Removed unsupported `MISP_IMPORT_LIMIT` from the MISP connector environment.
- Replaced unsupported `CONNECTOR_RUN_EVERY` with supported
  `CONNECTOR_DURATION_PERIOD`.
- Added supported MISP filter variables for date field, datetime attribute and
  keyword.
- Left the MISP connector stopped.
- Set the local `.env` MISP import date to `2026-12-31` as a guard against
  accidental restart-driven backfill.

## Product Implications For NarrowCTI

NarrowCTI should not rely on the official OpenCTI MISP connector for controlled
historical backfill on limited environments. The product adapter should query
MISP directly and enforce its own controls.

Required NarrowCTI controls for the MISP adapter:

- Maximum events per run.
- Maximum attributes per event.
- Optional skip/quarantine for oversized events.
- Explicit event metadata logging before attribute normalization.
- Persistent adapter state independent from the official OpenCTI MISP connector.
- Clear provenance fields for collector (`MISP`) and original source (`Orgc`,
  `Org`, `source` or event tags when available).


## Implemented Adapter Safeguards

The v0.4 adapter foundation now implements the first direct safeguards required
by the runtime validation:

- `MISPClient.search_events()` supports metadata searches and an explicit API
  limit payload.
- `MISPFeedAdapter.search()` requests metadata first and caps normalized search
  candidates with `max_events_per_run`.
- `MISPFeedAdapter` checks MISP `attribute_count` before normalizing attributes.
- Oversized events are skipped by default.
- A bounded `truncate` mode exists for controlled experiments and records the
  guardrail decision in `raw["narrowcti_controls"]`.
- `MISPSettings` centralizes required runtime configuration, timeouts and
  safety limits from environment variables.
- `MISPEventStateRepository` provides persistent MISP event state independent
  from OTX pulse state.
- `MISPProcessor` connects MISP candidates to the shared policy, scoring,
  decision audit and OpenCTI export flow.
- A dedicated MISP entrypoint exists for explicit validation with
  `python -m connectors.misp.connector`; it is not the Docker default.
- Dry-run validation is the default through `MISP_DRY_RUN=true`, preventing
  OpenCTI export and state marking while still exercising MISP search,
  enrichment, scoring, policy and audit paths.
- Decision-audit records now include MISP provenance metadata for collector,
  original source, event identifiers, tags and guardrail context.

Default foundation limits:

```text
max_events_per_run=10
max_attributes_per_event=1000
oversized_event_action=skip
```

These controls do not yet make MISP a production-ready runtime path. They
establish the controlled runtime foundation needed before local stack
validation and an opt-in Compose service are added.

## Mapping Decision

The v0.4 MISP adapter should normalize `Event` records into `FeedCandidate`
objects and treat attributes as IoC candidates only when they are actionable.

Initial supported MISP attribute families:

- Domains and hostnames.
- IPv4 and IPv6 values, including common IP plus port composite types.
- URLs and URIs.
- Email indicators.
- MD5, SHA1 and SHA256 hashes.
- Filename plus hash composite values, mapped to the hash indicator.

Context fields such as `link` attributes with `to_ids=false` should remain in
raw event context and not become indicators.

## NarrowCTI Dry-Run Runtime Validation

A dedicated NarrowCTI MISP dry-run validation was performed on 2026-06-21 after
adding the MISP processor foundation.

Validation controls:

```text
MISP_QUERIES=tlp:green
MISP_MAX_EVENTS_PER_RUN=1
MISP_MAX_ATTRIBUTES_PER_EVENT=1000
MISP_MAX_IOCS_PER_EVENT=20
MISP_DRY_RUN=true
```

Observed result with the default policy:

- MISP `/events/restSearch` returned HTTP 200.
- MISP `/events/view/56d4b32d-664c-4647-a748-1362950d210f` returned HTTP 200.
- NarrowCTI normalized `OSINT - New Hacking team samples (OSX)`.
- The event produced 7 actionable IoCs after normalization.
- Score was 40 with age around 3765 days.
- Default policy quarantined the event as `low score`.
- Summary: `reviewed=1 ingested=0 dropped=0 quarantined=1 skipped=0 errors=0 dry_run=0 available=1`.

A second validation intentionally relaxed policy thresholds only to prove the
non-exporting dry-run path:

```text
MIN_SCORE_TO_INGEST=0
ENABLE_QUARANTINE=false
QUARANTINE_SCORE_THRESHOLD=0
MAX_DAYS_OLD=9999
MISP_DRY_RUN=true
```

Observed result:

- Same MISP search and enrichment calls returned HTTP 200.
- NarrowCTI reached the would-ingest path and returned `dry_run=1`.
- No OpenCTI export was attempted.
- No MISP event state was marked because the validation used ephemeral `/tmp`
  state inside a one-shot container.
- Summary: `reviewed=1 ingested=0 dropped=0 quarantined=0 skipped=0 errors=0 dry_run=1 available=1`.

Provenance audit validation was repeated after adding audit metadata. The same
bounded dry-run path produced an audit record with:

```json
{
  "collector": "misp",
  "original_source": "CIRCL",
  "misp_event_id": "12",
  "misp_event_uuid": "56d4b32d-664c-4647-a748-1362950d210f",
  "tags": ["type:OSINT", "circl:incident-classification=\"malware\"", "tlp:green"],
  "guardrails": {
    "attribute_count": 10,
    "max_attributes_per_event": 1000,
    "oversized": false,
    "oversized_event_action": "skip"
  }
}
```

This confirms the audit trail can distinguish the collector (`MISP`) from the
original event source (`CIRCL`) while preserving event identifiers and guardrail
context.

Post-validation stack signals:

- OpenCTI HTTP on `localhost:8080` returned 200.
- MISP browser entrypoint on `localhost:8081` returned 302, expected for login
  redirect.
- OpenCTI and MISP Compose services remained up; Elasticsearch and MISP DB were
  healthy.
