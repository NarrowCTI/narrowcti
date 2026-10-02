# Community MISP Explorer search and detail contract

This document defines the current bounded MISP behavior of the Community Web
Source Explorer. It is a read-only, transient projection. It does not change
MISP data, create graph entities or replace Worker ingestion.

## Search intent

The Explorer selects a bounded provider strategy from the query shape:

| User intent | MISP operation | Result identity |
| --- | --- | --- |
| IPv4/IPv6, hostname/domain, MD5, SHA-1 or SHA-256 observable | `POST /attributes/restSearch` by exact `value`, with optional provider-side tag filters | Attribute rows are projected and deduplicated to their event identity. |
| Generic event text without an explicit tag | `POST /events/index` with `searcheventinfo`, plus bounded `/tags/search` resolution and at most one event search by canonical tags | Event-level results, deduplicated by event identity. |
| Generic text with an explicit tag filter | `POST /events/restSearch` with `eventinfo` and `tags` | Event-level results, deduplicated by event identity. |

The implementation does not use `searchall` or `searchattribute`. It does not
hydrate event detail during search. Request count, aggregate deadline,
response size, candidate count and displayed result count are bounded; the
search result's `truncated`/`has_more` indication is conservative when the
provider or bounded tag-resolution path may have omitted further matches.
Provider-specific filters remain provider-specific; no universal CTI query
language is implied.

## Bounded event detail

MISP detail makes two sequential requests at most:

1. `GET /events/view2/{id}.json` for the event shell.
2. `POST /events/viewAttributes/{id}.json` with `page=1` and `limit=101`.

Both calls share one monotonic aggregate deadline, use the existing per-provider
Web concurrency bound, and each response is capped by
`NARROWCTI_WEB_SOURCE_MAX_RESPONSE_BYTES` (default `1000000` bytes). No extra
page, N+1 lookup, `/events/view` request or full-event fallback is allowed.
The adapter validates event ID, UUID when present, attribute event identity,
response shapes and provider totals. Any malformed or inconsistent result
fails closed as `invalid_provider_response`. It renders at most 100 attributes,
caps each value at 512 characters, and sets `attributes_truncated` only when
the provider-reported total exceeds 100. Invalid/dropped rows do not fabricate
truncation. This detail contract requires MISP `>= 2.5.35`.

Because the detail is bounded, it does not issue an authoritative
`revision_fingerprint`. OTX detail continues to use its existing full-document
fingerprint contract.

## Preview is the revision authority

For MISP, Preview may be submitted without a fingerprint from detail. The
Worker fetches the full Event once, calculates
`source_document_fingerprint()` from that exact raw document, normalizes and
evaluates the same fetched document through the existing source-specific
processor, and returns only the bounded result plus the authoritative
fingerprint. The raw Event is not put in the job payload, result, browser or
logs. Preview has no durable candidate effects.
If the existing source-specific normalization policy intentionally yields no
candidate (for example, the oversized-event `skip` policy), Preview returns a
bounded terminal skip with the fingerprint from that same raw Event and does
not offer Dry-run or Run-once follow-up.

Dry-run and Run-once require the fingerprint returned by Preview. The Worker
refetches the full Event and compares the full-document digest before
normalization or processing. A mismatch returns `candidate_changed` and does
not proceed. Each follow-up submission uses a new request ID. OTX's existing
Preview fingerprint and full-document comparison behavior remain unchanged.

An ambiguous 404 from the bounded detail endpoint is not alone treated as
proof of an old MISP version. The adapter performs bounded version discovery
only when needed to distinguish an unsupported endpoint from an event that is
not found. Unsupported versions fail closed as `provider_unavailable`; a
supported server with a missing event reports `source_not_found`.

See [Community Web and Source Explorer](web-source-explorer.md) for operator
setup, credentials and the broader Web contract.
