# OTX Official Connector Mapping Baseline - v0.7.0

## Purpose

This document records how the official OpenCTI AlienVault OTX connector maps
OTX pulses into STIX/OpenCTI and how NarrowCTI should use that behavior as a
source-specific compatibility baseline for v0.7 graph enrichment.

The MISP official connector remains the best reference for broad OpenCTI graph
semantics. The OTX official connector is still required as a separate baseline
because OTX has a different payload model: pulses, pulse indicators, ATT&CK
ids, malware families, adversary hints, industries, targeted countries,
references, TLP and free tags.

## Validation Evidence

Local validation inspected the official connector image aligned with the lab
OpenCTI version:

```text
image: opencti/connector-alienvault:6.9.4
digest: sha256:87e08fb2b78ff8a8dc9a830206b7511a522169477c0f0b4fe07da3a25cf10ec3
size: 45825834 bytes
```

Important files inspected inside the image:

```text
/opt/opencti-connector-alienvault/alienvault/builder.py
/opt/opencti-connector-alienvault/alienvault/importer.py
/opt/opencti-connector-alienvault/alienvault/models.py
/opt/opencti-connector-alienvault/alienvault/core.py
/opt/opencti-connector-alienvault/alienvault/client.py
/opt/opencti-connector-alienvault/alienvault/utils/__init__.py
/opt/opencti-connector-alienvault/alienvault/utils/indicators.py
/opt/opencti-connector-alienvault/alienvault/utils/observables.py
/opt/opencti-connector-alienvault/alienvault/utils/constants.py
/opt/opencti-connector-alienvault/config.yml.sample
```

The official connector source is published in the OpenCTI connectors project
under `external-import/alienvault`, and the official image is published as
`opencti/connector-alienvault`.

Reference links:

```text
https://github.com/OpenCTI-Platform/connectors/tree/master/external-import/alienvault
https://hub.docker.com/r/opencti/connector-alienvault
```

No runtime OTX API key is required for this code-level mapping validation.

## Official Connector Flow

The official connector follows this high-level flow:

```text
OTX subscribed pulses
  -> latest_pulse_timestamp state
  -> optional indicator-created-time filter
  -> PulseBundleBuilder
  -> STIX bundle
  -> OpenCTI send_stix2_bundle
```

It uses `OTXv2.getsince(timestamp=modified_since, limit=20)` to retrieve
subscribed pulses. This runtime behavior has historically been fragile in some
OTX environments, which is one reason NarrowCTI has its own OTX client and
query/enrichment model. The mapping logic is still valuable as a baseline.

## Official Configuration Surface

The official connector exposes these OTX-specific controls:

- `ALIENVAULT_CREATE_OBSERVABLES`
- `ALIENVAULT_CREATE_INDICATORS`
- `ALIENVAULT_PULSE_START_TIMESTAMP`
- `ALIENVAULT_REPORT_TYPE`
- `ALIENVAULT_REPORT_STATUS`
- `ALIENVAULT_GUESS_MALWARE`
- `ALIENVAULT_GUESS_CVE`
- `ALIENVAULT_EXCLUDED_PULSE_INDICATOR_TYPES`
- `ALIENVAULT_ENABLE_RELATIONSHIPS`
- `ALIENVAULT_ENABLE_ATTACK_PATTERNS_INDICATES`
- `ALIENVAULT_FILTER_INDICATORS`
- `ALIENVAULT_DEFAULT_X_OPENCTI_SCORE`
- Type-specific OpenCTI scores for IP, domain, hostname, email, file, URL,
  mutex and cryptocurrency wallet indicators.

NarrowCTI should keep its broader gateway controls, quarantine workflow and
guardrails, but these official knobs are useful compatibility references for
operator-facing policy design.

## Official Pulse Model

The official connector validates OTX pulses with these high-value fields:

| OTX field | Official use |
| --- | --- |
| `id` | Pulse external id and OTX pulse URL. |
| `name` | Report name. |
| `description` | Report description. |
| `author_name` | Pulse author identity when different from provider. |
| `public` | Present in model, not promoted to graph object. |
| `revision` | Present in model, not promoted to graph object. |
| `adversary` | Intrusion Set. |
| `malware_families` | Malware objects. |
| `industries` | Sector identities. |
| `attack_ids` | ATT&CK Attack Pattern objects. |
| `tlp` | TLP marking definition. |
| `tags` | Report/indicator labels and optional malware/CVE guessing. |
| `created` | Report published/created timestamp. |
| `modified` | Report modified timestamp and state progression. |
| `references` | Report external references. |
| `targeted_countries` | Country locations. |
| `indicators` | Observables, indicators, vulnerabilities or YARA indicators. |

## Official Report Mapping

Each pulse becomes one OpenCTI report.

| OTX evidence | Official STIX/OpenCTI target |
| --- | --- |
| Pulse `name` | `report.name` |
| Pulse `description` | `report.description` |
| Pulse `created` | `report.published` and `report.created` |
| Pulse `modified` | `report.modified` |
| Configured report type | `report.report_types` |
| Configured report status | `x_opencti_report_status` |
| Pulse tags | `labels` |
| Pulse TLP | `object_marking_refs` |
| Pulse URL | External reference with pulse id |
| Pulse references | Additional external references |
| Converted objects and relationships | `report.object_refs` |

If a pulse has no converted objects, the official connector inserts a dummy
organization named `AV EMPTY REPORT` because STIX reports require at least one
object reference.

## Official Entity Mapping

| OTX evidence | Official STIX/OpenCTI target | Notes |
| --- | --- | --- |
| Provider | `identity` organization named `AlienVault` | Base author/provider. |
| Pulse `author_name` | `identity` organization | Used when different from provider. |
| Pulse `adversary` | `intrusion-set` | Strong graph promotion from a free OTX field. |
| Pulse `malware_families` | `malware` | Official connector does not mark these as `is_family=true` by default. |
| Guessed malware from tags | `malware` | Optional OpenCTI lookup by tag name or alias. |
| Pulse `attack_ids` | `attack-pattern` | Adds `x_mitre_id` and ATT&CK external reference. |
| Pulse `industries` | `identity` with class semantics | Sector/victimology context. |
| Pulse `targeted_countries` | `location` with Country type | Official code uses `country=ZZ` as a placeholder. |
| CVE pulse indicators | `vulnerability` | Adds NVD external reference. |
| Guessed CVEs from tags | `vulnerability` | Optional regex-based tag extraction. |

NarrowCTI should preserve the object intent but improve the weak areas:

- Resolve ATT&CK ids through the local MITRE cache so OpenCTI gets technique
  names, tactics, platforms, data sources, detection guidance and lifecycle
  state.
- Normalize countries to real ISO codes instead of repeating the official
  `ZZ` placeholder behavior.
- Treat `adversary`, `malware_families` and free tags as evidence with
  confidence, not automatic attribution.
- Mark malware families correctly and apply alias normalization.
- Keep tag-based guessing disabled or dry-run by default until it has audit
  evidence and confidence controls.

## Official Indicator And Observable Mapping

The official connector can create both observables and indicators from OTX
pulse indicators.

| OTX indicator type | Official observable/indicator target |
| --- | --- |
| `IPv4` | IPv4 address observable and STIX indicator pattern. |
| `IPv6` | IPv6 address observable and STIX indicator pattern. |
| `domain` | Domain observable and STIX indicator pattern. |
| `hostname` | Hostname observable and STIX indicator pattern. |
| `email` | Email address observable and STIX indicator pattern. |
| `URL`, `URI` | URL observable and STIX indicator pattern. |
| `FileHash-MD5` | File observable with MD5 hash and STIX indicator pattern. |
| `FileHash-SHA1` | File observable with SHA-1 hash and STIX indicator pattern. |
| `FileHash-SHA256` | File observable with SHA-256 hash and STIX indicator pattern. |
| `CIDR` | IPv4 address observable path in official mapping. |
| `FilePath` | File observable by name and STIX indicator pattern. |
| `Mutex` | Mutex observable and STIX indicator pattern. |
| `BitcoinAddress` | Cryptocurrency wallet observable and STIX indicator pattern. |
| `YARA` | YARA indicator with raw rule content as pattern. |
| `CVE` | Vulnerability object instead of indicator/observable. |

The official connector comments out or ignores several OTX indicator types such
as `FileHash-PEHASH`, `FileHash-IMPHASH`, `JA3`, `osquery` and
`SSLCertFingerprint`. NarrowCTI should decide whether those remain unsupported,
become quarantine evidence, or map to richer custom observables later.

Official indicators include:

- Deterministic OpenCTI indicator id from the pattern.
- `pattern_type=stix` for observable-backed indicators.
- `pattern_type=yara` for YARA rules.
- `valid_from` from the OTX indicator creation timestamp.
- Labels from OTX tags.
- Confidence from connector confidence level.
- `x_opencti_score` using either default or per-type configured score.
- `x_opencti_main_observable_type` for observable-backed indicators.

## Official Relationship Model

The official connector creates these relationship patterns when relationships
are enabled:

| Source | Relationship | Target |
| --- | --- | --- |
| Intrusion Set | `uses` | Malware |
| Intrusion Set | `uses` | Attack Pattern |
| Malware | `uses` | Attack Pattern |
| Intrusion Set | `targets` | Sector |
| Malware | `targets` | Sector |
| Intrusion Set | `targets` | Country |
| Malware | `targets` | Country |
| Intrusion Set | `targets` | Vulnerability |
| Malware | `targets` | Vulnerability |
| Attack Pattern | `targets` | Vulnerability |
| Indicator | `based-on` | Observable |
| Indicator | `indicates` | Intrusion Set |
| Indicator | `indicates` | Malware |
| Indicator | `indicates` | Attack Pattern, when enabled |

This relationship model is important for NarrowCTI because it already matches
the product ambition: OpenCTI should show actor, arsenal, ATT&CK, victimology,
vulnerability and observation pivots from a curated OTX pulse.

## Comparison With Current NarrowCTI

| Capability | Official AlienVault connector | Current NarrowCTI v0.7 state | v0.7 target |
| --- | --- | --- | --- |
| Runtime retrieval | Subscribed pulses through `getsince`. | Custom OTX search/enrichment flow. | Keep NarrowCTI runtime; use official mapping as export baseline. |
| Report metadata | Rich pulse report with status, labels, markings and refs. | Stable generic report export; pulse lifecycle, votes and indicator observation windows are preserved in audit metadata. | Add OTX-compatible report fields after curation. |
| Author/provider identity | AlienVault plus pulse author. | OTX author/source identity is captured as audit-only graph evidence. | Preserve provider and source author as graph/provenance evidence. |
| OTX entity extraction | Promotes adversary, malware, ATT&CK, sectors, countries and CVEs. | Extracts these into audit-only `graph_evidence` and graph candidates when source evidence exists. | Promote only after confidence and policy validation. |
| Observables | Emits supported SCO/custom observables. | Not emitted by current exporter. | Add observable output in graph-aware STIX builder. |
| Indicators | Emits supported STIX/YARA indicators with score metadata. | Emits selected STIX indicators; YARA indicators are parsed into audit-only `detection_rule` candidates. | Preserve official-compatible indicator semantics plus NarrowCTI scoring evidence. |
| Vulnerabilities | Creates CVE vulnerabilities from indicators and optional tag guessing. | CVE values from OTX fields, indicators, tags and references become audit-only vulnerability candidates. | Add NVD references, enrichment and relationship policy controls before export. |
| Relationships | Emits `uses`, `targets`, `based-on` and `indicates`. | Relationships are audit evidence only. | Add relationship policy with confidence/provenance. |
| Country handling | Country locations use placeholder `ZZ`. | Extracts target countries as evidence. | Normalize countries properly before export. |
| MITRE enrichment | Uses ATT&CK id as object name and `x_mitre_id`. | Resolves technique metadata through local MITRE cache. | Use NarrowCTI's richer MITRE resolver. |
| Guardrails | Excluded indicator types and optional created-time filtering. | Score policy, TLP, dedup, quarantine and source guardrails. | Keep NarrowCTI guardrails before official-compatible export. |

## NarrowCTI Decision

NarrowCTI should use the official AlienVault connector as the OTX-specific
mapping baseline, but should not copy its runtime or promote every field
blindly.

The target flow is:

```text
OTX pulse
  -> NarrowCTI query/enrichment runtime
  -> source guardrails and indicator hygiene
  -> entity, ATT&CK, vulnerability and victimology extraction
  -> scoring, TLP, policy, deduplication and quarantine
  -> graph candidates with confidence and provenance
  -> official-compatible STIX/OpenCTI objects and relationships
  -> OpenCTI import
```

The resulting OpenCTI import should look familiar to users of the official OTX
connector, but with better graph hygiene, richer MITRE context, country
normalization, explainable curation and safer release controls.

## Required v0.7 Work

The following v0.7 items should be tracked before calling OTX graph enrichment
complete:

1. Add OTX fixture coverage with adversary, malware family, ATT&CK ids,
   industries, countries, references, TLP, CVE, YARA and standard indicators.
   Initial YARA audit extraction is implemented.
2. Extend the graph candidate model to represent OTX Intrusion Set, Malware,
   Attack Pattern, Sector, Location, Vulnerability, Observable and Indicator
   candidates.
3. Add country normalization and confidence controls before exporting OTX
   target-country locations.
4. Use local MITRE cache data to enrich official-compatible ATT&CK objects
   beyond the raw technique id.
5. Add vulnerability mapping for OTX CVE indicators and optional tag-derived
   CVEs, with tag guessing disabled or audited by default. Initial audit-only
   CVE extraction is implemented; NVD references, enrichment and relationship
   export remain pending.
6. Add official-compatible relationship policy for `uses`, `targets`,
   `based-on` and `indicates`.
7. Add graph-aware STIX export dry-run output that shows what would be created,
   skipped, deduplicated, quarantined or released.
8. Compare a representative official OTX connector bundle shape with a
   NarrowCTI-curated bundle for the same pulse metadata.

## Validation Strategy

The safest validation path for OTX v0.7 is:

```text
same OTX pulse fixture
  -> official connector mapping review
  -> NarrowCTI dry-run graph export
  -> compare STIX object classes and relationship types
  -> import NarrowCTI curated bundle
  -> validate OpenCTI graph tabs and duplicate posture
```

NarrowCTI does not need to match every official connector implementation detail.
It should match the graph intent where the evidence passes curation:

- Analyses should contain the OTX pulse report and external references.
- Observations should contain supported indicators and observables.
- Threats should contain intrusion set context when adversary evidence is
  strong enough.
- Arsenal should contain malware family context when source evidence supports
  it.
- Techniques should contain ATT&CK attack patterns enriched by the MITRE cache.
- Entities and Locations should contain sector and country victimology when
  normalized and allowed by policy.
- Vulnerabilities should contain CVE context when present.
- Relationships should be evidence-backed and explainable through the source
  field that produced them.

This gives NarrowCTI an OTX-specific path to the same professional CTI gateway
goal: curate before ingest, then populate OpenCTI with high-value graph context
instead of raw feed noise.
