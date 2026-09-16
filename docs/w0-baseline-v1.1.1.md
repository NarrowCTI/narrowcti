# W0 baseline characterization — v1.1.1

## Authority and source of truth

This baseline is generated from the Git object database, not from the working
tree. The authoritative release reference is:

| Field | Value |
| --- | --- |
| Git tag | `v1.1.1` |
| Commit | `4e3509b8f18c330361994975ab3c5b11e8f5b05f` |
| Tree | `f5570e9d92643060d79ef59eef0d4a8f266b9476` |
| Tracked entries | `205` |
| Content bytes | `3,684,785` |
| Git object types | `205 blob` |

The machine-readable inventory is [`w0-baseline-v1.1.1.json`](w0-baseline-v1.1.1.json).
It includes the Git object id, mode, path, byte size and SHA-256 for every
blob. `state/.gitkeep` is present because it is tracked by the release tree;
local state, secrets, DOCX files and agent instructions are absent because
they are not part of that tree.

Regenerate it with:

```text
python scripts/generate_w0_baseline_inventory.py --ref v1.1.1 \
  --output docs/w0-baseline-v1.1.1.json
```

The script resolves `v1.1.1^{commit}` and `v1.1.1^{tree}`, enumerates
`git ls-tree -r -z`, and reads blob contents with `git cat-file`. It does not
walk the filesystem, so files added after the release cannot change the 205
entry result.

## Source-tree characterization

The release tree contains 101 Python files: 60 production modules and 41 test
modules. The top-level distribution is:

| Area | Entries |
| --- | ---: |
| `docs/` | 64 |
| `tests/` | 41 |
| `core/` | 22 |
| `gateway/` | 21 |
| `connectors/` | 19 |
| `.github/` | 12 |
| `scripts/` | 4 |
| `deployment/` | 3 |
| `exporters/` | 2 |
| Other tracked root/config/state entries | 17 |

The largest production seams are `connectors/misp/processor.py`,
`core/graph_evidence.py`, `exporters/stix_builder.py`,
`gateway/curation_report.py`, `core/opencti_graph_lookup.py` and
`gateway/decisions.py`. They are characterization targets, not W0 refactor
targets.

## Existing test and coverage evidence

The existing suite remains the first characterization layer. The unchanged
release tree passes **544 tests**; the W0 branch adds five targeted
characterization tests, for **549 tests** in total. Ruff and Bandit also pass.
With `coverage==7.16.1` added only to `requirements-dev.txt`, the initial
measurement is **90% aggregate coverage** using line and branch measurement.
This percentage is an observation and is not a merge gate in W0. The coverage
tool is not installed in runtime requirements, the Docker image, or the OTX
connector requirements.

The test-to-invariant gap analysis is recorded in
[`w0-test-inventory-v1.1.1.md`](w0-test-inventory-v1.1.1.md). New tests are
limited to immutable output/golden contracts and to invariants not already
directly protected by the 544-test suite.

## Execution-environment boundary

The local validation environment currently uses Python 3.14.6 and the
repository virtual environment. CI is configured for Python 3.11. This
difference is documented evidence, not a W0 remediation target. Python parity,
dependency upgrades, TLS, packaging, Docker runtime and configuration
reconciliation remain outside this PR.

## Release evidence boundary

Official v1.1.1 CI, security, DAST and container evidence remains in
[`release-v1.1.1.md`](release-v1.1.1.md). The local test and coverage results
above are separate execution evidence and must not be presented as a
replacement for the official release validation record.

## W0 non-goals

- no `src/` migration or compatibility shim;
- no runtime dependency or Docker change;
- no TLS or configuration behavior correction;
- no graph backfill, relationship promotion or W1 implementation;
- no claim that the measured coverage percentage is a quality gate.
