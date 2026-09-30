# Third-Party Notices

NarrowCTI depends on third-party open source packages. Each dependency remains
governed by its own license terms.

## Runtime Dependencies

The project currently declares these direct runtime Python dependencies in
`pyproject.toml`:

```text
pycti==7.260910.0
msgpack==1.2.2
fastapi==0.141.1
jinja2==3.1.6
uvicorn==0.52.4
stix2==3.0.2
requests==2.33.0
python-dateutil==2.9.0.post0
urllib3==2.8.0
sigmatools==0.23.1
argon2-cffi==25.1.0
```

The legacy compatibility projection is maintained in:

```text
connectors/otx/requirements.txt
```

`setuptools` in the legacy projection is build tooling, not a direct runtime
dependency. `sigmatools 0.23.1` is used only to mirror the Sigma syntax validation boundary
of supported OpenCTI `6.9.x` environments. It is distributed under LGPL-3.0;
NarrowCTI does not modify or relicense that dependency.

`argon2-cffi 25.1.0` (MIT) is used for local Community operator password
hashing with Argon2id. Its `argon2-cffi-bindings` dependency (MIT) supplies the
maintained native implementation; both upstream license notices remain
applicable.

## External Platforms

NarrowCTI is designed to integrate with OpenCTI and external threat
intelligence feeds. OpenCTI, OTX and any other integrated feed or platform remain
separate products governed by their own licenses, terms and API policies.

## Distribution And Service Check

Before public releases, packaged distributions, managed services or customer
deployments, verify and archive:

- License metadata for every pinned dependency.
- Transitive dependency license metadata.
- Docker base image license and distribution terms.
- OpenCTI client and API usage requirements.
- Feed provider terms for each supported connector.

This file is not a legal opinion. It is a release engineering control to ensure
license and terms review is explicit before packaging or operating NarrowCTI for
others.

## Vendored Browser Assets

The Community Web UI vendors `htmx 2.0.11` under the Zero-Clause BSD (0BSD)
license. The source URL, SRI value, and SHA-256 checksum are recorded alongside
the asset in `src/narrowcti/api/web/static/HTMX-VERSION.txt`; the license text is
in `HTMX-LICENSE.txt`.

This PR intentionally remains on the htmx 2.x compatibility line. A separate
major-version migration is deferred so its breaking behavior changes can be
reviewed and tested independently.
