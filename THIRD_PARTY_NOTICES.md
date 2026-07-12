# Third-Party Notices

NarrowCTI depends on third-party open source packages. Each dependency remains
governed by its own license terms.

## Runtime Dependencies

The gateway image currently pins these direct Python packages:

```text
pycti==7.260710.0
fastapi==0.139.0
uvicorn==0.51.0
stix2==3.0.1
requests==2.33.0
python-dateutil==2.9.0.post0
urllib3==2.7.0
sigmatools==0.23.1
```

The package list is maintained in:

```text
connectors/otx/requirements.txt
```

`sigmatools 0.23.1` is used only to mirror the Sigma syntax validation boundary
of supported OpenCTI `6.9.x` environments. It is distributed under LGPL-3.0;
NarrowCTI does not modify or relicense that dependency.

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
