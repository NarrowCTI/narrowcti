# Third-Party Notices

NarrowCTI depends on third-party open source packages. Each dependency remains
governed by its own license terms.

## Runtime Dependencies

The custom OTX connector currently pins these Python packages:

```text
pycti==6.4.8
stix2==3.0.1
requests==2.32.3
python-dateutil==2.9.0.post0
urllib3==2.2.3
```

The package list is maintained in:

```text
connectors/otx/requirements.txt
```

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
