---
name: Bug report
about: Report a reproducible NarrowCTI bug
title: "[bug] "
labels: bug, needs-triage
assignees: ""
---

## Summary

Describe the bug and the expected behavior.

## Version

- NarrowCTI version:
- Commit or tag:
- Deployment mode: Docker / local / other
- OpenCTI version:
- Source involved: OTX / MISP / other

## Reproduction

Steps to reproduce:

1.
2.
3.

## Evidence

Paste sanitized logs or decision audit snippets.

Do not include API keys, `.env` files, raw customer data, private feed payloads
or local `state/` artifacts.

## Impact

- Does this affect ingestion?
- Does this affect OpenCTI graph hygiene?
- Does this create duplicates?
- Does this drop intelligence that should pass policy?

## Validation Attempted

Commands or checks already run:

```text
python -m unittest discover -s tests -v
```

