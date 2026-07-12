## Summary

Describe the change and why it is needed.

## Type

- [ ] Bug fix
- [ ] Feature
- [ ] Documentation
- [ ] Deployment
- [ ] Refactor
- [ ] Test only

## CTI / OpenCTI Impact

- Source adapters affected:
- OpenCTI graph objects affected:
- Deduplication or graph hygiene impact:
- Quarantine/review impact:

## Validation

Commands run:

```text
python -m unittest discover -s tests -v
```

- Additional checks or real-feed validation:
- Expected CI workflows to pass:
  - [ ] CI
  - [ ] Security and Quality
  - [ ] Container Image, when the image or runtime changes
  - [ ] DAST, when the HTTP surface changes

## Review And Release Impact

- [ ] This PR is ready for maintainer review; it is not a direct release.
- [ ] Breaking changes, migrations or rollback behavior are documented.
- [ ] Public docs and release-archive classification were reviewed.
- [ ] No private strategy, competitive research, customer data or lab evidence
      was added to the public product path.

## Safety Checklist

- [ ] No secrets, `.env` files, local state or feed dumps are included.
- [ ] Tests were added or updated when behavior changed.
- [ ] Documentation was updated when operator behavior changed.
- [ ] OpenCTI graph hygiene was considered.
- [ ] Release archive impact was considered for public-facing docs.
