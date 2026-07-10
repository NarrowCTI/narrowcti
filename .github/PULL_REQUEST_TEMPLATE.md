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

## Safety Checklist

- [ ] No secrets, `.env` files, local state or feed dumps are included.
- [ ] Tests were added or updated when behavior changed.
- [ ] Documentation was updated when operator behavior changed.
- [ ] OpenCTI graph hygiene was considered.
- [ ] Release archive impact was considered for public-facing docs.
