## Summary

Describe the operational problem and the proposed change.

## Safety impact

- [ ] Audit mode still blocks every tenant mutation.
- [ ] New or changed Graph scopes are documented and tested.
- [ ] Tenant mutations use `Invoke-IRChange` with exact confirmation.
- [ ] No live tenant data, credentials, customer names, or private identifiers are included.

## Validation

- [ ] Built-in offline self-test passes.
- [ ] Pester suite passes.
- [ ] PSScriptAnalyzer reports no warnings or errors.
- [ ] Service limits, licensing needs, and partial-result behavior are documented.

