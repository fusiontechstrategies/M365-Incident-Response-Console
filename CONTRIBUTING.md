# Contributing

Contributions that improve safety, accuracy, service compatibility, evidence quality, or operator clarity are welcome.

## Project constraints

- The executable application remains one file: `M365-IR-Console.ps1`.
- Tenant-changing commands must execute only inside a function guarded by `Invoke-IRChange`.
- Every production `Invoke-IRChange` call requires a non-empty `-ExactConfirmation` value.
- Audit mode must never execute a tenant mutation or request an unreviewed Microsoft Graph write scope.
- New collection workflows must report retention limits, pagination ceilings, partial results, and licensing dependencies.
- Do not add hard-coded credentials, tenant identifiers, customer names, private endpoints, or real incident data.
- Use official Microsoft modules and documented service interfaces.

## Local validation

Use PowerShell 7.6 or later.

```powershell
pwsh -File .\M365-IR-Console.ps1 -OfflineSelfTest

Import-Module Pester -MinimumVersion 6.1.0
$result = Invoke-Pester -Path .\tests -Output Detailed -PassThru
if ($result.FailedCount -gt 0) { throw 'Pester tests failed.' }

Import-Module PSScriptAnalyzer -MinimumVersion 1.25.0
$findings = @(Invoke-ScriptAnalyzer -Path .\M365-IR-Console.ps1 -Severity Warning, Error)
if ($findings.Count -gt 0) { $findings | Format-Table; throw 'Static analysis failed.' }
```

Run `git diff --check` and scan the complete tree for secrets before committing.

## Pull requests

A focused pull request should explain:

- The operational problem
- The safety impact
- The Microsoft service or permission involved
- How Audit and Live modes behave
- The tests added or changed
- Any licensing, retention, paging, or role limitations

Use synthetic test data only. Do not authenticate automated tests to a live tenant.
