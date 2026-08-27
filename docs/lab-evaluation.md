# Safe lab evaluation

Use this sequence to evaluate M365 Incident Response Console without introducing an unreviewed production change. The console is a response aid, not a substitute for tenant-specific incident procedures, access reviews, or change approval.

## 1. Prepare an isolated evaluation

- Use an approved Microsoft 365 test tenant or a dedicated lab segment of a non-production tenant.
- Use synthetic users, messages, groups, applications, and files. Never reuse a real incident artifact in an issue, demo, or test fixture.
- Use a dedicated operator account protected by MFA. Do not test with an emergency-access account.
- Assign only the service roles and delegated scopes needed for the workflow being evaluated. Do not grant a broad role simply to make every menu item available.
- Store case output on an access-controlled test workstation. The generated reports can contain message, identity, device, application, and policy evidence.

## 2. Validate locally before authentication

These commands do not authenticate to a tenant or make a tenant change:

```powershell
pwsh -NoProfile -File .\M365-IR-Console.ps1 -OfflineSelfTest
pwsh -NoProfile -File .\M365-IR-Console.ps1 -PreflightOnly
```

`-OfflineSelfTest` runs deterministic safety and evidence-integrity checks. `-PreflightOnly` reports the local PowerShell and module prerequisites. A failed preflight should be resolved before tenant authentication.

`-InstallMissingModules` writes to the current user's PowerShell module path and obtains modules from the PowerShell Gallery. Use it only after your organization approves the listed modules and versions. Installation is not required for the offline self-test.

## 3. Start in Audit mode

Audit mode is the startup default. It permits reads and local evidence export, replaces reviewed Microsoft Graph write scopes with read-only scopes, and blocks tenant-changing scriptblocks.

```powershell
pwsh -NoProfile -File .\M365-IR-Console.ps1 `
    -TenantId 'your-lab-tenant.onmicrosoft.com' `
    -UserPrincipalName 'analyst-test@your-lab-tenant.onmicrosoft.com' `
    -Days 10
```

Before consenting, review the delegated scopes displayed by Microsoft. The console requests scopes as individual workflows need them; it does not require one universal permission bundle. Read access can still expose sensitive tenant data, so Audit mode does not remove the need for least privilege and evidence controls.

Validate only the workflows your responders intend to use. Record unavailable workloads as coverage limitations: licensing, retention, assigned roles, tenant configuration, and service query ceilings all affect results.

## 4. Gate any Live-mode exercise

Live mode can revoke sessions, change sign-in state, modify Conditional Access, remove grants or devices, alter mail controls, and perform other disruptive operations. Before a lab Live-mode test:

1. Create a disposable synthetic target and document its known starting state.
2. Obtain the same change approval your production response process would require.
3. Confirm the operator account has only the role needed for the selected action.
4. Run with `-WhatIf` where the command supports it and review the exact confirmation phrase.
5. Execute one change at a time, verify the resulting tenant state, and test the documented rollback or restoration path.
6. Return the console to Audit mode when the exercise is complete. This disconnects cached service sessions so a write-capable Graph context is not silently reused.

Do not weaken PowerShell execution policy, disable MFA, or grant Global Administrator as a shortcut for lab setup.

## 5. Review and dispose of evidence

- Confirm the case directory is restricted to the expected operating-system identity.
- Review collection-status rows for `Partial`, `Failed`, unavailable, or not-applicable sources.
- Generate the HTML report and SHA-256 evidence manifest, then verify the manifest before moving the case.
- Treat the hash chain and manifest as tamper evidence, not as a replacement for chain-of-custody procedures, trusted timestamps, or digital signatures.
- Delete synthetic tenant objects and test evidence according to the lab's retention policy. Do not attach case output to a public GitHub issue.

See the [sanitized sample report](../examples/sanitized-case-report.md) for an output preview and [SECURITY.md](../SECURITY.md) for private vulnerability reporting.
