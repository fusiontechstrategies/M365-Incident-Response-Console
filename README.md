# M365 Incident Response Console

> Turn a compromised Microsoft 365 identity into a controlled, evidence-backed response without assembling a dozen disconnected scripts.

[![CI](https://github.com/fusiontechstrategies/M365-Incident-Response-Console/actions/workflows/ci.yml/badge.svg)](https://github.com/fusiontechstrategies/M365-Incident-Response-Console/actions/workflows/ci.yml)
[![Dependency smoke test](https://github.com/fusiontechstrategies/M365-Incident-Response-Console/actions/workflows/dependency-smoke.yml/badge.svg)](https://github.com/fusiontechstrategies/M365-Incident-Response-Console/actions/workflows/dependency-smoke.yml)
[![PowerShell 7.6+](https://img.shields.io/badge/PowerShell-7.6%2B-5391FE?logo=powershell&logoColor=white)](https://github.com/PowerShell/PowerShell)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

M365 Incident Response Console is a one-file PowerShell application for Microsoft 365 investigation, guarded containment, forensic collection, remediation, and evidence integrity. It brings Microsoft Graph, Exchange Online, Purview, Teams, SharePoint, and local case handling into one interactive workflow.

The application starts in **Audit mode**. Audit mode blocks every tenant mutation and replaces reviewed Microsoft Graph write scopes with read-only scopes. **Live mode** must be selected explicitly, and every tenant-changing operation passes through a common gateway with `ShouldProcess`, an exact typed confirmation, and durable case logging.

## Why this is different

- **One executable file:** Copy `M365-IR-Console.ps1` to an approved administrative workstation and run it from PowerShell 7.6 or later.
- **Evidence before action:** Every case receives a chained JSONL action log, SHA-256 evidence manifests, portable exports, and a human-readable case report.
- **Safe by default:** Audit mode cannot execute tenant-changing scriptblocks and will not request a Microsoft Graph write scope.
- **Explicit containment:** Live changes require a case, durable approval logging, `ShouldProcess`, and an operation-specific confirmation phrase.
- **Honest collection:** Query ceilings, repeated pages, partial delivery, retention boundaries, and unavailable licensed features are reported instead of being presented as complete results.
- **Current dependencies:** Module baselines are validated weekly against the PowerShell Gallery and imported in an isolated smoke-test workflow.

## Capability map

| Area | Included workflows |
| --- | --- |
| Identity containment | Revoke sessions, reset a password, block or restore sign-in, review Conditional Access, create and remove console-managed targeted MFA policies |
| Mail investigation | Message Trace V2 with documented cursor handling, sender and recipient analysis, phishing spread review, per-recipient warning delivery status |
| Mailbox persistence | Mailbox snapshot, inbox rules, forwarding, delegation, folder permissions, transport rules, mailbox applications, mobile-device partnerships |
| Audit and risk | Unified Audit Log collection, normalized event timelines, conservative findings, sign-in logs, risky-user status, authentication methods |
| Application access | Delegated OAuth grants, app-role assignments, service-principal enrichment, guarded grant removal |
| Collaboration | Teams membership and channel inventory, SharePoint site access review, selected file-access context |
| Threat analysis | Defender for Office 365 mail detections, message heuristics, protected-domain similarity checks, threat-hunting query files |
| Purview | Create, start, inspect, and remove content-search definitions with explicit live-mode controls |
| Security policy | Policy snapshots and backups, blocked senders, anti-phish settings, outbound-spam review, quarantine rules, Conditional Access reporting and baselines |
| Evidence | Private case directories, chained action log, HTML report, normalized CSV and JSON exports, analyst import package, SHA-256 manifest, protected ZIP archive |

## Safety model

| Control | Audit mode | Live mode |
| --- | --- | --- |
| Default startup state | Yes | No |
| Microsoft Graph write scopes | Replaced with reviewed read-only scopes | Requested only by the selected operation |
| Tenant-changing operation | Blocked before the operation scriptblock executes | Allowed only through `Invoke-IRChange` |
| `-WhatIf` support | Available | Available |
| Exact typed confirmation | Not applicable because no change executes | Required for every production mutation |
| Durable approval record | Planned action recorded when a case exists | Required before execution |
| Completion or failure record | Not applicable | Added to the chained action log |

Returning from Live mode to Audit mode disconnects cached service sessions so a write-capable Graph context is not silently reused.

## Requirements

- PowerShell Core 7.6 or later
- A Microsoft 365 account authorized for the investigation or response action
- Administrator consent for requested Microsoft Graph delegated scopes where required
- Appropriate Microsoft Entra, Exchange Online, Purview, Teams, SharePoint, Intune, and Defender roles and licenses for the selected features
- Network access to Microsoft 365 authentication and service endpoints

The console does not contain real credentials, tenant identifiers, customer names, or API keys. Authentication is handled by the official Microsoft modules.

### Current module baselines

These versions were verified against the PowerShell Gallery on August 20, 2026.

| Module family | Minimum version | Use |
| --- | ---: | --- |
| `ExchangeOnlineManagement` | `3.10.1` | Exchange Online and Microsoft Purview |
| Microsoft Graph submodules | `2.39.0` | Authentication, users, identity, applications, reports, groups, and devices |
| `MicrosoftTeams` | `7.9.0` | Optional Teams collection |
| `Microsoft.Online.SharePoint.PowerShell` | `16.0.27515.12000` | Optional SharePoint collection |

Use `-InstallMissingModules` only after reviewing your organization's module-management policy. Installation is limited to the current user and the PowerShell Gallery.

## Quick start

1. Download [M365-IR-Console.ps1](M365-IR-Console.ps1).
2. Verify the file and review the source before execution.
3. Open PowerShell 7.6 or later.
4. Run the console in its default Audit mode.

```powershell
Get-FileHash .\M365-IR-Console.ps1 -Algorithm SHA256
pwsh -File .\M365-IR-Console.ps1
```

Start with a target and a 30-day investigation window:

```powershell
pwsh -File .\M365-IR-Console.ps1 `
    -UserPrincipalName user@contoso.com `
    -Days 30
```

Install missing current-user modules during preflight:

```powershell
pwsh -File .\M365-IR-Console.ps1 -InstallMissingModules
```

Run only the local safety and regression checks:

```powershell
pwsh -File .\M365-IR-Console.ps1 -OfflineSelfTest
```

Run the non-authenticated prerequisite report:

```powershell
pwsh -File .\M365-IR-Console.ps1 -PreflightOnly
```

## Case output

The default case root is outside the repository:

- Windows: `%LOCALAPPDATA%\M365-IR-Console\Cases`
- Linux and macOS: `$XDG_STATE_HOME/m365-ir-console/cases`, or `~/.local/state/m365-ir-console/cases`

New case directories are restricted to the current operating-system identity when the platform supports it. Use `-PreserveInheritedCasePermissions` only after reviewing the destination permissions.

A case can contain:

- `case_metadata.json`
- `action_log.jsonl` with sequence numbers and SHA-256 hash chaining
- Raw and normalized CSV, JSON, and CLIXML exports
- An HTML case report
- Threat-hunting query files
- A portable analyst import package
- `evidence_manifest.sha256.json` and `evidence_manifest.sha256.csv`
- A protected ZIP archive and returned SHA-256 digest

The hash chain and manifest provide tamper evidence. They do not replace organizational evidence-handling procedures, trusted timestamps, digital signatures, or chain-of-custody requirements.

## Microsoft Graph scopes

The console requests delegated scopes as individual workflows need them. Common read scopes include:

- `User.Read.All`
- `Policy.Read.All`
- `AuditLog.Read.All`
- `IdentityRiskyUser.Read.All`
- `UserAuthenticationMethod.Read.All`
- `Application.Read.All`
- `DelegatedPermissionGrant.Read.All`
- `AppRoleAssignment.Read.All`
- `DeviceManagementManagedDevices.Read.All`
- `GroupMember.Read.All`
- `RoleManagement.Read.Directory`

Live response operations can request write scopes such as `User.RevokeSessions.All`, `User-PasswordProfile.ReadWrite.All`, `User.ReadWrite.All`, `Policy.ReadWrite.ConditionalAccess`, `Mail.Send`, `DelegatedPermissionGrant.ReadWrite.All`, `AppRoleAssignment.ReadWrite.All`, and `DeviceManagementManagedDevices.ReadWrite.All`.

Audit mode replaces each reviewed write scope with a read-only alternative. An unreviewed write scope causes a closed failure instead of being requested.

## Operational boundaries

- Message Trace V2 retains up to 90 days, accepts no more than 10 days per query, returns at most 5,000 rows per request, and is subject to service throttling. The console divides the period into service-compliant windows and records incomplete results.
- Defender mail-detail collection is limited to the service's supported period and record ceiling.
- Unified Audit Log retention, result availability, and record fields depend on licensing, configuration, workload, and assigned roles.
- Console-managed MFA policy expiration is recorded as metadata. Review and remove expired policies through the console instead of assuming automatic deletion.
- Heuristic findings are analyst leads, not determinations of compromise.
- Live actions can disrupt accounts, mail flow, applications, devices, or access. Use an approved change and incident process.

## Validation

Release validation includes:

- 22 deterministic built-in offline self-tests
- 46 Pester 6.1.0 regression tests
- PowerShell parser validation
- PSScriptAnalyzer 1.25.0 with zero warning or error findings
- Mutation-gateway and exact-confirmation AST checks
- Windows ACL and Unix permission tests
- Microsoft Graph scope downgrade tests
- HTTP throttling and retry tests
- Message-trace and Unified Audit Log paging tests
- Action-log and evidence-manifest tamper tests
- Import tests for all 13 current Microsoft module baselines
- Gitleaks scans of the release tree and Git history
- GitHub Actions testing on current Windows and Ubuntu runners
- A weekly current-dependency import and command-contract smoke test

All automated tests are non-destructive and do not authenticate to a tenant.

## Federal cybersecurity discussion

For practitioner discussion about federal cloud, control effectiveness, evidence, incident response, and mission resilience, visit [r/FederalCyber](https://www.reddit.com/r/FederalCyber/).

It is an independent, unofficial community for public-source discussion. Never post CUI, credentials, customer details, active incident data, or nonpublic vulnerabilities.

## Contributing and security

Read [CONTRIBUTING.md](CONTRIBUTING.md) before proposing changes. The application must remain a one-file executable script, although tests, workflows, and documentation remain separate.

Do not open a public issue for a vulnerability or suspected secret exposure. Follow [SECURITY.md](SECURITY.md) and use GitHub private vulnerability reporting.

## License

Released under the [MIT License](LICENSE).
