# Changelog

All notable project changes are documented here.

## 5.1.1 | Unreleased

### Added

- Added a versioned, digest-verified release download path and a copy/paste
  offline-first quick start
- Added a safe lab evaluation guide plus synthetic Markdown and JSON case-report
  previews
- Added a future PowerShell Gallery publication plan without changing the
  supported v5.1.0 executable or publishing a package
- Added PowerShell Gallery script metadata with a stable package GUID,
  project, license, author, company, tags, release notes, and informational
  external module inventory
- Added deterministic five-entry Gallery package construction, repeat-build
  comparison, discovery, extraction, and exact installed-script verification
  without public credentials

### Changed

- Documented the current platform-validation boundaries, tenant permission
  model, and the unsigned status of the v5.1.0 release asset
- Moved citation metadata to the 5.1.1 candidate while preserving v5.1.0 as
  the current public release
- Synchronized package, application, changelog, and citation identity at 5.1.1
- Preserved optional, platform-dependent, and operator-approved dependency
  installation rather than turning cloud modules into unconditional package
  dependencies
- Updated the verified optional SharePoint Online module baseline to
  `16.0.27612.12000` after publisher, signature, payload, import, command-source,
  and secret-scan review

### Security

- Required explicit local repository identity for packaging validation so a
  test cannot fall through to the public PowerShell Gallery
- Kept the first public Gallery publication, API key use, tagging, signing,
  and release publication behind separate maintainer authorization

## 5.1.0 | 2026-08-22

### Fixed

- Canonicalized Exchange folder identities for folder-permission collection and
  classified known non-queryable system folders separately from collection
  failures
- Made Microsoft Graph additional-property lookup compatible with generic and
  read-only dictionaries
- Replaced recursive Graph SDK user serialization with a bounded evidence
  projection
- Hardened Windows evidence ACL application without requiring owner-assignment
  privileges
- Prevented repeated Audit-mode Graph reconnects when the identity platform
  returns broader scopes that were previously consented
- Added device-code authentication support for Graph, Exchange Online, and Teams
  where the installed module supports it

### Changed

- Ordered built-in Exchange authentication and Exchange-backed collection before
  Graph to avoid the verified module baselines' Graph-first MSAL assembly
  collision
- Reported unavailable licensed services and non-applicable workloads as
  environmental coverage conditions rather than product failures
- Expanded the regression suite from 46 to 52 Pester tests, including detailed
  investigator-report coverage

### Validation

- Live-retested Graph authentication-method collection with five returned records
- Live-retested Exchange folder-permission traversal with zero queryable-folder
  errors and nine internal system folders explicitly classified as not queryable
- Revalidated offline self-tests, Pester, parser checks, and static analysis

## 5.0.0 | 2026-08-20

Initial public release.

### Added

- One-file interactive Microsoft 365 incident response console
- Audit and Live execution modes
- Read-only Microsoft Graph scope replacement in Audit mode
- Common mutation gateway with `ShouldProcess` and exact confirmation
- Durable chained JSONL action logging
- Restricted case-directory and evidence-file permissions
- SHA-256 evidence manifests and verification
- Message Trace V2 cursor handling and retention windows
- Unified Audit Log paging and incomplete-result markers
- Identity, mailbox, application, device, Teams, SharePoint, Purview, Defender, and policy workflows
- HTML case report and portable analyst import exports
- Built-in self-tests, Pester regression tests, static analysis, CI, and weekly dependency validation

### Security

- Removed reliance on retired purge commands
- Blocked unreviewed Graph write scopes in Audit mode
- Added durable approval records before tenant mutations
- Added tamper detection for action logs and evidence files
- Added HTTP status-aware throttling and bounded retries
