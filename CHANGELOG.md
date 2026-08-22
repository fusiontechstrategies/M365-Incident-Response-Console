# Changelog

All notable project changes are documented here.

## 5.0.1 | 2026-08-22

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
