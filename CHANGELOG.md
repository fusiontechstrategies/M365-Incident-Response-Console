# Changelog

All notable project changes are documented here.

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

