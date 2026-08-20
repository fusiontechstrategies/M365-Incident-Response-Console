# Security Policy

## Supported version

Security fixes are applied to the latest release and the `main` branch.

## Report a vulnerability

Do not disclose a vulnerability, suspected credential, tenant identifier, or incident artifact in a public issue.

Use [GitHub private vulnerability reporting](https://github.com/fusiontechstrategies/M365-Incident-Response-Console/security/advisories/new) and include:

- The affected version or commit
- The relevant function or workflow
- Reproduction steps that do not expose live tenant data
- The expected and observed safety behavior
- The likely impact
- A suggested correction, if available

You should receive an initial acknowledgment within seven days. Disclosure timing will be coordinated after validation and remediation planning.

## Incident data

Never attach real case output, authentication material, access tokens, message content, user identifiers, tenant identifiers, or customer information to an issue or pull request. Replace them with synthetic examples.

## Scope

Security reports can include:

- A path that bypasses Audit mode or the mutation gateway
- Incorrect Microsoft Graph scope handling
- Unsafe confirmation or `ShouldProcess` behavior
- Credential or secret exposure
- Case-directory permission weaknesses
- Path traversal or unsafe archive behavior
- Evidence-log or manifest integrity failures
- Injection into generated HTML, CSV, JSON, or command parameters
- Dependency or workflow supply-chain risks

