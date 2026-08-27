# Future PowerShell Gallery publication plan

M365 Incident Response Console is not published to the PowerShell Gallery, and the current v5.1.0 executable does not contain `PSScriptInfo` package metadata. The supported public installation remains the versioned GitHub release asset linked from the main README.

Package metadata must not be added to a script while it still identifies itself as v5.1.0: that would create different executable bytes under an already-published version. Gallery preparation therefore belongs in a future versioned release, not in this documentation-only adoption update.

## Proposed future metadata

The future release candidate should add a standard `PSScriptInfo` block containing:

- A new version greater than `5.1.0`, synchronized with the in-script version, changelog, release tag, and `CITATION.cff`
- A stable package GUID plus author, company, license, project, tags, and release-notes metadata
- The existing PowerShell 7.6 runtime requirement
- External module information that preserves the console's distinction between required, optional, and platform-dependent capabilities

Do not convert every cloud module into an unconditional `#Requires -Module` declaration. The offline safety checks do not need those modules, several service workflows are optional, and the console currently installs modules only when the operator explicitly supplies `-InstallMissingModules`.

The same future change should add regression tests that run `Test-PSScriptFileInfo`, compare the package and application versions, and compare declared external module names with the in-script module catalog.

## Gates before the first publication

Publishing is a separate, irreversible release action. Complete all of these gates against one exact future release commit before using a public Gallery publishing command:

1. Select the new release version and update package metadata, application version, changelog, citation metadata, and release notes together.
2. Run the complete Windows and Ubuntu offline suites, Pester, PSScriptAnalyzer, dependency smoke tests, dependency review, and secret scanning.
3. Repeat the approved test-tenant workflow for the service operations included in that release.
4. Build and inspect the package in an isolated non-public process. Confirm that no packaging command can fall through to the public Gallery without an explicit destination and credential.
5. Build the GitHub asset and Gallery candidate from the exact validated source; do not hand-edit either candidate after testing.
6. Authenticode-sign and timestamp the final script if publisher signing is part of the release policy, then verify the signature on a clean workstation.
7. Confirm package name ownership, tags, license, project link, dependencies, and release notes before enabling public credentials.
8. Obtain explicit publication approval and use a narrowly scoped Gallery API key through the approved secret-handling process.
9. Install the published version on a clean PowerShell 7.6 workstation, verify its hash, signature status, and metadata, and rerun `-OfflineSelfTest` before announcing it.

The current v5.1.0 GitHub release asset is not Authenticode-signed. Do not represent any future Gallery package as publisher-signed unless its final downloadable bytes pass `Get-AuthenticodeSignature` with the expected certificate and timestamp.
