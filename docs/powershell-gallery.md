# PowerShell Gallery release readiness

Version 5.2.0 is being prepared for its first PowerShell Gallery release. The current public GitHub release is 5.1.1.

`M365-IR-Console` uses the Gallery's single-script package format.

Do not use a public Gallery publishing command until the maintainer explicitly authorizes the exact candidate, signing policy, Gallery account, API key use, tag, and publication.

## Decision

Proceed with `M365-IR-Console` as a script package, not a module wrapper.

This preserves the existing one-file operator experience and supports both current `Install-PSResource` clients and legacy `Install-Script` clients. The exact package name returned no public Gallery entries during the 2026-08-28 readiness check. That observation is not a reservation. Recheck it immediately before the first publication.

## Candidate metadata

The release executable contains a standard `PSScriptInfo` block with:

- version `5.2.0`
- stable GUID `3d49185d-e43b-4ad0-8b87-78629275d00f`
- Jeffrey Friedler as author
- Fusion Technology Strategies as company metadata
- MIT license and project links
- focused discovery tags
- release notes
- an informational inventory of all 13 external module families
- the existing PowerShell 7.6 runtime requirement

The external module inventory is deliberately not a `RequiredModules` list. Offline safety checks do not need cloud modules, several capabilities are optional or platform-dependent, and installation currently occurs only when an operator explicitly supplies `-InstallMissingModules`.

Gallery owner identity is separate from author and company metadata. The PowerShell Gallery account whose API key performs the first publication becomes the initial package owner. Add any co-owner only through the Gallery's confirmation process after publication.

## Packaging result

Use `Microsoft.PowerShell.PSResourceGet` 1.2.0 to validate, discover, and publish the package. Use the repository's deterministic package builder to construct the exact candidate. Do not use legacy `Publish-Script` to construct this package.

The legacy builder automatically indexed the console's internal functions and commands, producing a tag field beyond its 4,000-character warning threshold. The modern metadata path produced a focused 158-character tag field and no internal function names, but its raw package wrapper included changing timestamps and relationship identifiers. `New-DeterministicGalleryPackage.ps1` writes the same canonical five-entry package from the same source bytes.

The repository validation command is:

```powershell
$outputRoot = Join-Path $env:LOCALAPPDATA 'M365-IR-Console\GalleryValidation'
pwsh -NoProfile -File .\scripts\Test-GalleryPackage.ps1 -OutputRoot $outputRoot
```

Use an empty output directory. The validator:

1. validates metadata with PSResourceGet 1.2.0
2. constructs the canonical package twice without public credentials
3. requires both complete package SHA-256 digests to match
4. rejects unsafe archive paths, extra files, and unexpected identity
5. confirms the packaged script is byte-identical to source
6. enforces the 4,000-character tag ceiling and rejects internal function tags
7. publishes the inspected package to a temporary modern local repository and requires exact package-byte preservation
8. discovers and saves the package through that repository
9. validates metadata with PowerShellGet 2.2.5
10. discovers and saves the same package through a temporary legacy local repository
11. confirms both saved scripts are byte-identical to source
12. removes both temporary repository registrations

The validated Windows run built the package twice with the same complete digest, found it through both clients, and matched both saved copies to source. It did not contact the public PowerShell Gallery.

## Intended installation after publication

Modern clients:

```powershell
Install-PSResource -Name M365-IR-Console -Version 5.2.0 -Repository PSGallery -Scope CurrentUser
```

Legacy clients:

```powershell
Install-Script -Name M365-IR-Console -RequiredVersion 5.2.0 -Repository PSGallery -Scope CurrentUser
```

The repository should remain untrusted unless an organization's policy explicitly says otherwise. Review the package and its source before installation.

## Gates before the first publication

Publishing is a separate external action. Complete every gate against one exact release candidate:

1. Pass the complete Windows and Ubuntu offline suites, Pester, PSScriptAnalyzer, dependency smoke tests, dependency review, and security scanners.
2. Pass the isolated package test on Windows and Ubuntu.
3. Repeat the approved test-tenant workflow for the included service operations.
4. Sign and timestamp the candidate with the Fusion Authenticode certificate, then run the package validator with `-ScriptPath` pointing to the signed release asset.
5. Confirm the exact package name is still available and sign in to the intended PowerShell Gallery owner account.
6. Build the final GitHub asset and Gallery package from the same exact approved executable bytes.
7. Inspect the final NuSpec, five archive entries, metadata, tag length, script bytes, and SHA-256 digest.
8. Obtain explicit publication approval and retrieve the narrowly scoped Gallery API key through the approved secret process.
9. Publish the signed GitHub release with the script and canonical package as assets. Dispatch **Publish signed script to PowerShell Gallery** on `main` with the exact release tag, verified source commit, and both SHA-256 digests. Approve the protected `powershell-gallery` environment deployment after checking the inputs.
10. Install the public package with both modern and legacy clients in clean PowerShell 7.6 environments.
11. Verify public script bytes, metadata, hash, signature status, `-OfflineSelfTest`, and `-PreflightOnly` before announcing it.
12. Add the confirmed package owner and public Gallery link to the repository documentation.

The workflow checks the signed script against the release commit, verifies the signer and timestamp, and independently reconstructs the package before uploading. It uses the `PSGALLERY_API_KEY` environment secret only for the final upload.

Official references:

- [Creating and publishing an item](https://learn.microsoft.com/en-us/powershell/gallery/how-to/publishing-packages/publishing-a-package?view=powershellget-3.x)
- [PSResourceGet overview](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.psresourceget/about/about_psresourceget?view=powershellget-3.x)
- [PowerShell Gallery package metadata](https://learn.microsoft.com/en-us/powershell/gallery/concepts/package-manifest-affecting-ui?view=powershellget-3.x)
- [Managing package owners](https://learn.microsoft.com/en-us/powershell/gallery/how-to/publishing-packages/managing-package-owners?view=powershellget-3.x)
