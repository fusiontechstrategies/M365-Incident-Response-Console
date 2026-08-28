#Requires -Version 7.6

[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string]$OutputRoot
)

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$repositoryRoot = [System.IO.Path]::GetFullPath((Join-Path -Path $PSScriptRoot -ChildPath '..'))
$scriptPath = Join-Path -Path $repositoryRoot -ChildPath 'M365-IR-Console.ps1'
$outputPath = [System.IO.Path]::GetFullPath($OutputRoot)

if (Test-Path -LiteralPath $outputPath) {
    if (@(Get-ChildItem -LiteralPath $outputPath -Force).Count -gt 0) {
        throw "OutputRoot must be empty: $outputPath"
    }
}
else {
    $null = New-Item -ItemType Directory -Path $outputPath
}

$packagePathA = Join-Path -Path $outputPath -ChildPath 'package-a'
$packagePathB = Join-Path -Path $outputPath -ChildPath 'package-b'
$feedPath = Join-Path -Path $outputPath -ChildPath 'feed'
$modernSavePath = Join-Path -Path $outputPath -ChildPath 'modern-save'
$legacySavePath = Join-Path -Path $outputPath -ChildPath 'legacy-save'
$temporaryPath = Join-Path -Path $outputPath -ChildPath 'temporary'
$null = New-Item -ItemType Directory -Path $packagePathA, $packagePathB, $feedPath, $modernSavePath, $legacySavePath, $temporaryPath

$previousTemp = $env:TEMP
$previousTmp = $env:TMP
$env:TEMP = $temporaryPath
$env:TMP = $temporaryPath

$suffix = [guid]::NewGuid().ToString('N')
$modernRepository = "M365GalleryModern_$suffix"
$legacyRepository = "M365GalleryLegacy_$suffix"

function Get-FileSha256 {
    param([Parameter(Mandatory)][string]$Path)
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash
}

function Remove-ValidationRepository {
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Low')]
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][ValidateSet('Modern', 'Legacy')][string]$Kind
    )

    if ($Kind -eq 'Modern') {
        if ((Get-PSResourceRepository -Name $Name -ErrorAction SilentlyContinue) -and
            $PSCmdlet.ShouldProcess($Name, 'Unregister temporary PSResource repository')) {
            Unregister-PSResourceRepository -Name $Name
        }
        return
    }

    if ((Get-PSRepository -Name $Name -ErrorAction SilentlyContinue) -and
        $PSCmdlet.ShouldProcess($Name, 'Unregister temporary PowerShellGet repository')) {
        Unregister-PSRepository -Name $Name
    }
}

try {
    Import-Module Microsoft.PowerShell.PSResourceGet -RequiredVersion 1.2.0 -ErrorAction Stop
    if (-not (Test-PSScriptFileInfo -Path $scriptPath)) {
        throw 'PSResourceGet rejected the PSScriptInfo metadata.'
    }

    $packageName = 'M365-IR-Console.5.1.1.nupkg'
    $packageA = Join-Path -Path $packagePathA -ChildPath $packageName
    $packageB = Join-Path -Path $packagePathB -ChildPath $packageName
    $builder = Join-Path -Path $PSScriptRoot -ChildPath 'New-DeterministicGalleryPackage.ps1'
    $createdA = @(& $builder -ScriptPath $scriptPath -OutputPath $packageA)
    $createdB = @(& $builder -ScriptPath $scriptPath -OutputPath $packageB)
    if ($createdA.Count -ne 1 -or $createdB.Count -ne 1 -or
        -not (Test-Path -LiteralPath $packageA) -or -not (Test-Path -LiteralPath $packageB)) {
        throw 'Expected exactly one package from each independent build.'
    }
    if ((Get-FileSha256 -Path $packageA) -cne (Get-FileSha256 -Path $packageB)) {
        throw 'Independent Gallery package builds differ.'
    }
    $nupkg = Get-Item -LiteralPath $packageA

    Add-Type -AssemblyName System.IO.Compression
    $archive = [System.IO.Compression.ZipFile]::OpenRead($nupkg.FullName)
    try {
        $entryNames = @($archive.Entries | ForEach-Object FullName)
        $expectedEntries = @(
            '[Content_Types].xml'
            '_rels/.rels'
            'M365-IR-Console.nuspec'
            'M365-IR-Console.ps1'
            'package/services/metadata/core-properties/core.psmdcp'
        )
        if (@(Compare-Object -ReferenceObject $expectedEntries -DifferenceObject $entryNames).Count -gt 0) {
            throw "Package entry set is unexpected: $($entryNames -join ', ')"
        }
        $unsafeEntries = @($entryNames | Where-Object {
            $_ -match '(^|/)\.\.(/|$)' -or
            $_ -match '^/' -or
            $_ -match '^[A-Za-z]:' -or
            $_.Contains('\')
        })
        if ($unsafeEntries.Count -gt 0) {
            throw "Package contains unsafe archive path(s): $($unsafeEntries -join ', ')"
        }

        $scriptEntry = $archive.GetEntry('M365-IR-Console.ps1')
        $nuspecEntry = $archive.GetEntry('M365-IR-Console.nuspec')
        if ($null -eq $scriptEntry -or $null -eq $nuspecEntry) {
            throw 'Package is missing the expected script or NuSpec.'
        }

        $sourceBytes = [System.IO.File]::ReadAllBytes($scriptPath)
        $memory = [System.IO.MemoryStream]::new()
        try {
            $stream = $scriptEntry.Open()
            try {
                $stream.CopyTo($memory)
            }
            finally {
                $stream.Dispose()
            }
            $sourceDigest = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($sourceBytes))
            $packagedDigest = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($memory.ToArray()))
            if ($sourceDigest -cne $packagedDigest) {
                throw 'Packaged script bytes differ from repository source.'
            }
        }
        finally {
            $memory.Dispose()
        }

        $reader = [System.IO.StreamReader]::new($nuspecEntry.Open())
        try {
            [xml]$nuspec = $reader.ReadToEnd()
        }
        finally {
            $reader.Dispose()
        }
    }
    finally {
        $archive.Dispose()
    }

    $metadata = $nuspec.SelectSingleNode("/*[local-name()='package']/*[local-name()='metadata']")
    if ($null -eq $metadata) {
        throw 'Package NuSpec metadata is missing.'
    }
    if ([string]$metadata.id -cne 'M365-IR-Console') {
        throw "Unexpected package id: $($metadata.id)"
    }
    if ([string]$metadata.version -cne '5.1.1') {
        throw "Unexpected package version: $($metadata.version)"
    }
    if ([string]$metadata.authors -cne 'Jeffrey Friedler') {
        throw "Unexpected package author: $($metadata.authors)"
    }
    if ([string]$metadata.owners -cne 'Fusion Technology Strategies') {
        throw "Unexpected package owner metadata: $($metadata.owners)"
    }
    if ([string]$metadata.licenseUrl -cne 'https://github.com/fusiontechstrategies/M365-Incident-Response-Console/blob/main/LICENSE') {
        throw "Unexpected license URL: $($metadata.licenseUrl)"
    }
    if ([string]$metadata.projectUrl -cne 'https://github.com/fusiontechstrategies/M365-Incident-Response-Console') {
        throw "Unexpected project URL: $($metadata.projectUrl)"
    }

    $tags = [string]$metadata.tags
    if ($tags.Length -gt 4000) {
        throw "Package tag field is $($tags.Length) characters; the safe maximum is 4000."
    }
    if ($tags -match 'PS(Function|Command)_') {
        throw 'Package tags expose internal function or command names.'
    }
    foreach ($requiredTag in @('PSScript', 'Microsoft365', 'IncidentResponse', 'DFIR', 'Security', 'PSEdition_Core')) {
        if (@($tags -split '\s+') -cnotcontains $requiredTag) {
            throw "Package is missing required tag '$requiredTag'."
        }
    }

    Register-PSResourceRepository -Name $modernRepository -Uri $feedPath -ApiVersion Local -Trusted
    Publish-PSResource -NupkgPath $nupkg.FullName -Repository $modernRepository -ApiKey 'local-validation-only'
    $publishedPackages = @(Get-ChildItem -LiteralPath $feedPath -File -Filter '*.nupkg')
    if ($publishedPackages.Count -ne 1 -or
        (Get-FileSha256 -Path $publishedPackages[0].FullName) -cne (Get-FileSha256 -Path $nupkg.FullName)) {
        throw 'Local publish did not preserve the exact package bytes.'
    }
    $modern = Find-PSResource -Name M365-IR-Console -Version 5.1.1 -Repository $modernRepository
    if ($modern.Type -ne 'Script') {
        throw "Modern discovery returned unexpected type '$($modern.Type)'."
    }
    Save-PSResource -Name M365-IR-Console -Version 5.1.1 -Repository $modernRepository -Path $modernSavePath -IncludeXml -TrustRepository
    $modernScript = @(Get-ChildItem -LiteralPath $modernSavePath -Recurse -File -Filter 'M365-IR-Console.ps1')
    if ($modernScript.Count -ne 1 -or (Get-FileSha256 -Path $modernScript[0].FullName) -cne (Get-FileSha256 -Path $scriptPath)) {
        throw 'Modern saved script is missing or differs from source.'
    }
    Remove-ValidationRepository -Name $modernRepository -Kind Modern

    Import-Module PowerShellGet -RequiredVersion 2.2.5 -ErrorAction Stop
    $legacyInfo = Test-ScriptFileInfo -Path $scriptPath
    $expectedExternalModules = @(
        'ExchangeOnlineManagement'
        'Microsoft.Graph.Authentication'
        'Microsoft.Graph.Users'
        'Microsoft.Graph.Users.Actions'
        'Microsoft.Graph.Identity.SignIns'
        'Microsoft.Graph.Applications'
        'Microsoft.Graph.Reports'
        'Microsoft.Graph.Groups'
        'Microsoft.Graph.Identity.DirectoryManagement'
        'Microsoft.Graph.Devices.CorporateManagement'
        'Microsoft.Graph.DeviceManagement'
        'MicrosoftTeams'
        'Microsoft.Online.SharePoint.PowerShell'
    )
    if (@(Compare-Object -ReferenceObject $expectedExternalModules -DifferenceObject @($legacyInfo.ExternalModuleDependencies)).Count -gt 0) {
        throw 'PSScriptInfo external module inventory differs from the application catalog.'
    }
    if (@($legacyInfo.RequiredModules | Where-Object { $null -ne $_ }).Count -ne 0) {
        throw 'Gallery metadata must not turn optional or capability-specific modules into unconditional dependencies.'
    }

    Register-PSRepository -Name $legacyRepository -SourceLocation $feedPath -PublishLocation $feedPath -InstallationPolicy Trusted
    $legacy = Find-Script -Name M365-IR-Console -RequiredVersion 5.1.1 -Repository $legacyRepository
    if ($legacy.Type -ne 'Script') {
        throw "Legacy discovery returned unexpected type '$($legacy.Type)'."
    }
    Save-Script -Name M365-IR-Console -RequiredVersion 5.1.1 -Repository $legacyRepository -Path $legacySavePath -Force
    $legacyScript = Join-Path -Path $legacySavePath -ChildPath 'M365-IR-Console.ps1'
    if (-not (Test-Path -LiteralPath $legacyScript) -or (Get-FileSha256 -Path $legacyScript) -cne (Get-FileSha256 -Path $scriptPath)) {
        throw 'Legacy saved script is missing or differs from source.'
    }
    Remove-ValidationRepository -Name $legacyRepository -Kind Legacy

    $evidence = [ordered]@{
        schema = 1
        package = $nupkg.Name
        packageVersion = '5.1.1'
        packageSha256 = Get-FileSha256 -Path $nupkg.FullName
        sourceSha256 = Get-FileSha256 -Path $scriptPath
        packageEntryCount = $entryNames.Count
        repeatPackageSha256Match = $true
        tagLength = $tags.Length
        localPublishPackageByteMatch = $true
        modernDiscovery = $true
        modernSourceByteMatch = $true
        legacyDiscovery = $true
        legacySourceByteMatch = $true
        publicRepositoryContacted = $false
    }
    $evidencePath = Join-Path -Path $outputPath -ChildPath 'gallery-package-evidence.json'
    $evidence | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $evidencePath -Encoding utf8NoBOM
    $evidence
}
finally {
    Remove-ValidationRepository -Name $modernRepository -Kind Modern
    Remove-ValidationRepository -Name $legacyRepository -Kind Legacy
    $env:TEMP = $previousTemp
    $env:TMP = $previousTmp
}
