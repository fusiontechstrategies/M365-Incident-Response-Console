#Requires -Version 7.6

[CmdletBinding()]
param(
    [string]$ScriptPath = (Join-Path -Path $PSScriptRoot -ChildPath '..\M365-IR-Console.ps1'),
    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string]$OutputPath
)

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$sourcePath = [System.IO.Path]::GetFullPath($ScriptPath)
$destinationPath = [System.IO.Path]::GetFullPath($OutputPath)
if (-not (Test-Path -LiteralPath $sourcePath -PathType Leaf)) {
    throw "ScriptPath does not exist: $sourcePath"
}
if (Test-Path -LiteralPath $destinationPath) {
    throw "OutputPath already exists: $destinationPath"
}

$destinationDirectory = Split-Path -Path $destinationPath -Parent
if (-not (Test-Path -LiteralPath $destinationDirectory -PathType Container)) {
    $null = New-Item -ItemType Directory -Path $destinationDirectory
}

Import-Module Microsoft.PowerShell.PSResourceGet -RequiredVersion 1.2.0 -ErrorAction Stop
if (-not (Test-PSScriptFileInfo -Path $sourcePath)) {
    throw 'PSResourceGet rejected the PSScriptInfo metadata.'
}
Import-Module PowerShellGet -RequiredVersion 2.2.5 -ErrorAction Stop
$metadata = Test-ScriptFileInfo -Path $sourcePath

if ($metadata.Name -cne 'M365-IR-Console' -or $metadata.Version.ToString() -cne '5.1.1') {
    throw "Unexpected package identity: $($metadata.Name) $($metadata.Version)"
}

function ConvertTo-XmlText {
    param([AllowEmptyString()][string]$Value)
    return [System.Security.SecurityElement]::Escape($Value)
}

function ConvertTo-Utf8ByteArray {
    param([Parameter(Mandatory)][string]$Value)
    $normalized = $Value -replace "`r`n?", "`n"
    return [System.Text.UTF8Encoding]::new($false).GetBytes($normalized)
}

function Get-Crc32 {
    param([Parameter(Mandatory)][byte[]]$Bytes)

    $table = [uint32[]]::new(256)
    for ($index = 0; $index -lt $table.Length; $index++) {
        [uint32]$value = $index
        for ($bit = 0; $bit -lt 8; $bit++) {
            if (($value -band 1) -eq 1) {
                $value = ($value -shr 1) -bxor [uint32]3988292384
            }
            else {
                $value = $value -shr 1
            }
        }
        $table[$index] = $value
    }

    [uint32]$crc = [uint32]::MaxValue
    foreach ($byte in $Bytes) {
        $lookup = [int](($crc -bxor [uint32]$byte) -band 0xFF)
        $crc = ($crc -shr 8) -bxor $table[$lookup]
    }
    return [uint32](([uint64]$crc -bxor [uint64][uint32]::MaxValue) -band [uint64][uint32]::MaxValue)
}

$description = ([string]$metadata.Description -replace "`r`n?", "`n").Trim()
$releaseNotes = (@($metadata.ReleaseNotes) -join "`n").Trim()
$tags = @('PSScript') + @($metadata.Tags | Where-Object { $_ -cne 'PSScript' })
$tagText = $tags -join ' '

$escaped = [ordered]@{
    Id = ConvertTo-XmlText -Value $metadata.Name
    Version = ConvertTo-XmlText -Value $metadata.Version.ToString()
    Author = ConvertTo-XmlText -Value $metadata.Author
    Company = ConvertTo-XmlText -Value $metadata.CompanyName
    License = ConvertTo-XmlText -Value $metadata.LicenseUri.AbsoluteUri
    Project = ConvertTo-XmlText -Value $metadata.ProjectUri.AbsoluteUri.TrimEnd('/')
    Description = ConvertTo-XmlText -Value $description
    ReleaseNotes = ConvertTo-XmlText -Value $releaseNotes
    Copyright = ConvertTo-XmlText -Value $metadata.Copyright
    Tags = ConvertTo-XmlText -Value $tagText
}

$relationships = @"
<?xml version="1.0" encoding="utf-8"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Type="http://schemas.microsoft.com/packaging/2010/07/manifest" Target="/M365-IR-Console.nuspec" Id="RManifest" />
  <Relationship Type="http://schemas.openxmlformats.org/package/2006/relationships/metadata/core-properties" Target="/package/services/metadata/core-properties/core.psmdcp" Id="RCore" />
</Relationships>
"@

$contentTypes = @"
<?xml version="1.0" encoding="utf-8"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
  <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml" />
  <Default Extension="psmdcp" ContentType="application/vnd.openxmlformats-package.core-properties+xml" />
  <Default Extension="ps1" ContentType="application/octet" />
  <Default Extension="nuspec" ContentType="application/octet" />
</Types>
"@

$nuspec = @"
<?xml version="1.0" encoding="utf-8"?>
<package xmlns="http://schemas.microsoft.com/packaging/2011/08/nuspec.xsd">
  <metadata>
    <id>$($escaped.Id)</id>
    <version>$($escaped.Version)</version>
    <authors>$($escaped.Author)</authors>
    <owners>$($escaped.Company)</owners>
    <requireLicenseAcceptance>false</requireLicenseAcceptance>
    <licenseUrl>$($escaped.License)</licenseUrl>
    <projectUrl>$($escaped.Project)</projectUrl>
    <description>$($escaped.Description)</description>
    <releaseNotes>$($escaped.ReleaseNotes)</releaseNotes>
    <copyright>$($escaped.Copyright)</copyright>
    <tags>$($escaped.Tags)</tags>
  </metadata>
</package>
"@

$coreProperties = @"
<?xml version="1.0" encoding="utf-8"?>
<coreProperties xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:dcterms="http://purl.org/dc/terms/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns="http://schemas.openxmlformats.org/package/2006/metadata/core-properties">
  <dc:creator>$($escaped.Author)</dc:creator>
  <dc:description>$($escaped.Description)</dc:description>
  <dc:identifier>$($escaped.Id)</dc:identifier>
  <version>$($escaped.Version)</version>
  <keywords>$($escaped.Tags)</keywords>
  <lastModifiedBy>M365-IR-Console deterministic package builder</lastModifiedBy>
</coreProperties>
"@

$entries = [ordered]@{
    '[Content_Types].xml' = ConvertTo-Utf8ByteArray -Value $contentTypes
    '_rels/.rels' = ConvertTo-Utf8ByteArray -Value $relationships
    'M365-IR-Console.nuspec' = ConvertTo-Utf8ByteArray -Value $nuspec
    'M365-IR-Console.ps1' = [System.IO.File]::ReadAllBytes($sourcePath)
    'package/services/metadata/core-properties/core.psmdcp' = ConvertTo-Utf8ByteArray -Value $coreProperties
}

$stream = [System.IO.File]::Open($destinationPath, [System.IO.FileMode]::CreateNew, [System.IO.FileAccess]::Write, [System.IO.FileShare]::None)
$writer = [System.IO.BinaryWriter]::new($stream, [System.Text.UTF8Encoding]::new($false), $true)
$centralEntries = [System.Collections.Generic.List[object]]::new()
$utf8Flag = [uint16]0x0800
$dosTime = [uint16]0
$dosDate = [uint16]33

try {
    foreach ($entry in $entries.GetEnumerator()) {
        $nameBytes = [System.Text.UTF8Encoding]::new($false).GetBytes([string]$entry.Key)
        [byte[]]$data = $entry.Value
        if ($data.LongLength -gt [uint32]::MaxValue -or $stream.Position -gt [uint32]::MaxValue) {
            throw 'Package exceeds the classic ZIP size limit.'
        }
        [uint32]$crc = Get-Crc32 -Bytes $data
        [uint32]$size = $data.Length
        [uint32]$offset = $stream.Position

        $writer.Write([uint32]0x04034B50)
        $writer.Write([uint16]20)
        $writer.Write($utf8Flag)
        $writer.Write([uint16]0)
        $writer.Write($dosTime)
        $writer.Write($dosDate)
        $writer.Write($crc)
        $writer.Write($size)
        $writer.Write($size)
        $writer.Write([uint16]$nameBytes.Length)
        $writer.Write([uint16]0)
        $writer.Write($nameBytes)
        $writer.Write($data)

        $centralEntries.Add([pscustomobject]@{
            NameBytes = $nameBytes
            Crc = $crc
            Size = $size
            Offset = $offset
        })
    }

    [uint32]$centralOffset = $stream.Position
    foreach ($entry in $centralEntries) {
        $writer.Write([uint32]0x02014B50)
        $writer.Write([uint16]20)
        $writer.Write([uint16]20)
        $writer.Write($utf8Flag)
        $writer.Write([uint16]0)
        $writer.Write($dosTime)
        $writer.Write($dosDate)
        $writer.Write([uint32]$entry.Crc)
        $writer.Write([uint32]$entry.Size)
        $writer.Write([uint32]$entry.Size)
        $writer.Write([uint16]$entry.NameBytes.Length)
        $writer.Write([uint16]0)
        $writer.Write([uint16]0)
        $writer.Write([uint16]0)
        $writer.Write([uint16]0)
        $writer.Write([uint32]0)
        $writer.Write([uint32]$entry.Offset)
        $writer.Write([byte[]]$entry.NameBytes)
    }
    [uint32]$centralSize = $stream.Position - $centralOffset

    $writer.Write([uint32]0x06054B50)
    $writer.Write([uint16]0)
    $writer.Write([uint16]0)
    $writer.Write([uint16]$centralEntries.Count)
    $writer.Write([uint16]$centralEntries.Count)
    $writer.Write($centralSize)
    $writer.Write($centralOffset)
    $writer.Write([uint16]0)
    $writer.Flush()
}
finally {
    $writer.Dispose()
    $stream.Dispose()
}

Get-Item -LiteralPath $destinationPath
