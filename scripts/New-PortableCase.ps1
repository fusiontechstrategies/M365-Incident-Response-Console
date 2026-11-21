#Requires -Version 7.6

[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)][string]$CasePath,
    [Parameter(Mandatory)][string]$Destination,
    [string]$CoveragePath,
    [switch]$Synthetic
)

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'

function Assert-RegularCaseEntry {
    param([IO.FileSystemInfo]$Item)

    if (!$Item -or ($Item.Attributes -band ([IO.FileAttributes]::ReparsePoint -bor [IO.FileAttributes]::Device)) -or
        ($Item -isnot [IO.DirectoryInfo] -and $Item -isnot [IO.FileInfo]) -or
        (!$IsWindows -and $Item -is [IO.FileInfo] -and [string]$Item.UnixStat.ItemType -cne 'File')) {
        throw 'Portable case export requires regular files and directories.'
    }
}

function Get-PortableLocalItem {
    param([string]$ItemPath)

    $fullPath = [IO.Path]::GetFullPath($ItemPath, $PWD.ProviderPath)
    if ($IsWindows -and $fullPath.StartsWith('\\')) { throw 'Use a local case path.' }
    $current = [IO.Path]::GetPathRoot($fullPath)
    $item = Get-Item -LiteralPath $current -Force
    $parts = $fullPath.Substring($current.Length).Split([IO.Path]::DirectorySeparatorChar, [StringSplitOptions]::RemoveEmptyEntries)
    foreach ($segment in $parts) {
        $current = Join-Path $current $segment
        $item = Get-Item -LiteralPath $current -Force
        Assert-RegularCaseEntry $item
    }
    return $item
}

function New-PrivateExportDirectory {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSUseShouldProcessForStateChangingFunctions', '',
        Justification = 'The calling script obtains ShouldProcess approval before creating the export directory.')]
    param([string]$Path)

    if ($IsWindows) {
        $identity = [Security.Principal.WindowsIdentity]::GetCurrent().User
        if (!$identity) { throw 'Could not determine the export owner.' }
        $security = [Security.AccessControl.DirectorySecurity]::new()
        $security.SetAccessRuleProtection($true, $false)
        $security.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
            $identity, 'FullControl', 'ContainerInherit, ObjectInherit', 'None', 'Allow'))
        [IO.FileSystemAclExtensions]::Create([IO.DirectoryInfo]::new($Path), $security)
    }
    else {
        [IO.Directory]::CreateDirectory($Path, [IO.UnixFileMode]'UserRead, UserWrite, UserExecute')
    }
}

function Copy-PortableArtifact {
    param([IO.FileInfo]$InputFile, [string]$RelativePath, [string]$ExportRoot)

    $output = Join-Path $ExportRoot $RelativePath
    $null = [IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($output))
    [IO.File]::Copy($InputFile.FullName, $output)
    $file = Get-Item -LiteralPath $output -Force
    return [ordered]@{
        Path = $RelativePath
        Length = $file.Length
        SHA256 = (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
    }
}

$source = Get-PortableLocalItem $CasePath
$destinationPath = [IO.Path]::GetFullPath($Destination, $PWD.ProviderPath)
$parent = Get-PortableLocalItem ([IO.Path]::GetDirectoryName($destinationPath))
Assert-RegularCaseEntry $source
Assert-RegularCaseEntry $parent
$comparison = if ($IsWindows) { [StringComparison]::OrdinalIgnoreCase } else { [StringComparison]::Ordinal }
if ($source -isnot [IO.DirectoryInfo] -or $parent -isnot [IO.DirectoryInfo] -or !$source.Parent -or
    (Test-Path -LiteralPath $destinationPath) -or $destinationPath.StartsWith(
        $source.FullName.TrimEnd([IO.Path]::DirectorySeparatorChar) + [IO.Path]::DirectorySeparatorChar, $comparison)) {
    throw 'Choose an existing case directory and a new destination outside it.'
}

$entries = [Collections.Generic.List[IO.FileInfo]]::new()
$directories = [Collections.Generic.Stack[IO.DirectoryInfo]]::new()
$directories.Push($source)
$entryCount = 0
while ($directories.Count) {
    foreach ($item in (Get-ChildItem -LiteralPath $directories.Pop().FullName -Force)) {
        Assert-RegularCaseEntry $item
        $entryCount++
        if ($entryCount -gt 8186) { throw 'Case exceeds the portable entry limit.' }
        if ($item -is [IO.DirectoryInfo]) { $directories.Push($item) }
        else { $entries.Add($item) }
    }
}
$manifest = $entries | Where-Object { $_.Name -ceq 'evidence_manifest.sha256.json' -and $_.DirectoryName -ceq $source.FullName }
if (!$manifest -or $manifest.Length -gt 4MB) { throw 'Seal the source case before exporting it.' }

$handoffPath = Join-Path $source.Parent.FullName '.handoffs'
$journal = $null
if (Test-Path -LiteralPath $handoffPath) {
    Assert-RegularCaseEntry (Get-Item -LiteralPath $handoffPath -Force)
    $handoffDirectory = Join-Path $handoffPath $source.Name
    if (Test-Path -LiteralPath $handoffDirectory) {
        Assert-RegularCaseEntry (Get-Item -LiteralPath $handoffDirectory -Force)
        $journalPath = Join-Path $handoffDirectory 'events.json'
        if (Test-Path -LiteralPath $journalPath) {
            $journal = Get-Item -LiteralPath $journalPath -Force
            Assert-RegularCaseEntry $journal
            if ($journal -isnot [IO.FileInfo] -or $journal.Length -gt 4MB) { throw 'Invalid handoff journal.' }
        }
    }
}

$coverage = @([ordered]@{ Source = 'Original case collection'; Status = 'Unknown'; Evidence = @(); Note = 'The operator supplied no structured coverage record.' })
if ($CoveragePath) {
    $coverageFile = Get-PortableLocalItem $CoveragePath
    if ($coverageFile -isnot [IO.FileInfo] -or $coverageFile.Length -gt 1MB) { throw 'Invalid coverage document.' }
    $coverage = ConvertFrom-Json -InputObject ([IO.File]::ReadAllText($coverageFile.FullName)) -AsHashtable -DateKind String -Depth 20 -NoEnumerate
}
if (!$PSCmdlet.ShouldProcess($destinationPath, 'Export a private portable case snapshot')) { return }

$temp = Join-Path $parent.FullName ('.portable-case-' + [guid]::NewGuid().ToString('N'))
if (Test-Path -LiteralPath $temp) { throw 'Could not reserve a new private export directory.' }
$null = New-PrivateExportDirectory $temp
try {
    $files = [Collections.Generic.List[object]]::new()
    foreach ($file in ($entries | Sort-Object FullName -CaseSensitive)) {
        $relative = [IO.Path]::GetRelativePath($source.FullName, $file.FullName).Replace([IO.Path]::DirectorySeparatorChar, '/')
        $files.Add((Copy-PortableArtifact $file "case/$relative" $temp))
    }
    $handoff = [ordered]@{ Count = 0; Head = '0' * 64 }
    if ($journal) {
        $files.Add((Copy-PortableArtifact $journal 'handoff/events.json' $temp))
        $handoffCopy = Get-Content -LiteralPath (Join-Path $temp 'handoff/events.json') -Raw | ConvertFrom-Json -AsHashtable -DateKind String -Depth 20
        $handoff = [ordered]@{ Count = $handoffCopy.Events.Count; Head = $handoffCopy.Events[-1].Hash }
    }
    $portable = [ordered]@{
        Schema = 'm365-ir-portable-case/v1'
        CaseId = $source.Name
        Synthetic = $Synthetic.IsPresent
        GeneratedUtc = [datetime]::UtcNow.ToString('o')
        Files = $files.ToArray()
        Handoff = $handoff
        Coverage = $coverage
    }
    $portable | ConvertTo-Json -Depth 24 -Compress | Set-Content -LiteralPath (Join-Path $temp 'portable-case.json') -Encoding utf8
    $null = & (Join-Path $PSScriptRoot 'Test-PortableCase.ps1') -Path $temp
    [IO.Directory]::Move($temp, $destinationPath)
}
finally {
    if ([IO.Directory]::Exists($temp)) {
        $staged = Get-Item -LiteralPath $temp -Force
        Assert-RegularCaseEntry $staged
        if ($staged.FullName -cne $temp -or $staged.Parent.FullName -cne $parent.FullName) {
            throw 'The private staging path changed during export.'
        }
        [IO.Directory]::Delete($staged.FullName, $true)
    }
}
Get-Item -LiteralPath $destinationPath
