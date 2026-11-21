#Requires -Version 7.6

[CmdletBinding(SupportsShouldProcess)]
param([Parameter(Mandatory)][string]$Destination)

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'
$root = [IO.Path]::GetFullPath($Destination, $PWD.ProviderPath)
if (Test-Path -LiteralPath $root) { throw 'Choose a new destination directory.' }
if (!$PSCmdlet.ShouldProcess($root, 'Create the synthetic portable case')) { return }

$utf8 = [Text.UTF8Encoding]::new($false)
$caseId = 'IR-SYNTHETIC-PORTABLE-001'
$at = '2026-01-15T13:00:00.0000000Z'
$zeroHash = '0' * 64
$casePath = Join-Path $root 'case'
$null = New-Item -ItemType Directory -Path $casePath, (Join-Path $root 'handoff')

function Write-FixtureText {
    param([string]$RelativePath, [string]$Text)
    [IO.File]::WriteAllText((Join-Path $root $RelativePath), "$Text" + [char]10, $utf8)
}

function Get-FixtureHash {
    param([string]$Text)
    [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($utf8.GetBytes($Text)))
}

function Get-FixtureInventoryItem {
    param([string]$RelativePath, [string]$InventoryRoot)
    $file = Get-Item -LiteralPath (Join-Path $InventoryRoot $RelativePath)
    [ordered]@{
        Path = $RelativePath
        Length = $file.Length
        SHA256 = (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
    }
}

$metadata = [ordered]@{
    CaseId = $caseId
    CreatedUtc = $at
    Investigator = 'Alex'
    Mode = 'Audit'
    Label = ('Sample caf' + [char]0x00e9)
}
[IO.File]::WriteAllText((Join-Path $casePath 'case_metadata.json'),
    ($metadata | ConvertTo-Json -Compress) + [char]10, [Text.UTF8Encoding]::new($true))
Write-FixtureText 'case/mailbox.txt' 'Synthetic mailbox evidence. No tenant data.'
$text = [IO.File]::ReadAllText((Join-Path $casePath 'case_metadata.json'))
$metadataDigest = Get-FixtureHash $text

$action = [ordered]@{
    Sequence = 1L
    TimestampUtc = $at
    Status = 'Read'
    Action = 'Inspect synthetic mailbox'
    Target = 'fixture@contoso.example'
    Investigator = 'Alex'
    Mode = 'Audit'
    Details = [ordered]@{ Source = 'Synthetic input'; Label = ('Sample caf' + [char]0x00e9) }
    PreviousHash = $zeroHash
}
$action.EntryHash = Get-FixtureHash ($action | ConvertTo-Json -Depth 30 -Compress)
Write-FixtureText 'case/action_log.jsonl' ($action | ConvertTo-Json -Depth 30 -Compress)

$files = foreach ($name in 'action_log.jsonl', 'case_metadata.json', 'mailbox.txt') {
    $item = Get-FixtureInventoryItem $name $casePath
    [ordered]@{ RelativePath = $item.Path; Length = $item.Length; LastWriteTimeUtc = $at; SHA256 = $item.SHA256 }
}
$native = [ordered]@{
    Schema = 'm365-ir-evidence-manifest/v1'
    CaseId = $caseId
    ToolVersion = '5.2.0'
    GeneratedUtc = $at
    HashAlgorithm = 'SHA-256'
    ActionLogChainValid = $true
    ActionLogEntries = 1
    ActionLogFinalHash = $action.EntryHash
    ManifestFilesExcluded = @('evidence_manifest.sha256.json', 'evidence_manifest.sha256.csv')
    FileCount = $files.Count
    Files = @($files)
}
Write-FixtureText 'case/evidence_manifest.sha256.json' ($native | ConvertTo-Json -Depth 8 -Compress)

$handoff = [ordered]@{
    Event = 'Assigned'
    AssignmentId = '0123456789abcdef0123456789abcdef'
    ReplacesAssignmentId = ''
    TimestampUtc = $at
    Investigator = 'Alex'
    IdentitySource = 'Operator-entered'
    Recipient = 'Sam'
    Decision = 'Verify the synthetic mailbox finding'
    Note = ''
    EvidenceReferences = @('mailbox.txt')
    CaseDigest = $metadataDigest
    PreviousHash = $zeroHash
}
$handoffTip = Get-FixtureHash ($handoff | ConvertTo-Json -Depth 8 -Compress)
$journal = [ordered]@{
    Schema = 'm365-ir-case-handoff/v1'
    Events = @([ordered]@{ Payload = $handoff; Hash = $handoffTip })
}
Write-FixtureText 'handoff/events.json' ($journal | ConvertTo-Json -Depth 12 -Compress)

$inventory = foreach ($name in 'case/action_log.jsonl', 'case/case_metadata.json', 'case/evidence_manifest.sha256.json', 'case/mailbox.txt', 'handoff/events.json') {
    Get-FixtureInventoryItem $name $root
}
$manifest = [ordered]@{
    Schema = 'm365-ir-portable-case/v1'
    CaseId = $caseId
    Synthetic = $true
    GeneratedUtc = $at
    Files = @($inventory)
    Handoff = [ordered]@{ Count = 1; Head = $handoffTip }
    Coverage = @(
        [ordered]@{ Source = 'Synthetic mailbox'; Status = 'Completed'; Evidence = @('case/mailbox.txt'); Note = 'Only the synthetic fixture was inspected.' }
        [ordered]@{ Source = 'Identity sign-ins'; Status = 'NotRun'; Evidence = @(); Note = 'The fixture performs no identity collection.' }
    )
}
Write-FixtureText 'portable-case.json' ($manifest | ConvertTo-Json -Depth 8 -Compress)
Get-Item -LiteralPath $root
