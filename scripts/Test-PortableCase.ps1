#Requires -Version 7.6

[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Path,
    [string]$TrustedPublicKey
)

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'
$zeroHash = '0' * 64
$ordinal = [StringComparer]::Ordinal
$ignoreCase = [StringComparer]::OrdinalIgnoreCase

function Get-PortableTextHash {
    param([string]$Text)
    return [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData([Text.Encoding]::UTF8.GetBytes($Text)))
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
        if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) {
            throw "Linked path component '$current' is not supported."
        }
    }
    return $item
}

function Assert-PortableRegularFile {
    param([IO.FileInfo]$File)
    if (($File.Attributes -band [IO.FileAttributes]::Device) -or
        (!$IsWindows -and [string]$File.UnixStat.ItemType -cne 'File')) {
        throw "Unsupported file type '$($File.Name)'."
    }
}

function Assert-PortablePath {
    param([string]$RelativePath)

    if ($RelativePath.Length -gt 240 -or $RelativePath -cne $RelativePath.Normalize() -or
        $RelativePath -match '[\\:\x00-\x1f\x7f<>?"*|]') {
        throw "Unsafe portable path '$RelativePath'."
    }
    foreach ($segment in $RelativePath.Split('/')) {
        if (!$segment -or $segment.EndsWith('.') -or $segment.EndsWith(' ') -or
            $segment -match '^(?:CON|PRN|AUX|NUL|CONIN\$|CONOUT\$|(?:COM|LPT)[1-9\u00b9\u00b2\u00b3])(?:\.|$)') {
            throw "Unsafe portable path '$RelativePath'."
        }
    }
}

function Read-PortableText {
    param([IO.FileInfo]$File, [long]$MaximumBytes)

    if (!$File -or $File.Length -gt $MaximumBytes) { throw 'A required case document is absent or oversized.' }
    return [IO.File]::ReadAllText($File.FullName, [Text.UTF8Encoding]::new($false, $true))
}

function Assert-PortableJsonProperty {
    param([Text.Json.JsonElement]$Element)

    switch ($Element.ValueKind) {
        Object {
            $keys = [Collections.Generic.HashSet[string]]::new($ignoreCase)
            foreach ($property in $Element.EnumerateObject()) {
                if (!$keys.Add($property.Name)) { throw 'Duplicate JSON property in case data.' }
                Assert-PortableJsonProperty $property.Value
            }
        }
        Array {
            foreach ($value in $Element.EnumerateArray()) { Assert-PortableJsonProperty $value }
        }
    }
}

function ConvertFrom-PortableJson {
    param([string]$Text)

    $jsonOptions = [Text.Json.JsonDocumentOptions]::new()
    $jsonOptions.MaxDepth = 32
    $json = [Text.Json.JsonDocument]::Parse($Text, $jsonOptions)
    try { Assert-PortableJsonProperty $json.RootElement }
    finally { $json.Dispose() }
    return ConvertFrom-Json -InputObject $Text -AsHashtable -DateKind String -Depth 32 -NoEnumerate
}

function Get-PortableFileInventory {
    param([IO.DirectoryInfo]$Root)

    $files = [Collections.Generic.Dictionary[string, IO.FileInfo]]::new($ordinal)
    $seen = [Collections.Generic.HashSet[string]]::new($ignoreCase)
    $pending = [Collections.Generic.Stack[IO.DirectoryInfo]]::new()
    $pending.Push($Root)
    while ($pending.Count) {
        foreach ($item in (Get-ChildItem -LiteralPath $pending.Pop().FullName -Force)) {
            $relative = [IO.Path]::GetRelativePath($Root.FullName, $item.FullName).Replace([IO.Path]::DirectorySeparatorChar, '/')
            Assert-PortablePath $relative
            if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -or !$seen.Add($relative) -or $seen.Count -gt 8192) {
                throw "Link, case collision, or excessive entries at '$relative'."
            }
            if ($item -is [IO.DirectoryInfo]) {
                if ($relative -cnotin @('case', 'handoff') -and $relative -cnotlike 'case/*') {
                    throw "Unexpected directory '$relative'."
                }
                $pending.Push($item)
            }
            elseif ($item -is [IO.FileInfo]) {
                Assert-PortableRegularFile $item
                $files.Add($relative, $item)
            }
            else { throw "Unsupported entry '$relative'." }
        }
    }
    return $files
}

function Test-PortableSignature {
    param([IO.FileInfo]$Manifest, [IO.FileInfo]$Signature, [string]$PublicKeyPath)

    if (!$PublicKeyPath) {
        return $(if ($Signature) { 'SignaturePresentUnverified' } else { 'Unsigned' })
    }
    if (!$Signature -or $Signature.Length -gt 1024) { throw 'A detached signature is required with a trusted public key.' }
    $publicKey = Get-PortableLocalItem $PublicKeyPath
    if ($publicKey -isnot [IO.FileInfo] -or $publicKey.Length -gt 16KB) { throw 'Supply a trusted RSA public key in PEM format.' }
    Assert-PortableRegularFile $publicKey
    $rsa = [Security.Cryptography.RSA]::Create()
    try {
        $pem = [IO.File]::ReadAllText($publicKey.FullName)
        if ($pem -notmatch '\A\s*-----BEGIN (?:RSA )?PUBLIC KEY-----' -or $pem -match 'PRIVATE KEY') {
            throw 'Supply a trusted RSA public key in PEM format.'
        }
        $rsa.ImportFromPem($pem)
        if ($rsa.KeySize -lt 2048 -or !$rsa.VerifyData([IO.File]::ReadAllBytes($Manifest.FullName),
                [IO.File]::ReadAllBytes($Signature.FullName), [Security.Cryptography.HashAlgorithmName]::SHA256,
                [Security.Cryptography.RSASignaturePadding]::Pss)) {
            throw 'The detached signature did not validate with the supplied public key.'
        }
    }
    finally { $rsa.Dispose() }
    return 'VerifiedWithSuppliedKey'
}

function Read-PortableActionJournal {
    param([IO.FileInfo]$Log, [System.Collections.IDictionary]$Native)

    $sequence = 0L
    $previous = $zeroHash
    $timeline = [Collections.Generic.List[object]]::new()
    $lines = (Read-PortableText $Log 32MB).Split([char]10)
    foreach ($line in $lines) {
        if ([string]::IsNullOrWhiteSpace($line)) { continue }
        $sequence++
        $entry = ConvertFrom-PortableJson $line
        if ($entry -isnot [System.Collections.IDictionary] -or $entry['Sequence'] -isnot [long] -or
            $entry['Sequence'] -ne $sequence -or $entry['PreviousHash'] -cne $previous -or
            $entry['TimestampUtc'] -isnot [string] -or $entry['Action'] -isnot [string] -or $entry['Status'] -isnot [string]) {
            throw "Invalid action journal sequence or linkage at entry $sequence."
        }
        $payload = [ordered]@{
            Sequence = $sequence
            TimestampUtc = [string]$entry['TimestampUtc']
            Status = [string]$entry['Status']
            Action = [string]$entry['Action']
            Target = [string]$entry['Target']
            Investigator = [string]$entry['Investigator']
            Mode = [string]$entry['Mode']
            Details = $entry['Details']
            PreviousHash = $previous
        }
        $previous = Get-PortableTextHash ($payload | ConvertTo-Json -Depth 30 -Compress)
        if ($entry['EntryHash'] -cne $previous) { throw "Action journal digest mismatch at entry $sequence." }
        $timeline.Add([pscustomobject]@{ Source = 'case/action_log.jsonl'; Record = $sequence; TimestampUtc = $payload.TimestampUtc; Event = $payload.Action; Status = $payload.Status })
    }
    if (!$sequence -or $Native['ActionLogChainValid'] -isnot [bool] -or !$Native['ActionLogChainValid'] -or
        $Native['ActionLogEntries'] -ne $sequence -or $Native['ActionLogFinalHash'] -cne $previous) {
        throw 'Action journal count or terminal hash differs from the original evidence manifest.'
    }
    return $timeline.ToArray()
}

function Read-PortableHandoffJournal {
    param([IO.FileInfo]$File, [System.Collections.IDictionary]$Anchor, [string]$CaseDigest, [System.Collections.IDictionary]$Artifacts)

    if (!$Anchor -or $Anchor['Count'] -isnot [long] -or $Anchor['Head'] -cnotmatch '\A[A-F0-9]{64}\z') {
        throw 'A valid handoff count and terminal hash are required.'
    }
    if (!$File) {
        if ($Anchor['Count'] -ne 0 -or $Anchor['Head'] -cne $zeroHash) { throw 'The anchored handoff history is missing.' }
        return
    }
    $journal = ConvertFrom-PortableJson (Read-PortableText $File 4MB)
    $events = $journal['Events']
    if ($journal['Schema'] -cne 'm365-ir-case-handoff/v1' -or $events -isnot [array] -or
        $events.Count -lt 1 -or $events.Count -gt 512 -or $events.Count -ne $Anchor['Count']) {
        throw 'Invalid handoff schema or event count.'
    }
    $previous = $zeroHash
    $pending = $null
    $assignments = [Collections.Generic.HashSet[string]]::new($ordinal)
    foreach ($entry in $events) {
        $payload = $entry['Payload']
        $hash = Get-PortableTextHash ($payload | ConvertTo-Json -Depth 8 -Compress)
        $assignment = $payload['AssignmentId']
        $recordedAt = [datetime]::MinValue
        if ($entry['Hash'] -cne $hash -or $payload['PreviousHash'] -cne $previous -or
            $payload['CaseDigest'] -cne $CaseDigest -or $payload['IdentitySource'] -cne 'Operator-entered' -or
            $assignment -cnotmatch '\A[a-f0-9]{32}\z' -or $payload['EvidenceReferences'] -isnot [array] -or
            $payload['Investigator'] -isnot [string] -or $payload['Recipient'] -isnot [string] -or
            $payload['Decision'] -isnot [string] -or $payload['TimestampUtc'] -isnot [string] -or
            [string]::IsNullOrWhiteSpace($payload['Investigator']) -or [string]::IsNullOrWhiteSpace($payload['Recipient']) -or
            [string]::IsNullOrWhiteSpace($payload['Decision']) -or
            ![datetime]::TryParseExact($payload['TimestampUtc'], 'o', [Globalization.CultureInfo]::InvariantCulture,
                [Globalization.DateTimeStyles]::RoundtripKind, [ref]$recordedAt) -or $recordedAt.Kind -ne 'Utc') {
            throw 'Handoff event fields, digest, or case binding are invalid.'
        }
        foreach ($reference in $payload['EvidenceReferences']) {
            if ($reference -isnot [string] -or !$Artifacts.Contains("case/$reference")) {
                throw 'A handoff evidence reference is absent from the portable inventory.'
            }
        }
        if ($payload['Event'] -ceq 'Assigned') {
            $expectedReplacement = if ($pending) { $pending['AssignmentId'] } else { '' }
            if ($payload['ReplacesAssignmentId'] -cne $expectedReplacement -or !$assignments.Add($assignment)) {
                throw 'Handoff journal assignment transition is invalid.'
            }
            $pending = $payload
        }
        elseif ($payload['Event'] -ceq 'Accepted' -and $pending -and
            $assignment -ceq $pending['AssignmentId'] -and $payload['Investigator'] -ieq $pending['Recipient'] -and
            $payload['Recipient'] -ceq $pending['Recipient'] -and $payload['Decision'] -ceq $pending['Decision'] -and
            $payload['ReplacesAssignmentId'] -ceq '') {
            $pending = $null
        }
        else { throw 'Handoff journal acceptance transition is invalid.' }
        $previous = $hash
    }
    if ($previous -cne $Anchor['Head']) { throw 'Handoff journal terminal hash differs from the portable manifest.' }
    return $events | ForEach-Object { [pscustomobject]$_['Payload'] }
}

$root = Get-PortableLocalItem $Path
if ($root -isnot [IO.DirectoryInfo] -or ($root.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
    throw 'Supply an extracted case directory that is a regular folder.'
}
$actual = Get-PortableFileInventory $root
$manifestFile = $actual['portable-case.json']
$manifest = ConvertFrom-PortableJson (Read-PortableText $manifestFile 4MB)
if ($manifest['Schema'] -cne 'm365-ir-portable-case/v1' -or $manifest['Synthetic'] -isnot [bool] -or
    $manifest['Files'] -isnot [array] -or $manifest['Coverage'] -isnot [array] -or !$manifest['Coverage'].Count) {
    throw 'Invalid portable case schema or required fields.'
}
$trust = Test-PortableSignature $manifestFile $actual['portable-case.sig'] $TrustedPublicKey
$expected = [ordered]@{}
foreach ($item in $manifest['Files']) {
    $relative = $item['Path']
    Assert-PortablePath $relative
    if (($relative -cnotmatch '\Acase/.+' -and $relative -cne 'handoff/events.json') -or $expected.Contains($relative) -or
        $item['Length'] -isnot [long] -or $item['Length'] -lt 0 -or $item['SHA256'] -cnotmatch '\A[a-f0-9]{64}\z') {
        throw "Invalid or duplicate inventory entry '$relative'."
    }
    $file = $actual[$relative]
    if (!$file -or $file.Length -ne $item['Length'] -or
        (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash.ToLowerInvariant() -cne $item['SHA256']) {
        throw "Missing or modified artifact '$relative'."
    }
    $expected.Add($relative, $item)
}
foreach ($name in $actual.Keys) {
    if ($name -cnotin @('portable-case.json', 'portable-case.sig') -and !$expected.Contains($name)) {
        throw "Unexpected artifact '$name'."
    }
}

$metadataText = Read-PortableText $actual['case/case_metadata.json'] 64KB
$metadata = ConvertFrom-PortableJson $metadataText
$native = ConvertFrom-PortableJson (Read-PortableText $actual['case/evidence_manifest.sha256.json'] 4MB)
if (!$manifest['CaseId'] -or $manifest['CaseId'] -isnot [string] -or $manifest['CaseId'] -cne $metadata['CaseId'] -or
    $manifest['CaseId'] -cne $native['CaseId'] -or $native['Schema'] -cne 'm365-ir-evidence-manifest/v1' -or
    $native['HashAlgorithm'] -cne 'SHA-256' -or $native['Files'] -isnot [array] -or $native['Files'].Count -ne $native['FileCount']) {
    throw 'Case metadata and the original evidence manifest do not match the portable manifest.'
}
$nativePaths = [Collections.Generic.HashSet[string]]::new($ordinal)
foreach ($item in $native['Files']) {
    $relative = [string]$item['RelativePath']
    Assert-PortablePath $relative
    $match = $expected["case/$relative"]
    if ($relative -cin @('evidence_manifest.sha256.json', 'evidence_manifest.sha256.csv') -or
        !$nativePaths.Add($relative) -or !$match -or !$actual.ContainsKey("case/$relative") -or
        $match['Length'] -ne $item['Length'] -or $match['SHA256'] -cne $item['SHA256']) {
        throw "Original evidence inventory differs at '$relative'."
    }
}
foreach ($name in @($expected.Keys | Where-Object { $_ -clike 'case/*' })) {
    $relative = $name.Substring(5)
    if ($relative -cnotin @('evidence_manifest.sha256.json', 'evidence_manifest.sha256.csv') -and !$nativePaths.Contains($relative)) {
        throw "Artifact '$name' is absent from the original evidence manifest."
    }
}
foreach ($coverage in $manifest['Coverage']) {
    if ($coverage['Source'] -isnot [string] -or [string]::IsNullOrWhiteSpace($coverage['Source']) -or
        $coverage['Status'] -cnotin @('Completed', 'Partial', 'Unavailable', 'Failed', 'NotRun', 'Unknown') -or
        $coverage['Evidence'] -isnot [array]) {
        throw 'Invalid collection coverage record.'
    }
    foreach ($reference in $coverage['Evidence']) {
        if ($reference -isnot [string] -or !$expected.Contains($reference) -or !$actual.ContainsKey($reference)) {
            throw 'A collection coverage reference is absent from the inventory.'
        }
    }
}

[pscustomobject]@{
    CaseId = $manifest['CaseId']
    Synthetic = $manifest['Synthetic']
    Integrity = 'InternallyConsistent'
    Signature = $trust
    ArtifactCount = $expected.Count
    Coverage = $manifest['Coverage']
    Timeline = @(Read-PortableActionJournal $actual['case/action_log.jsonl'] $native)
    HandoffHistory = @(Read-PortableHandoffJournal $actual['handoff/events.json'] $manifest['Handoff'] (Get-PortableTextHash $metadataText) $expected)
}
