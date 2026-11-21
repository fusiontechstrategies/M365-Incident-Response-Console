BeforeAll {
    $script:Verifier = Join-Path $PSScriptRoot '../scripts/Test-PortableCase.ps1'
    $script:Exporter = Join-Path $PSScriptRoot '../scripts/New-PortableCase.ps1'
    $script:Example = Join-Path $PSScriptRoot '../examples/New-SyntheticPortableCase.ps1'
    $script:Console = Join-Path $PSScriptRoot '../M365-IR-Console.ps1'
    function script:Read-Inventory {
        Get-Content -LiteralPath (Join-Path $script:Fixture 'portable-case.json') -Raw |
            ConvertFrom-Json -AsHashtable -DateKind String
    }
    function script:Write-Inventory($Inventory) {
        $Inventory | ConvertTo-Json -Depth 24 -Compress |
            Set-Content -LiteralPath (Join-Path $script:Fixture 'portable-case.json') -Encoding utf8
    }
}

Describe 'Portable case format' {
    BeforeEach {
        $script:Fixture = Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))
        $null = & $script:Example -Destination $script:Fixture
    }

    It 'reproduces the same inventory and shows the native timeline, handoff and coverage' {
        $second = Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))
        $null = & $script:Example -Destination $second
        foreach ($item in (Get-ChildItem -LiteralPath $second -File -Recurse)) {
            $relative = [IO.Path]::GetRelativePath($second, $item.FullName)
            (Get-FileHash -LiteralPath $item.FullName).Hash |
                Should -BeExactly (Get-FileHash -LiteralPath (Join-Path $script:Fixture $relative)).Hash
        }
        $result = & $script:Verifier -Path $script:Fixture
        $result.Integrity | Should -BeExactly 'InternallyConsistent'
        $result.Signature | Should -BeExactly 'Unsigned'
        $result.Synthetic | Should -BeTrue
        $result.Coverage[1].Status | Should -BeExactly 'NotRun'
        $result.Timeline[0].Event | Should -BeExactly 'Inspect synthetic mailbox'
        $result.HandoffHistory[0].Recipient | Should -BeExactly 'Sam'
    }

    It 'rejects changed, missing and unlisted artifacts' {
        $item = Join-Path $script:Fixture 'case/mailbox.txt'
        $original = [IO.File]::ReadAllBytes($item)
        Add-Content -LiteralPath $item -Value 'changed'
        { & $script:Verifier -Path $script:Fixture } | Should -Throw '*Missing or modified artifact*'
        Remove-Item -LiteralPath $item
        { & $script:Verifier -Path $script:Fixture } | Should -Throw '*Missing or modified artifact*'
        [IO.File]::WriteAllBytes($item, $original)
        'extra' | Set-Content -LiteralPath (Join-Path $script:Fixture 'case/unlisted.txt')
        { & $script:Verifier -Path $script:Fixture } | Should -Throw '*Unexpected artifact*'
    }

    It 'rejects path traversal, portable name collisions, and duplicate JSON properties' {
        $inventory = Read-Inventory
        $inventory.Files += @{ Path = 'case/MAILBOX.txt'; Length = 0; SHA256 = '0' * 64 }
        Write-Inventory $inventory
        { & $script:Verifier -Path $script:Fixture } | Should -Throw '*duplicate inventory entry*'
        $inventory.Files[-1].Path = 'case/../secret.txt'
        Write-Inventory $inventory
        { & $script:Verifier -Path $script:Fixture } | Should -Throw '*Unsafe portable path*'
        $manifestPath = Join-Path $script:Fixture 'portable-case.json'
        $text = [IO.File]::ReadAllText($manifestPath).Replace('"Synthetic":true','"Synthetic":true,"synthetic":true')
        [IO.File]::WriteAllText($manifestPath, $text)
        { & $script:Verifier -Path $script:Fixture } | Should -Throw '*Duplicate JSON property*'
    }

    It 'rejects directory links instead of following them' {
        $target = Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))
        $null = New-Item -ItemType Directory -Path $target
        $linkType = if ($IsWindows) { 'Junction' } else { 'SymbolicLink' }
        $null = New-Item -ItemType $linkType -Path (Join-Path $script:Fixture 'case/link') -Target $target
        { & $script:Verifier -Path $script:Fixture } | Should -Throw '*Link, case collision*'
    }

    It 'rejects a linked ancestor of the verifier root or export destination' {
        $root = Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))
        $physical = Join-Path $root 'physical'
        $child = Join-Path $physical 'child'
        $null = New-Item -ItemType Directory -Path $child
        $link = Join-Path $root 'alias'
        $linkType = if ($IsWindows) { 'Junction' } else { 'SymbolicLink' }
        $null = New-Item -ItemType $linkType -Path $link -Target $physical
        { & $script:Verifier -Path (Join-Path $link 'child') } | Should -Throw '*Linked path component*'
        $destination = Join-Path $link 'child/export'
        { & $script:Exporter -CasePath (Join-Path $script:Fixture 'case') -Destination $destination } |
            Should -Throw '*requires regular files and directories*'
        Test-Path -LiteralPath (Join-Path $child 'export') | Should -BeFalse
    }

    It 'rejects named pipes before reading evidence' -Skip:$IsWindows {
        $pipe = Join-Path $script:Fixture 'case/unlisted.pipe'
        mkfifo $pipe
        $LASTEXITCODE | Should -Be 0
        { & $script:Verifier -Path $script:Fixture } | Should -Throw '*Unsupported file type*'
    }

    It 'checks the native action anchor even if the modified manifest is rehashed' {
        $inventory = Read-Inventory
        $nativePath = Join-Path $script:Fixture 'case/evidence_manifest.sha256.json'
        $native = Get-Content -LiteralPath $nativePath -Raw | ConvertFrom-Json -AsHashtable -DateKind String
        $native.ActionLogFinalHash = 'F' * 64
        $native | ConvertTo-Json -Depth 12 -Compress | Set-Content -LiteralPath $nativePath
        $row = $inventory.Files | Where-Object Path -CEQ 'case/evidence_manifest.sha256.json'
        $row.SHA256 = (Get-FileHash -LiteralPath $nativePath).Hash.ToLowerInvariant()
        $row.Length = (Get-Item -LiteralPath $nativePath).Length
        Write-Inventory $inventory
        { & $script:Verifier -Path $script:Fixture } | Should -Throw '*Action journal count or terminal hash*'
    }

    It 'rejects a removed handoff journal when its anchor is still present' {
        $inventory = Read-Inventory
        $inventory.Files = @($inventory.Files | Where-Object Path -CNE 'handoff/events.json')
        Remove-Item -LiteralPath (Join-Path $script:Fixture 'handoff/events.json')
        Write-Inventory $inventory
        { & $script:Verifier -Path $script:Fixture } | Should -Throw '*anchored handoff history is missing*'
    }

    It 'rejects a correctly rehashed handoff with a malformed UTC timestamp' {
        $inventory = Read-Inventory
        $path = Join-Path $script:Fixture 'handoff/events.json'
        $journal = Get-Content -LiteralPath $path -Raw | ConvertFrom-Json -AsHashtable -DateKind String
        $event = $journal.Events[0]
        $event.Payload.TimestampUtc = '2026-01-15'
        $text = $event.Payload | ConvertTo-Json -Depth 8 -Compress
        $event.Hash = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData([Text.Encoding]::UTF8.GetBytes($text)))
        $journal | ConvertTo-Json -Depth 12 -Compress | Set-Content -LiteralPath $path
        $row = $inventory.Files | Where-Object Path -CEQ 'handoff/events.json'
        $row.SHA256 = (Get-FileHash -LiteralPath $path).Hash.ToLowerInvariant()
        $row.Length = (Get-Item -LiteralPath $path).Length
        $inventory.Handoff.Head = $event.Hash
        Write-Inventory $inventory
        { & $script:Verifier -Path $script:Fixture } | Should -Throw '*Handoff event fields*'
    }

    It 'distinguishes verified signatures from unsigned or untrusted packages' {
        $keyPath = Join-Path $TestDrive ([guid]::NewGuid().ToString('N') + '.pem')
        $manifestPath = Join-Path $script:Fixture 'portable-case.json'
        $signaturePath = Join-Path $script:Fixture 'portable-case.sig'
        $key = [Security.Cryptography.RSA]::Create(2048)
        try {
            [IO.File]::WriteAllText($keyPath,$key.ExportSubjectPublicKeyInfoPem())
            $signature = $key.SignData([IO.File]::ReadAllBytes($manifestPath),
                [Security.Cryptography.HashAlgorithmName]::SHA256, [Security.Cryptography.RSASignaturePadding]::Pss)
            [IO.File]::WriteAllBytes($signaturePath,$signature)
        }
        finally { $key.Dispose() }
        (& $script:Verifier -Path $script:Fixture).Signature | Should -BeExactly 'SignaturePresentUnverified'
        (& $script:Verifier -Path $script:Fixture -TrustedPublicKey $keyPath).Signature | Should -BeExactly 'VerifiedWithSuppliedKey'
        $inventory = Read-Inventory
        $inventory.Coverage[1].Status = 'Completed'
        Write-Inventory $inventory
        { & $script:Verifier -Path $script:Fixture -TrustedPublicKey $keyPath } | Should -Throw '*did not validate*'
    }

    It 'exports the native case with its sibling handoff snapshot and defaults coverage to unknown' {
        $root = Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))
        $caseId = 'IR-SYNTHETIC-PORTABLE-001'
        $source = Join-Path $root $caseId
        $handoff = Join-Path (Join-Path $root '.handoffs') $caseId
        $null = New-Item -ItemType Directory -Path $source,$handoff
        Get-ChildItem -LiteralPath (Join-Path $script:Fixture 'case') -File |
            Copy-Item -Destination $source
        Copy-Item -LiteralPath (Join-Path $script:Fixture 'handoff/events.json') -Destination $handoff
        $destination = Join-Path $root 'portable'
        $null = & $script:Exporter -CasePath $source -Destination $destination -Synthetic
        $result = & $script:Verifier -Path $destination
        $result.ArtifactCount | Should -Be 5
        $result.HandoffHistory[0].Recipient | Should -BeExactly 'Sam'
        $result.Coverage[0].Status | Should -BeExactly 'Unknown'
    }

    It 'verifies a native console case with a recorded assignment and acceptance' {
        $root = Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))
        . $script:Console -OutputRoot $root -NoAutoConnect -SkipPreflight
        $nativeCase = Initialize-IRCase -CaseId 'IR-Portable-Native' -Confirm:$false
        'Synthetic evidence written by the production smoke test' | Set-Content -LiteralPath (Join-Path $nativeCase 'case-note.txt')
        $null = Add-IRActionLog -Action 'Collect case note' -Status Read -Target 'case-note.txt' -Details @{
            Evidence = @([ordered]@{ File = 'case-note.txt'; Record = 1 })
        }
        $null = New-IREvidenceManifest -Confirm:$false
        $request = @{ CaseId = 'IR-Portable-Native'; Operation = 'Assign'; Investigator = 'Alex'; Recipient = 'Sam'; Decision = 'Read case note'; Evidence = 'case-note.txt' }
        $assignment = Set-IRCaseHandoff @request -Confirm:$false
        $acceptance = @{ CaseId = 'IR-Portable-Native'; Operation = 'Accept'; Investigator = 'Sam'; AssignmentId = $assignment.Current.AssignmentId }
        $null = Set-IRCaseHandoff @acceptance -Confirm:$false
        $destination = Join-Path $root 'portable'
        $null = & $script:Exporter -CasePath $nativeCase -Destination $destination -Synthetic
        $result = & $script:Verifier -Path $destination
        $result.HandoffHistory[-1].Event | Should -BeExactly 'Accepted'
        $result.Timeline.Event | Should -Contain 'Collect case note'
    }
}
