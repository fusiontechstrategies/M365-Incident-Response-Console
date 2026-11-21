BeforeAll {
    $script:DefenderConsole = Join-Path $PSScriptRoot '../M365-IR-Console.ps1'
    $script:DefenderFixture = Join-Path $PSScriptRoot '../examples/synthetic-defender-incident.json'
    $script:DefenderTenant = [guid]'11111111-1111-1111-1111-111111111111'
    $script:DefenderMailbox = 'analyst@contoso.example'

    function script:Invoke-MgGraphRequest {
        [CmdletBinding()]
        param([string]$Method, [string]$Uri, [string]$OutputType)
        throw 'Tests must mock the Graph request.'
    }
}

Describe 'Defender incident case intake' {
    BeforeEach {
        $script:IntakeOutput = Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))
        . $script:DefenderConsole -OutputRoot $script:IntakeOutput
        $script:IR.Interactive = $false
        $script:Intake = @{ IncidentId = '42'; SourceTenantId = $script:DefenderTenant; MailboxUpn = $script:DefenderMailbox }
        $script:GraphContext = @{
            TenantId = $script:DefenderTenant.ToString()
            AuthType = 'Delegated'
            Environment = 'Global'
            Scopes = @('SecurityIncident.Read.All')
        }
        $script:IncidentResponse = @{
            id = '42'
            tenantId = $script:DefenderTenant.ToString()
            displayName = '<script>synthetic title</script>'
            status = 'active'
            createdDateTime = '2026-01-15T13:00:00Z'
            lastUpdateDateTime = '2026-01-15T13:15:00Z'
            incidentWebUrl = 'javascript:alert(1)'
            'alerts@odata.nextLink' = 'https://untrusted.example.invalid/next'
        }
        Mock Connect-IRGraph {
            $script:IR.TenantId = $script:GraphContext.TenantId
            return $script:GraphContext
        }
        Mock Invoke-MgGraphRequest { $script:IncidentResponse | ConvertTo-Json -Compress }
    }

    It 'creates a synthetic case through the script entry point and seals exact evidence' {
        $result = & $script:DefenderConsole -OutputRoot $script:IntakeOutput -NoAutoConnect `
            -TenantId $script:DefenderTenant -UserPrincipalName $script:DefenderMailbox `
            -DefenderIncidentId 42 -DefenderFixturePath $script:DefenderFixture
        $result.Status | Should -BeExactly 'Imported'
        $result.Synthetic | Should -BeTrue
        $evidence = Get-Content -LiteralPath $result.EvidencePath -Raw | ConvertFrom-Json -DateKind String
        $evidence.SourceTenantId | Should -BeExactly $script:DefenderTenant.ToString()
        $evidence.Incident.createdDateTime | Should -BeExactly '2026-01-15T13:00:00Z'
        Get-Content -LiteralPath $result.ReportPath -Raw | Should -Match 'Synthetic fixture. No Microsoft 365 data was collected.'
        $script:IR.CasePath = $result.CasePath
        $script:IR.CaseId = $result.CaseId
        (Test-IREvidenceManifest -ManifestPath $result.ManifestPath).IsValid | Should -BeTrue
        Add-Content -LiteralPath $result.EvidencePath -Value 'changed'
        (Test-IREvidenceManifest -ManifestPath $result.ManifestPath).IsValid | Should -BeFalse
        Should -Invoke Connect-IRGraph -Times 0 -Exactly
        Should -Invoke Invoke-MgGraphRequest -Times 0 -Exactly
    }

    It 'makes only the bound read request and treats returned HTML and URLs as data' {
        $result = New-IRDefenderIncidentCase @script:Intake -Confirm:$false
        $result.Synthetic | Should -BeFalse
        $html = Get-Content -LiteralPath $result.ReportPath -Raw
        $html | Should -Match '&lt;script&gt;synthetic title&lt;/script&gt;'
        $html | Should -Not -Match '<script>|href="javascript:'
        $html | Should -Match 'Alert evidence was not collected'
        $html | Should -Match 'still require separate collection'
        $html | Should -Not -Match '0 OAuth grants|0 rules|0 coverage errors'
        $regenerated = New-IRCaseReport
        $regeneratedHtml = Get-Content -LiteralPath $regenerated -Raw
        $regeneratedHtml | Should -Match 'Alert evidence was not collected'
        $regeneratedHtml | Should -Match 'Its relationship to the incident was not verified'
        Should -Invoke Connect-IRGraph -Times 1 -Exactly -ParameterFilter {
            $Scopes.Count -eq 1 -and $Scopes[0] -eq 'SecurityIncident.Read.All' -and $Modules.Count -eq 0
        }
        Should -Invoke Invoke-MgGraphRequest -Times 1 -Exactly
        Should -Invoke Invoke-MgGraphRequest -Times 1 -Exactly -ParameterFilter {
            $Method -ceq 'GET' -and $Uri -ceq 'https://graph.microsoft.com/v1.0/security/incidents/42' -and $OutputType -ceq 'Json'
        }
    }

    It 'refuses an invalid Graph context before making any request' -TestCases @(
        @{ Field = 'TenantId'; Value = '22222222-2222-2222-2222-222222222222' }
        @{ Field = 'AuthType'; Value = 'AppOnly' }
        @{ Field = 'Environment'; Value = 'USGov' }
        @{ Field = 'Scopes'; Value = @('SecurityIncident.Read.All', 'SecurityIncident.ReadWrite.All') }
    ) {
        param($Field, $Value)
        $script:GraphContext[$Field] = $Value
        { New-IRDefenderIncidentCase @script:Intake -Confirm:$false } | Should -Throw '*delegated Microsoft Graph Global context*'
        Should -Invoke Invoke-MgGraphRequest -Times 0 -Exactly
        Test-Path -LiteralPath $script:IntakeOutput | Should -BeFalse
    }

    It 'refuses a response with a mismatched source tenant or ID' -TestCases @(
        @{ Field = 'tenantId'; Value = '22222222-2222-2222-2222-222222222222'; ExpectedError = '*did not match the requested source tenant*' }
        @{ Field = 'id'; Value = '43'; ExpectedError = '*did not exactly match the requested ID*' }
    ) {
        param($Field, $Value, $ExpectedError)
        $script:IncidentResponse[$Field] = $Value
        { New-IRDefenderIncidentCase @script:Intake -Confirm:$false } | Should -Throw $ExpectedError
        Test-Path -LiteralPath $script:IntakeOutput | Should -BeFalse
    }

    It 'seals a visibly unavailable case when the incident request fails' {
        Mock Invoke-MgGraphRequest { throw 'Permission denied by mock.' }
        $result = New-IRDefenderIncidentCase @script:Intake -Confirm:$false
        $result.Status | Should -BeExactly 'Unavailable'
        $evidence = Get-Content -LiteralPath $result.EvidencePath -Raw | ConvertFrom-Json
        $evidence.Incident | Should -BeNullOrEmpty
        $evidence.Limitation | Should -Match 'incident request did not complete'
        (Test-IREvidenceManifest -ManifestPath $result.ManifestPath).IsValid | Should -BeTrue
    }

    It 'never falls back to Graph when a fixture path is empty or lacks the Boolean synthetic marker' {
        $fixture = Join-Path $TestDrive 'invalid-fixture.json'
        '{"schema":"m365-ir-defender-fixture/v1","synthetic":"true","incident":{}}' | Set-Content -LiteralPath $fixture
        { New-IRDefenderIncidentCase @script:Intake -FixturePath $fixture -Confirm:$false } | Should -Throw '*Boolean synthetic set to true*'
        { New-IRDefenderIncidentCase @script:Intake -FixturePath ' ' -Confirm:$false } | Should -Throw '*local Defender fixture path*'
        Should -Invoke Connect-IRGraph -Times 0 -Exactly
        Test-Path -LiteralPath $script:IntakeOutput | Should -BeFalse
    }

    It 'rejects incident IDs that can alter the request path' {
        $script:Intake.IncidentId = '42?redirect=1'
        { New-IRDefenderIncidentCase @script:Intake -Confirm:$false } | Should -Throw
        Should -Invoke Connect-IRGraph -Times 0 -Exactly
    }
}
