BeforeAll {
    $script:ScriptUnderTest = Join-Path -Path $PSScriptRoot -ChildPath '..\M365-IR-Console.ps1'
    $script:CaseOutputRoot = Join-Path -Path $TestDrive -ChildPath 'cases'
    . $script:ScriptUnderTest -OutputRoot $script:CaseOutputRoot -NoAutoConnect -SkipPreflight
    $script:IR.Interactive = $false

    function script:Get-MgContext { [CmdletBinding()] param() }
    function script:Connect-MgGraph {
        [CmdletBinding()]
        param(
            [string[]]$Scopes,
            [string]$ContextScope,
            [switch]$NoWelcome,
            [switch]$UseDeviceCode,
            [string]$TenantId
        )
    }
    function script:Disconnect-MgGraph { [CmdletBinding()] param() }

    function script:Get-MessageTraceV2 {
        [CmdletBinding()]
        param(
            [datetime]$StartDate,
            [datetime]$EndDate,
            [int]$ResultSize,
            [string]$SenderAddress,
            [string]$RecipientAddress,
            [string]$StartingRecipientAddress
        )
    }

    function script:Search-UnifiedAuditLog {
        [CmdletBinding()]
        param(
            [datetime]$StartDate,
            [datetime]$EndDate,
            [string]$SessionId,
            [string]$SessionCommand,
            [int]$ResultSize,
            [string[]]$UserIds,
            [string[]]$Operations,
            [string]$RecordType
        )
    }

    function script:Reset-IRTestState {
        $script:IR.Mode = 'Audit'
        $script:IR.CaseId = $null
        $script:IR.CasePath = $null
        $script:IR.Investigator = $null
        $script:IR.ActionLog.Clear()
        $script:IR.ActionSequence = 0L
        $script:IR.LastActionHash = '0' * 64
        $script:IR.Results.Clear()
        $script:IR.GraphBroadConsentAcknowledged = $false
        $script:IR.UseDeviceAuthentication = $false
        foreach ($key in @($script:IR.Connections.Keys)) {
            $script:IR.Connections[$key] = $false
        }
    }

    function script:New-IRTestCase {
        Reset-IRTestState
        $caseId = 'Pester-{0}' -f [guid]::NewGuid().ToString('N')
        return Initialize-IRCase -CaseId $caseId -ForceNew -Confirm:$false
    }
}

Describe 'M365 Incident Response Console' {
    BeforeEach {
        Reset-IRTestState
    }

Describe 'Parser and static safety gates' {
    It 'parses without errors' {
        $tokens = $null
        $errors = $null
        [void][System.Management.Automation.Language.Parser]::ParseFile(
            $script:ScriptUnderTest,
            [ref]$tokens,
            [ref]$errors
        )
        @($errors).Count | Should -Be 0
    }

    It 'does not contain Invoke-Expression or the retired purge command' {
        $tokens = $null
        $errors = $null
        $ast = [System.Management.Automation.Language.Parser]::ParseFile(
            $script:ScriptUnderTest,
            [ref]$tokens,
            [ref]$errors
        )
        $commands = @($ast.FindAll({
            param($node)
            $node -is [System.Management.Automation.Language.CommandAst]
        }, $true) | ForEach-Object { $_.GetCommandName() })
        $commands | Should -Not -Contain 'Invoke-Expression'
        $commands | Should -Not -Contain 'New-ComplianceSearchAction'
    }

    It 'keeps public Markdown free of em dashes' {
        $repositoryRoot = Split-Path -Path $script:ScriptUnderTest -Parent
        $violations = @(Get-ChildItem -LiteralPath $repositoryRoot -Recurse -File -Filter '*.md' |
            Where-Object {
                [System.IO.File]::ReadAllText($_.FullName).Contains([char]0x2014)
            } |
            ForEach-Object {
                [System.IO.Path]::GetRelativePath($repositoryRoot, $_.FullName)
            })

        $violations | Should -BeNullOrEmpty
    }

    It 'orders Exchange-backed authentication and collection before Graph' {
        $tokens = $null
        $errors = $null
        $ast = [System.Management.Automation.Language.Parser]::ParseFile(
            $script:ScriptUnderTest,
            [ref]$tokens,
            [ref]$errors
        )
        $functions = @($ast.FindAll({
            param($node)
            $node -is [System.Management.Automation.Language.FunctionDefinitionAst]
        }, $true))

        foreach ($name in @('Test-IRPreflight', 'Start-IRInteractiveConsole')) {
            $text = @($functions | Where-Object Name -eq $name | Select-Object -First 1).Extent.Text
            $text.IndexOf('Connect-IRExchange', [StringComparison]::Ordinal) |
                Should -BeLessThan $text.IndexOf('Connect-IRGraph', [StringComparison]::Ordinal)
        }

        $collectionText = @($functions | Where-Object Name -eq 'Invoke-IRComprehensiveCollection' | Select-Object -First 1).Extent.Text
        $collectionText.IndexOf("-Name 'Mailbox configuration'", [StringComparison]::Ordinal) |
            Should -BeLessThan $collectionText.IndexOf("-Name 'User profile'", [StringComparison]::Ordinal)
        $collectionText.IndexOf("-Name 'Threat and Defender'", [StringComparison]::Ordinal) |
            Should -BeLessThan $collectionText.IndexOf("-Name 'User profile'", [StringComparison]::Ordinal)
    }

    It 'requires exact confirmation on every production mutation gateway call' {
        $tokens = $null
        $errors = $null
        $ast = [System.Management.Automation.Language.Parser]::ParseFile(
            $script:ScriptUnderTest,
            [ref]$tokens,
            [ref]$errors
        )
        $calls = @($ast.FindAll({
            param($node)
            $node -is [System.Management.Automation.Language.CommandAst] -and
            $node.GetCommandName() -eq 'Invoke-IRChange'
        }, $true))
        $unguarded = @($calls | Where-Object {
            $_.Extent.Text -notmatch '(?i)-ExactConfirmation\b' -and
            $_.Extent.Text -notmatch "(?i)-Target\s+'self-test'"
        })
        $unguarded.Count | Should -Be 0
    }

    It 'places every direct cloud mutator inside a gateway-guarded function' {
        $cloudMutators = @(
            'Disable-App',
            'Disable-TransportRule',
            'New-ComplianceSearch',
            'New-MgIdentityConditionalAccessPolicy',
            'New-TransportRule',
            'Remove-ComplianceSearch',
            'Remove-InboxRule',
            'Remove-MailboxFolderPermission',
            'Remove-MailboxPermission',
            'Remove-MgDeviceManagementManagedDevice',
            'Remove-MgIdentityConditionalAccessPolicy',
            'Remove-MgOauth2PermissionGrant',
            'Remove-MgUserAppRoleAssignment',
            'Remove-MobileDevice',
            'Remove-RecipientPermission',
            'Revoke-MgUserSignInSession',
            'Send-MgUserMail',
            'Set-AntiPhishPolicy',
            'Set-CalendarProcessing',
            'Set-HostedContentFilterPolicy',
            'Set-Mailbox',
            'Start-ComplianceSearch',
            'Update-MgIdentityConditionalAccessPolicy',
            'Update-MgUser'
        )
        $tokens = $null
        $errors = $null
        $ast = [System.Management.Automation.Language.Parser]::ParseFile(
            $script:ScriptUnderTest,
            [ref]$tokens,
            [ref]$errors
        )
        $mutatorCalls = @($ast.FindAll({
            param($node)
            $node -is [System.Management.Automation.Language.CommandAst] -and
            $node.GetCommandName() -in $cloudMutators
        }, $true))
        $unguarded = [System.Collections.Generic.List[string]]::new()
        foreach ($call in $mutatorCalls) {
            $parent = $call.Parent
            while ($null -ne $parent -and $parent -isnot [System.Management.Automation.Language.FunctionDefinitionAst]) {
                $parent = $parent.Parent
            }
            if ($null -eq $parent) {
                $unguarded.Add($call.Extent.Text)
                continue
            }
            $gateway = @($parent.Body.FindAll({
                param($node)
                $node -is [System.Management.Automation.Language.CommandAst] -and
                $node.GetCommandName() -eq 'Invoke-IRChange'
            }, $true))
            if ($gateway.Count -eq 0) {
                $unguarded.Add("$($parent.Name): $($call.GetCommandName())")
            }
        }
        $unguarded.ToArray() | Should -BeNullOrEmpty
    }
}

Describe 'Public demo fixtures' {
    It 'keeps the sample machine-readable and explicitly synthetic' {
        $fixturePath = Join-Path -Path $PSScriptRoot -ChildPath '..\examples\sanitized-case-summary.json'
        $fixture = Get-Content -LiteralPath $fixturePath -Raw -Encoding utf8 |
            ConvertFrom-Json -Depth 20 -DateKind String

        $fixture.synthetic | Should -BeTrue
        $fixture.case.mode | Should -BeExactly 'Audit'
        $fixture.case.target | Should -Match '@[^.]+\.example$'
        $fixture.messageTrace.heuristicLeads[0].sourceIp | Should -BeExactly '192.0.2.44'
    }

    It 'labels the human-readable report as synthetic and non-evidence' {
        $reportPath = Join-Path -Path $PSScriptRoot -ChildPath '..\examples\sanitized-case-report.md'
        $report = Get-Content -LiteralPath $reportPath -Raw -Encoding utf8

        $report | Should -Match '(?i)synthetic preview'
        $report | Should -Match '(?i)not cryptographically verifiable evidence'
        $report | Should -Match 'analyst-test@contoso\.example'
    }
}

Describe 'Portable input and path handling' {
    It 'sanitizes portable invalid characters and reserved device names' {
        ConvertTo-IRSafeFileName -Value 'CON.txt' | Should -BeExactly '_CON.txt'
        ConvertTo-IRSafeFileName -Value '..\bad/name:*?' | Should -Not -Match '[\\/:*?]'
        ConvertTo-IRSafeFileName -Value 'report<draft>|final' | Should -BeExactly 'report_draft__final'
    }

    It 'accepts descendants and rejects sibling-prefix paths' {
        $root = Join-Path -Path $TestDrive -ChildPath 'root'
        Test-IRPathWithinRoot -Root $root -Candidate (Join-Path $root 'child\item.json') | Should -BeTrue
        Test-IRPathWithinRoot -Root $root -Candidate "$root-escape\item.json" | Should -BeFalse
    }

    It 'rejects case-path traversal' {
        $null = New-IRTestCase
        { Get-IRCasePath -ChildPath '../escape.txt' } | Should -Throw '*outside case directory*'
    }

    It 'restricts a newly created case directory to the current user' {
        $casePath = New-IRTestCase
        if ($IsWindows) {
            $acl = Get-Acl -LiteralPath $casePath
            $currentSid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
            $acl.AreAccessRulesProtected | Should -BeTrue
            $allowedSids = @($acl.Access | Where-Object AccessControlType -eq 'Allow' | ForEach-Object {
                try {
                    $_.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value
                }
                catch {
                    $_.IdentityReference.Value
                }
            })
            $allowedSids | Should -Contain $currentSid
            @($allowedSids | Where-Object { $_ -ne $currentSid }).Count | Should -Be 0
        }
        else {
            [int][System.IO.File]::GetUnixFileMode($casePath) | Should -Be 448
        }
    }

    It 'reads generic and read-only dictionary properties safely' {
        $dictionary = [System.Collections.Generic.Dictionary[string, object]]::new()
        $dictionary['@odata.type'] = '#microsoft.graph.phoneAuthenticationMethod'
        $readOnly = [System.Collections.ObjectModel.ReadOnlyDictionary[string, object]]::new($dictionary)
        Get-IRProperty -InputObject $readOnly -Name '@odata.type' | Should -BeExactly '#microsoft.graph.phoneAuthenticationMethod'
    }

    It 'builds valid Exchange mailbox-folder identities' {
        ConvertTo-IRMailboxFolderIdentity -UserPrincipalName 'user@example.com' -FolderPath '/Inbox/Child' | Should -BeExactly 'user@example.com:\Inbox\Child'
        ConvertTo-IRMailboxFolderIdentity -UserPrincipalName 'user@example.com' -FolderPath "/Projects$([char]0xF8FF)Federal" | Should -BeExactly 'user@example.com:\Projects/Federal'
        ConvertTo-IRMailboxFolderIdentity -UserPrincipalName 'user@example.com' -FolderPath '' -ReportedIdentity 'user@example.com\Calendar' | Should -BeExactly 'user@example.com:\Calendar'
    }
}

Describe 'Audit and live execution boundaries' {
    It 'does not execute a tenant operation in Audit mode' {
        $marker = [pscustomobject]@{ Executed = $false }
        $result = Invoke-IRChange -Target 'test' -Action 'test mutation' -Operation {
            $marker.Executed = $true
        } -Confirm:$false
        $result | Should -BeNullOrEmpty
        $marker.Executed | Should -BeFalse
        $script:IR.ActionLog[-1].Status | Should -BeExactly 'Planned'
    }

    It 'rejects a Live operation without an exact confirmation phrase' {
        $script:IR.Mode = 'Live'
        $marker = [pscustomobject]@{ Executed = $false }
        {
            Invoke-IRChange -Target 'test' -Action 'test mutation' -Operation {
                $marker.Executed = $true
            } -Confirm:$false
        } | Should -Throw '*exact-confirmation phrase*'
        $marker.Executed | Should -BeFalse
    }

    It 'does not prompt or execute when WhatIf declines the operation' {
        $script:IR.Mode = 'Live'
        $marker = [pscustomobject]@{ Executed = $false }
        Mock Read-Host { throw 'Read-Host must not run during WhatIf.' }
        $null = Invoke-IRChange -Target 'test' -Action 'test mutation' -ExactConfirmation 'CONFIRM' -Operation {
            $marker.Executed = $true
        } -WhatIf
        $marker.Executed | Should -BeFalse
        Should -Not -Invoke Read-Host
    }

    It 'blocks execution when exact confirmation does not match' {
        $script:IR.Mode = 'Live'
        $marker = [pscustomobject]@{ Executed = $false }
        Mock Read-Host { 'WRONG' }
        $null = Invoke-IRChange -Target 'test' -Action 'test mutation' -ExactConfirmation 'CONFIRM' -Operation {
            $marker.Executed = $true
        } -Confirm:$false
        $marker.Executed | Should -BeFalse
        $script:IR.ActionLog[-1].Status | Should -BeExactly 'Skipped'
    }

    It 'disconnects cached service sessions when returning to Audit mode' {
        $script:IR.Mode = 'Live'
        Mock Disconnect-IRService { }
        $result = Set-IRMode -NewMode Audit
        $result | Should -BeExactly 'Audit'
        Should -Invoke Disconnect-IRService -Times 1 -Exactly
    }

    It 'fails closed before execution when durable approval logging fails' {
        $script:IR.Mode = 'Live'
        $marker = [pscustomobject]@{ Executed = $false }
        Mock Read-Host { 'CONFIRM' }
        Mock Add-IRActionLog {
            if ($Status -eq 'Approved') { throw 'synthetic durable-log failure' }
        }
        {
            Invoke-IRChange -Target 'test' -Action 'test mutation' -ExactConfirmation 'CONFIRM' -Operation {
                $marker.Executed = $true
            } -Confirm:$false
        } | Should -Throw '*synthetic durable-log failure*'
        $marker.Executed | Should -BeFalse
    }

    It 'records Approved and Changed entries around a successful operation' {
        $null = New-IRTestCase
        $script:IR.Mode = 'Live'
        Mock Read-Host { 'CONFIRM' }
        $result = Invoke-IRChange -Target 'test' -Action 'test mutation' -ExactConfirmation 'CONFIRM' -Operation {
            return 42
        } -Confirm:$false
        $result | Should -Be 42
        $script:IR.ActionLog[-2].Status | Should -BeExactly 'Approved'
        $script:IR.ActionLog[-1].Status | Should -BeExactly 'Changed'
        (Test-IRActionLogChain).Valid | Should -BeTrue
    }

    It 'records an Error entry when the operation fails' {
        $null = New-IRTestCase
        $script:IR.Mode = 'Live'
        Mock Read-Host { 'CONFIRM' }
        {
            Invoke-IRChange -Target 'test' -Action 'test mutation' -ExactConfirmation 'CONFIRM' -Operation {
                throw 'synthetic operation failure'
            } -Confirm:$false
        } | Should -Throw '*synthetic operation failure*'
        $script:IR.ActionLog[-2].Status | Should -BeExactly 'Approved'
        $script:IR.ActionLog[-1].Status | Should -BeExactly 'Error'
        (Test-IRActionLogChain).Valid | Should -BeTrue
    }
}

Describe 'Graph scope safety' {
    It 'maps every reviewed write scope used by the script to a read-only scope' {
        $mapped = @(ConvertTo-IRAuditGraphScope -Scopes @(
            'User.RevokeSessions.All',
            'User-PasswordProfile.ReadWrite.All',
            'User.ReadWrite.All',
            'Policy.ReadWrite.ConditionalAccess',
            'Mail.Send',
            'DelegatedPermissionGrant.ReadWrite.All',
            'AppRoleAssignment.ReadWrite.All',
            'DeviceManagementManagedDevices.ReadWrite.All'
        ))
        @($mapped | Where-Object { Test-IRGraphWriteScope -Scope $_ }).Count | Should -Be 0
        $mapped | Should -Contain 'User.Read.All'
        $mapped | Should -Contain 'Policy.Read.All'
        $mapped | Should -Contain 'User.Read'
        $mapped | Should -Contain 'DelegatedPermissionGrant.Read.All'
        $mapped | Should -Contain 'AppRoleAssignment.Read.All'
        $mapped | Should -Contain 'DeviceManagementManagedDevices.Read.All'
    }

    It 'fails closed for an unreviewed write scope' {
        { ConvertTo-IRAuditGraphScope -Scopes @('Files.ReadWrite.All') } | Should -Throw '*no reviewed read-only replacement*'
    }

    It 'drops a cached write-capable Graph context when Audit mode connects' {
        $script:IR.Mode = 'Audit'
        $script:contextCalls = 0
        Mock Import-IRModule { [pscustomobject]@{ Name = $Name } }
        Mock Test-IRGraphConnected { $true }
        Mock Get-MgContext {
            $script:contextCalls++
            if ($script:contextCalls -eq 1) {
                return [pscustomobject]@{
                    Account = 'analyst@example.com'
                    TenantId = '11111111-1111-1111-1111-111111111111'
                    Scopes = @('User.Read.All', 'User.ReadWrite.All')
                }
            }
            return [pscustomobject]@{
                Account = 'analyst@example.com'
                TenantId = '11111111-1111-1111-1111-111111111111'
                Scopes = @('User.Read.All')
            }
        }
        Mock Disconnect-MgGraph { }
        Mock Connect-MgGraph { }

        $context = Connect-IRGraph -Scopes @('User.ReadWrite.All') -Modules @('Microsoft.Graph.Users')

        $context.Scopes | Should -Contain 'User.Read.All'
        $context.Scopes | Should -Not -Contain 'User.ReadWrite.All'
        Should -Invoke Disconnect-MgGraph -Times 1 -Exactly
        Should -Invoke Connect-MgGraph -Times 1 -Exactly -ParameterFilter {
            'User.Read.All' -in $Scopes -and 'User.ReadWrite.All' -notin $Scopes
        }
    }

    It 'does not reconnect repeatedly when the identity platform returns broader pre-consented scopes' {
        $script:IR.Mode = 'Audit'
        Mock Import-IRModule { [pscustomobject]@{ Name = $Name } }
        Mock Test-IRGraphConnected { $true }
        Mock Get-MgContext {
            [pscustomobject]@{
                Account = 'analyst@example.com'
                TenantId = '11111111-1111-1111-1111-111111111111'
                Scopes = @('User.ReadWrite.All')
            }
        }
        Mock Disconnect-MgGraph { }
        Mock Connect-MgGraph { }

        $first = Connect-IRGraph -Scopes @('User.Read.All') -Modules @('Microsoft.Graph.Users')
        $second = Connect-IRGraph -Scopes @('User.Read.All') -Modules @('Microsoft.Graph.Users')

        $first.Scopes | Should -Contain 'User.ReadWrite.All'
        $second.Scopes | Should -Contain 'User.ReadWrite.All'
        $script:IR.GraphBroadConsentAcknowledged | Should -BeTrue
        Should -Invoke Disconnect-MgGraph -Times 1 -Exactly
        Should -Invoke Connect-MgGraph -Times 1 -Exactly
    }

    It 'passes device-code authentication to Graph when requested' {
        $script:IR.Mode = 'Audit'
        $script:IR.UseDeviceAuthentication = $true
        Mock Import-IRModule { [pscustomobject]@{ Name = $Name } }
        Mock Test-IRGraphConnected { $false }
        Mock Connect-MgGraph { }
        Mock Get-MgContext {
            [pscustomobject]@{
                Account = 'analyst@example.com'
                TenantId = '11111111-1111-1111-1111-111111111111'
                Scopes = @('User.Read.All')
            }
        }

        $null = Connect-IRGraph -Scopes @('User.Read.All') -Modules @('Microsoft.Graph.Users')

        Should -Invoke Connect-MgGraph -Times 1 -Exactly -ParameterFilter { $UseDeviceCode }
    }

    It 'preserves an explicitly requested write scope in Live mode' {
        $script:IR.Mode = 'Live'
        Mock Import-IRModule { [pscustomobject]@{ Name = $Name } }
        Mock Test-IRGraphConnected { $false }
        Mock Connect-MgGraph { }
        Mock Get-MgContext {
            [pscustomobject]@{
                Account = 'analyst@example.com'
                TenantId = '11111111-1111-1111-1111-111111111111'
                Scopes = @('User.ReadWrite.All')
            }
        }

        $context = Connect-IRGraph -Scopes @('User.ReadWrite.All') -Modules @('Microsoft.Graph.Users')

        $context.Scopes | Should -Contain 'User.ReadWrite.All'
        Should -Invoke Connect-MgGraph -Times 1 -Exactly -ParameterFilter {
            'User.ReadWrite.All' -in $Scopes
        }
    }
}

Describe 'Retry and HTTP error handling' {
    It 'retries transient failures and eventually returns the result' {
        $script:attempt = 0
        Mock Start-Sleep { }
        $result = Invoke-IRRetry -MaximumAttempts 4 -Operation {
            $script:attempt++
            if ($script:attempt -lt 3) { throw 'HTTP 503 service unavailable' }
            return 'ok'
        }
        $result | Should -BeExactly 'ok'
        $script:attempt | Should -Be 3
        Should -Invoke Start-Sleep -Times 2 -Exactly
    }

    It 'does not retry a non-transient failure' {
        $script:attempt = 0
        Mock Start-Sleep { }
        {
            Invoke-IRRetry -MaximumAttempts 4 -Operation {
                $script:attempt++
                throw 'permission denied'
            }
        } | Should -Throw '*permission denied*'
        $script:attempt | Should -Be 1
        Should -Not -Invoke Start-Sleep
    }

    It 'retries a status-coded throttle even when the message omits 429' {
        $script:attempt = 0
        Mock Start-Sleep { }
        $result = Invoke-IRRetry -MaximumAttempts 3 -Operation {
            $script:attempt++
            if ($script:attempt -eq 1) {
                $exception = [System.Exception]::new('Request limit reached')
                $exception | Add-Member -NotePropertyName StatusCode -NotePropertyValue 429
                throw $exception
            }
            return 'recovered'
        }
        $result | Should -BeExactly 'recovered'
        $script:attempt | Should -Be 2
        Should -Invoke Start-Sleep -Times 1 -Exactly
    }

    It 'extracts Retry-After delta values' {
        $exception = [System.Exception]::new('HTTP 429')
        $exception | Add-Member -NotePropertyName Response -NotePropertyValue ([pscustomobject]@{
            Headers = [pscustomobject]@{
                RetryAfter = [pscustomobject]@{
                    Delta = [timespan]::FromSeconds(17)
                    Date = $null
                }
            }
        })
        $record = [System.Management.Automation.ErrorRecord]::new(
            $exception,
            'Synthetic429',
            [System.Management.Automation.ErrorCategory]::LimitsExceeded,
            $null
        )
        Get-IRRetryDelay -ErrorRecord $record | Should -Be 17
    }

    It 'recognizes a Graph not-found response as a valid not-listed condition' {
        $exception = [System.Exception]::new('Request_ResourceNotFound')
        $exception | Add-Member -NotePropertyName StatusCode -NotePropertyValue 404
        $record = [System.Management.Automation.ErrorRecord]::new(
            $exception,
            'Synthetic404',
            [System.Management.Automation.ErrorCategory]::ObjectNotFound,
            $null
        )
        Test-IRNotFoundError -ErrorRecord $record | Should -BeTrue
    }
}

Describe 'Service pagination and completeness markers' {
    BeforeEach {
        Mock Connect-IRExchange { }
        Mock Assert-IRCommand { }
    }

    It 'follows the documented message-trace cursor without duplicating rows' {
        $script:traceCall = 0
        $now = [datetime]::UtcNow
        Mock Get-MessageTraceV2 {
            $script:traceCall++
            if ($script:traceCall -eq 1) {
                return @(
                    [pscustomobject]@{
                        Received = $now.AddMinutes(-1)
                        SenderAddress = 'sender@example.com'
                        RecipientAddress = 'first@example.com'
                        Subject = 'first'
                        Status = 'Delivered'
                        Size = 100
                        MessageId = 'message-1'
                        MessageTraceId = '00000000-0000-0000-0000-000000000001'
                        FromIP = '192.0.2.10'
                        ToIP = '192.0.2.20'
                    },
                    [pscustomobject]@{
                        Received = $now.AddMinutes(-2)
                        SenderAddress = 'sender@example.com'
                        RecipientAddress = 'second@example.com'
                        Subject = 'second'
                        Status = 'Delivered'
                        Size = 200
                        MessageId = 'message-2'
                        MessageTraceId = '00000000-0000-0000-0000-000000000002'
                        FromIP = '192.0.2.10'
                        ToIP = '192.0.2.20'
                    }
                )
            }
            return @(
                [pscustomobject]@{
                    Received = $now.AddMinutes(-3)
                    SenderAddress = 'sender@example.com'
                    RecipientAddress = 'third@example.com'
                    Subject = 'third'
                    Status = 'Delivered'
                    Size = 300
                    MessageId = 'message-3'
                    MessageTraceId = '00000000-0000-0000-0000-000000000003'
                    FromIP = '192.0.2.10'
                    ToIP = '192.0.2.20'
                }
            )
        }

        $rows = @(Get-IRMessageTrace -UserPrincipalName 'sender@example.com' -Direction Sent -DaysBack 1 -PageSize 2)

        $rows.Count | Should -Be 3
        @($rows.MessageTraceId | Sort-Object -Unique).Count | Should -Be 3
        $script:IR.Results.MessageTraceMetadata.Queries | Should -Be 2
        $script:IR.Results.MessageTraceMetadata.Incomplete | Should -BeFalse
        Should -Invoke Get-MessageTraceV2 -Times 2 -Exactly
    }

    It 'stops repeated unified-audit pages and marks the result incomplete' {
        $script:auditCall = 0
        Mock Search-UnifiedAuditLog {
            $script:auditCall++
            return [pscustomobject]@{
                Identity = 'record-1'
                CreationDate = [datetime]::UtcNow
                RecordType = 'AzureActiveDirectory'
                Operations = 'UserLoggedIn'
                AuditData = '{}'
            }
        }

        $rows = @(Search-IRUnifiedAuditLog -UserIds 'user@example.com' -DaysBack 1 -PageSize 1 -MaximumResults 10)

        $rows.Count | Should -Be 1
        $script:IR.Results.UnifiedAuditMetadata.Pages | Should -Be 3
        $script:IR.Results.UnifiedAuditMetadata.Incomplete | Should -BeTrue
        Should -Invoke Search-UnifiedAuditLog -Times 3 -Exactly
    }
}

Describe 'Risk and audit analysis' {
    It 'classifies public, private, mapped, and special-use addresses' -ForEach @(
        @{ Address = '8.8.8.8'; Expected = 'PublicIPv4' },
        @{ Address = '10.0.0.1'; Expected = 'PrivateIPv4' },
        @{ Address = '100.64.0.1'; Expected = 'CarrierGradeNATIPv4' },
        @{ Address = '192.0.2.1'; Expected = 'DocumentationIPv4' },
        @{ Address = '169.254.1.1'; Expected = 'LinkLocalIPv4' },
        @{ Address = '2001:db8::1'; Expected = 'DocumentationIPv6' },
        @{ Address = '::ffff:192.168.1.1'; Expected = 'IPv4Mapped-PrivateIPv4' },
        @{ Address = 'not-an-ip'; Expected = 'Invalid' }
    ) {
        Get-IRIPAddressCategory -IPAddress $Address | Should -BeExactly $Expected
    }

    It 'does not create a finding solely because an IP is public' {
        $sample = [pscustomobject]@{
            CreationUtc = [datetime]'2026-01-01T12:00:00Z'
            Operation = 'UserLoggedIn'
            Category = 'Authentication'
            UserId = 'user@example.com'
            ClientIP = '8.8.8.8'
            IPAddressCategory = 'PublicIPv4'
            ResultStatus = 'Succeeded'
            ObjectId = $null
        }
        @(Get-IRAuditFinding -Events @($sample) -TimeZoneId 'UTC').Count | Should -Be 0
    }

    It 'returns NotListedAsRisky for a normal Graph 404' {
        Mock Get-IRGraphUser {
            [pscustomobject]@{ Id = 'user-id'; UserPrincipalName = 'user@example.com' }
        }
        Mock Connect-IRGraph { [pscustomobject]@{} }
        Mock Assert-IRCommand { }
        Mock Invoke-IRRetry { throw 'Request_ResourceNotFound 404' }
        Mock Add-IRActionLog { }
        $result = Get-IRRiskyUser -UserPrincipalName 'user@example.com'
        $result.ListingStatus | Should -BeExactly 'NotListedAsRisky'
        $result.RiskLevel | Should -BeExactly 'none'
    }
}

Describe 'Investigator case report' {
    It 'renders the detailed evidence and decision sections' {
        $casePath = New-IRTestCase
        Mock Get-IRConnectionStatus {
            @([pscustomobject]@{ Service = 'Microsoft Graph'; Connected = $false; Identity = $null })
        }

        $script:IR.Results['Collection:Mailbox configuration'] = [pscustomobject]@{
            Snapshot = [pscustomobject]@{
                Summary = [pscustomobject]@{
                    HasForwarding = $false
                    ForwardingSmtpAddress = $null
                    DeliverToMailboxAndForward = $false
                    GrantSendOnBehalfTo = @()
                    AuditEnabled = $true
                    LitigationHoldEnabled = $false
                    SingleItemRecoveryEnabled = $true
                    ItemCount = 42
                    TotalItemSize = '1 MB'
                }
                InboxRules = @([pscustomobject]@{
                    Name = 'Synthetic rule'
                    Enabled = $true
                    Risk = 'Low'
                    Reasons = 'Test evidence'
                    ForwardTo = @()
                    RedirectTo = @()
                    ForwardAsAttachmentTo = @()
                    MoveToFolder = $null
                    DeleteMessage = $false
                    MarkAsRead = $false
                })
            }
            Applications = @()
            Permissions = [pscustomobject]@{ FolderErrors = @(); SkippedFolders = @() }
        }
        $script:IR.Results['Collection:Message trace'] = [pscustomobject]@{
            Messages = @([pscustomobject]@{ Status = 'Delivered' })
            Analysis = [pscustomobject]@{
                SentRows = 1
                ReceivedRows = 0
                Anomalies = @([pscustomobject]@{ Type = 'Large external'; Severity = 'High'; Count = 1; Detail = 'Synthetic lead' })
            }
        }
        $script:IR.Results['Collection:Unified audit log'] = [pscustomobject]@{
            Events = @([pscustomobject]@{ Operation = 'HardDelete' })
            Findings = @([pscustomobject]@{
                Severity = 'High'
                Operation = 'HardDelete'
                CreationUtc = '2026-01-01T00:00:00Z'
                ClientIP = '192.0.2.1'
                ObjectId = 'synthetic-object'
                Reasons = 'Synthetic high-risk operation'
            })
        }

        $path = New-IRCaseReport -CollectionStatus @([pscustomobject]@{
            Component = 'Synthetic collection'
            Status = 'Completed'
            DurationSeconds = 1
            Error = $null
        }) -Confirm:$false
        $html = Get-Content -LiteralPath $path -Raw -Encoding utf8

        foreach ($heading in @(
            'Investigator summary',
            'Mailbox controls and persistence review',
            'Message-flow analysis',
            'Unified-audit analysis',
            'Investigator decision framework'
        )) {
            $html | Should -Match ([regex]::Escape($heading))
        }
        $html | Should -Match 'Synthetic high-risk operation'
        $path | Should -Be (Join-Path -Path $casePath -ChildPath 'case_report.html')
    }
}

Describe 'Evidence action log and manifest integrity' {
    It 'validates an intact action log and detects a changed entry' {
        $casePath = New-IRTestCase
        $null = Add-IRActionLog -Action 'Synthetic evidence read' -Status Read -Target 'item-1' -RequireDurable
        (Test-IRActionLogChain).Valid | Should -BeTrue
        $logPath = Join-Path -Path $casePath -ChildPath 'action_log.jsonl'
        $lines = @(Get-Content -LiteralPath $logPath -Encoding utf8)
        $lines[0] = $lines[0].Replace('Initialize incident response case', 'Altered case initialization')
        $lines | Set-Content -LiteralPath $logPath -Encoding utf8
        (Test-IRActionLogChain).Valid | Should -BeFalse
    }

    It 'verifies an intact evidence manifest' {
        $casePath = New-IRTestCase
        'evidence' | Set-Content -LiteralPath (Join-Path $casePath 'evidence.txt') -Encoding utf8
        $manifest = New-IREvidenceManifest -Confirm:$false
        $result = Test-IREvidenceManifest -ManifestPath $manifest.JsonPath
        $result.IsValid | Should -BeTrue
        $result.Failed | Should -Be 0
        $result.ActionLogChain.Valid | Should -BeTrue
    }

    It 'detects modified evidence after sealing' {
        $casePath = New-IRTestCase
        $evidencePath = Join-Path $casePath 'evidence.txt'
        'original' | Set-Content -LiteralPath $evidencePath -Encoding utf8
        $manifest = New-IREvidenceManifest -Confirm:$false
        'changed' | Set-Content -LiteralPath $evidencePath -Encoding utf8
        $result = Test-IREvidenceManifest -ManifestPath $manifest.JsonPath
        $result.IsValid | Should -BeFalse
        @($result.Files | Where-Object Status -eq 'Modified').Count | Should -Be 1
    }

    It 'detects missing evidence after sealing' {
        $casePath = New-IRTestCase
        $evidencePath = Join-Path $casePath 'evidence.txt'
        'original' | Set-Content -LiteralPath $evidencePath -Encoding utf8
        $manifest = New-IREvidenceManifest -Confirm:$false
        Remove-Item -LiteralPath $evidencePath -Force
        $result = Test-IREvidenceManifest -ManifestPath $manifest.JsonPath
        $result.IsValid | Should -BeFalse
        @($result.Files | Where-Object Status -eq 'Missing').Count | Should -Be 1
    }

    It 'detects duplicate paths inside a manifest' {
        $casePath = New-IRTestCase
        'original' | Set-Content -LiteralPath (Join-Path $casePath 'evidence.txt') -Encoding utf8
        $manifest = New-IREvidenceManifest -Confirm:$false
        $document = Get-Content -LiteralPath $manifest.JsonPath -Raw -Encoding utf8 | ConvertFrom-Json -AsHashtable -Depth 20 -DateKind String
        $document.Files = @($document.Files) + @($document.Files[0])
        $document.FileCount = @($document.Files).Count
        $document | ConvertTo-Json -Depth 20 | Set-Content -LiteralPath $manifest.JsonPath -Encoding utf8
        $result = Test-IREvidenceManifest -ManifestPath $manifest.JsonPath
        $result.IsValid | Should -BeFalse
        @($result.Files | Where-Object Status -eq 'Duplicate').Count | Should -Be 1
    }

    It 'refuses to seal a case after the action log is altered' {
        $casePath = New-IRTestCase
        $logPath = Join-Path $casePath 'action_log.jsonl'
        $lines = @(Get-Content -LiteralPath $logPath -Encoding utf8)
        $lines[0] = $lines[0].Replace('Initialize incident response case', 'Altered initialization')
        $lines | Set-Content -LiteralPath $logPath -Encoding utf8
        { New-IREvidenceManifest -Confirm:$false } | Should -Throw '*action log hash chain is invalid*'
    }

    It 'detects files added after sealing' {
        $casePath = New-IRTestCase
        'original' | Set-Content -LiteralPath (Join-Path $casePath 'evidence.txt') -Encoding utf8
        $manifest = New-IREvidenceManifest -Confirm:$false
        'extra' | Set-Content -LiteralPath (Join-Path $casePath 'unexpected.txt') -Encoding utf8
        $result = Test-IREvidenceManifest -ManifestPath $manifest.JsonPath
        $result.IsValid | Should -BeFalse
        @($result.Files | Where-Object Status -eq 'Extra').Count | Should -Be 1
    }

    It 'rejects an unsafe relative path in a manifest' {
        $casePath = New-IRTestCase
        'original' | Set-Content -LiteralPath (Join-Path $casePath 'evidence.txt') -Encoding utf8
        $manifest = New-IREvidenceManifest -Confirm:$false
        $document = Get-Content -LiteralPath $manifest.JsonPath -Raw -Encoding utf8 | ConvertFrom-Json -AsHashtable -Depth 20 -DateKind String
        $document.Files = @($document.Files) + @([ordered]@{
            RelativePath = '../escape.txt'
            Length = 1
            LastWriteTimeUtc = '2026-01-01T00:00:00Z'
            SHA256 = '0' * 64
        })
        $document.FileCount = @($document.Files).Count
        $document | ConvertTo-Json -Depth 20 | Set-Content -LiteralPath $manifest.JsonPath -Encoding utf8
        $result = Test-IREvidenceManifest -ManifestPath $manifest.JsonPath
        $result.IsValid | Should -BeFalse
        @($result.Files | Where-Object Status -eq 'UnsafePath').Count | Should -Be 1
    }

    It 'rejects an unsupported manifest schema' {
        $casePath = New-IRTestCase
        'original' | Set-Content -LiteralPath (Join-Path $casePath 'evidence.txt') -Encoding utf8
        $manifest = New-IREvidenceManifest -Confirm:$false
        $document = Get-Content -LiteralPath $manifest.JsonPath -Raw -Encoding utf8 | ConvertFrom-Json -AsHashtable -Depth 20 -DateKind String
        $document.Schema = 'unknown/v9'
        $document | ConvertTo-Json -Depth 20 | Set-Content -LiteralPath $manifest.JsonPath -Encoding utf8
        { Test-IREvidenceManifest -ManifestPath $manifest.JsonPath } | Should -Throw '*Unsupported evidence manifest schema*'
    }
}
}
