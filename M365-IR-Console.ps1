#Requires -Version 7.6

<#
.SYNOPSIS
    Interactive Microsoft 365 incident response and forensic collection console.

.DESCRIPTION
    Consolidates the supported investigation, containment, remediation, evidence
    collection, and reporting capabilities from the two predecessor scripts in
    this directory.

    The console targets PowerShell 7.6 or later and defaults to Audit mode.
    Audit mode permits reads and local evidence exports, but it never performs a
    tenant-changing operation or requests a Microsoft Graph write scope. Live
    mode must be selected explicitly and every high-impact change requires
    confirmation plus durable case logging.

    Cloud features remain subject to Microsoft 365 licensing, tenant roles,
    consented Microsoft Graph scopes, service availability, and retention limits.
    The preflight and connection menus report those prerequisites rather than
    pretending that an unavailable feature succeeded.

.PARAMETER UserPrincipalName
    Initial target user. The console prompts when this value is omitted.

.PARAMETER TenantId
    Optional Microsoft Entra tenant ID or verified tenant domain used for Graph.

.PARAMETER Days
    Initial investigation lookback. Message trace is limited to 90 days by the
    service and queried in windows of no more than 10 days.

.PARAMETER OutputRoot
    Parent directory for case folders. Defaults to a private, per-user state
    directory outside the script and source-control folders.

.PARAMETER Mode
    Audit (default) or Live. Audit mode blocks every tenant mutation.

.PARAMETER InstallMissingModules
    Permit the preflight/connection workflow to install missing modules into the
    current user's PowerShell module path.

.PARAMETER PreflightOnly
    Run the offline preflight report and exit without authentication.

.PARAMETER OfflineSelfTest
    Run deterministic local regression tests and exit without authentication.

.PARAMETER SkipPreflight
    Skip the startup preflight. The connection menu can run it later.

.PARAMETER NoAutoConnect
    Do not offer to connect to core services during startup.

.PARAMETER PreserveInheritedCasePermissions
    Keep inherited permissions on newly created case folders. By default, the
    console restricts case evidence to the current user when the platform allows.

.PARAMETER UseDeviceAuthentication
    Use device-code authentication for Microsoft Graph, Exchange Online, and
    Microsoft Teams when the installed module supports it. This is useful on
    headless systems and when an embedded browser cannot be displayed.

.EXAMPLE
    .\M365-IR-Console.ps1

.EXAMPLE
    .\M365-IR-Console.ps1 -UserPrincipalName user@contoso.com -Days 30

.EXAMPLE
    .\M365-IR-Console.ps1 -OfflineSelfTest

.NOTES
    Version: 5.0.1
    Target runtime: PowerShell 7.6+
    Tested runtime: PowerShell 7.6.4
    License: MIT

.LINK
    https://github.com/fusiontechstrategies/M365-Incident-Response-Console
#>

[CmdletBinding()]
param(
    [string]$UserPrincipalName,
    [string]$TenantId,
    [ValidateRange(1, 90)]
    [int]$Days = 10,
    [string]$OutputRoot,
    [ValidateSet('Audit', 'Live')]
    [string]$Mode = 'Audit',
    [switch]$InstallMissingModules,
    [switch]$PreflightOnly,
    [switch]$OfflineSelfTest,
    [switch]$SkipPreflight,
    [switch]$NoAutoConnect,
    [switch]$PreserveInheritedCasePermissions,
    [switch]$UseDeviceAuthentication
)

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'Continue'

$script:IRVersion = [version]'5.0.1'
$script:IRMinimumPowerShell = [version]'7.6.0'
$script:IRScriptPath = $PSCommandPath
$script:IRModuleCatalog = [ordered]@{
    ExchangeOnlineManagement = [ordered]@{
        MinimumVersion = [version]'3.10.1'
        Optional = $false
        Purpose = 'Exchange Online and Microsoft Purview connectivity'
    }
    'Microsoft.Graph.Authentication' = [ordered]@{
        MinimumVersion = [version]'2.39.0'
        Optional = $false
        Purpose = 'Microsoft Graph authentication'
    }
    'Microsoft.Graph.Users' = [ordered]@{
        MinimumVersion = [version]'2.39.0'
        Optional = $false
        Purpose = 'User and delegated grant operations'
    }
    'Microsoft.Graph.Users.Actions' = [ordered]@{
        MinimumVersion = [version]'2.39.0'
        Optional = $false
        Purpose = 'Session revocation and mail actions'
    }
    'Microsoft.Graph.Identity.SignIns' = [ordered]@{
        MinimumVersion = [version]'2.39.0'
        Optional = $false
        Purpose = 'Conditional Access, user risk, and grant removal'
    }
    'Microsoft.Graph.Applications' = [ordered]@{
        MinimumVersion = [version]'2.39.0'
        Optional = $false
        Purpose = 'Service principals and app role assignments'
    }
    'Microsoft.Graph.Reports' = [ordered]@{
        MinimumVersion = [version]'2.39.0'
        Optional = $false
        Purpose = 'Sign-in logs'
    }
    'Microsoft.Graph.Groups' = [ordered]@{
        MinimumVersion = [version]'2.39.0'
        Optional = $true
        Purpose = 'Conditional Access exclusion groups'
    }
    'Microsoft.Graph.Identity.DirectoryManagement' = [ordered]@{
        MinimumVersion = [version]'2.39.0'
        Optional = $true
        Purpose = 'Tenant domains and directory role templates'
    }
    'Microsoft.Graph.Devices.CorporateManagement' = [ordered]@{
        MinimumVersion = [version]'2.39.0'
        Optional = $true
        Purpose = 'Intune managed devices'
    }
    'Microsoft.Graph.DeviceManagement' = [ordered]@{
        MinimumVersion = [version]'2.39.0'
        Optional = $true
        Purpose = 'Intune managed-device removal'
    }
    MicrosoftTeams = [ordered]@{
        MinimumVersion = [version]'7.9.0'
        Optional = $true
        Purpose = 'Teams membership and channel inventory'
    }
    'Microsoft.Online.SharePoint.PowerShell' = [ordered]@{
        MinimumVersion = [version]'16.0.27515.12000'
        Optional = $true
        Purpose = 'SharePoint Online site and user inventory'
    }
}

$outputRootWasDefault = [string]::IsNullOrWhiteSpace($OutputRoot)
if ($outputRootWasDefault) {
    if ($IsWindows) {
        $base = [Environment]::GetFolderPath([Environment+SpecialFolder]::LocalApplicationData)
        if ([string]::IsNullOrWhiteSpace($base)) {
            $base = [Environment]::GetFolderPath([Environment+SpecialFolder]::UserProfile)
        }
        $OutputRoot = Join-Path -Path $base -ChildPath 'M365-IR-Console\Cases'
    }
    else {
        $base = [Environment]::GetEnvironmentVariable('XDG_STATE_HOME')
        if ([string]::IsNullOrWhiteSpace($base)) {
            $base = Join-Path -Path ([Environment]::GetFolderPath([Environment+SpecialFolder]::UserProfile)) -ChildPath '.local/state'
        }
        $OutputRoot = Join-Path -Path $base -ChildPath 'm365-ir-console/cases'
    }
}

$script:IR = [ordered]@{
    Version = $script:IRVersion
    Runtime = $PSVersionTable.PSVersion
    RequestedTenantId = $TenantId
    TenantId = $TenantId
    TenantSelectionValidated = [string]::IsNullOrWhiteSpace($TenantId)
    TargetUpn = $null
    Days = $Days
    Mode = $Mode
    OutputRoot = [System.IO.Path]::GetFullPath($OutputRoot)
    OutputRootWasDefault = $outputRootWasDefault
    CaseId = $null
    CasePath = $null
    StartedUtc = [datetime]::UtcNow
    Investigator = $null
    Connections = [ordered]@{
        Graph = $false
        Exchange = $false
        Purview = $false
        Teams = $false
        SharePoint = $false
    }
    ActionLog = [System.Collections.Generic.List[object]]::new()
    ActionSequence = 0L
    LastActionHash = ('0' * 64)
    Results = @{}
    InstallMissingModules = $InstallMissingModules.IsPresent
    SkipPreflight = $SkipPreflight.IsPresent
    NoAutoConnect = $NoAutoConnect.IsPresent
    PreserveInheritedCasePermissions = $PreserveInheritedCasePermissions.IsPresent
    UseDeviceAuthentication = $UseDeviceAuthentication.IsPresent
    GraphBroadConsentAcknowledged = $false
    CasePermissionStatus = 'Not initialized'
    Interactive = $true
}

function Write-IRConsole {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSAvoidUsingWriteHost',
        '',
        Justification = 'This is an interactive console; Write-Host prevents menu text from contaminating object output.'
    )]
    param(
        [AllowEmptyString()]
        [string]$Message = '',
        [System.ConsoleColor]$Color,
        [switch]$NoNewline
    )

    $params = @{ Object = $Message }
    if ($PSBoundParameters.ContainsKey('Color')) {
        $params.ForegroundColor = $Color
    }
    if ($NoNewline) {
        $params.NoNewline = $true
    }
    Write-Host @params
}

function Write-IRInfo {
    param([Parameter(Mandatory)][string]$Message)
    Write-IRConsole -Message "[i] $Message" -Color Cyan
}

function Write-IRSuccess {
    param([Parameter(Mandatory)][string]$Message)
    Write-IRConsole -Message "[+] $Message" -Color Green
}

function Write-IRWarn {
    param([Parameter(Mandatory)][string]$Message)
    Write-IRConsole -Message "[!] $Message" -Color Yellow
}

function Write-IRFailure {
    param([Parameter(Mandatory)][string]$Message)
    Write-IRConsole -Message "[-] $Message" -Color Red
}

function Get-IRInvestigator {
    try {
        if ($IsWindows) {
            return [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
        }
    }
    catch {
        Write-Verbose "Unable to resolve Windows identity: $($_.Exception.Message)"
    }

    if (-not [string]::IsNullOrWhiteSpace([Environment]::UserName)) {
        return [Environment]::UserName
    }
    return 'Unknown'
}

function Get-IRProperty {
    param(
        [AllowNull()]
        [object]$InputObject,
        [Parameter(Mandatory)]
        [string]$Name,
        [AllowNull()]
        [object]$Default = $null
    )

    if ($null -eq $InputObject) {
        return $Default
    }

    if ($InputObject -is [System.Collections.IDictionary]) {
        $containsKeyMethod = $InputObject.PSObject.Methods['ContainsKey']
        $containsMethod = $InputObject.PSObject.Methods['Contains']
        $hasKey = if ($null -ne $containsKeyMethod) {
            $InputObject.ContainsKey($Name)
        }
        elseif ($null -ne $containsMethod) {
            $InputObject.Contains($Name)
        }
        else {
            $Name -in @($InputObject.Keys)
        }
        if ($hasKey) {
            return $InputObject[$Name]
        }
        return $Default
    }

    $property = $InputObject.PSObject.Properties[$Name]
    if ($null -ne $property) {
        return $property.Value
    }
    return $Default
}

function ConvertTo-IRODataLiteral {
    param([Parameter(Mandatory)][string]$Value)
    return $Value.Replace("'", "''")
}

function Get-IRPathStringComparison {
    if ($IsWindows) {
        return [System.StringComparison]::OrdinalIgnoreCase
    }
    return [System.StringComparison]::Ordinal
}

function Test-IRPathWithinRoot {
    param(
        [Parameter(Mandatory)][string]$Root,
        [Parameter(Mandatory)][string]$Candidate
    )

    $rootPath = [System.IO.Path]::GetFullPath($Root)
    $candidatePath = [System.IO.Path]::GetFullPath($Candidate)
    $comparison = Get-IRPathStringComparison
    if ($candidatePath.Equals($rootPath, $comparison)) {
        return $true
    }
    $prefix = $rootPath.TrimEnd(
        [System.IO.Path]::DirectorySeparatorChar,
        [System.IO.Path]::AltDirectorySeparatorChar
    ) + [System.IO.Path]::DirectorySeparatorChar
    return $candidatePath.StartsWith($prefix, $comparison)
}

function ConvertTo-IRSafeFileName {
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Value,
        [ValidateRange(8, 180)]
        [int]$MaximumLength = 120
    )

    $safe = $Value.Trim()
    # Apply a portable superset so evidence packages remain valid when moved
    # between Windows, Linux, and macOS.
    $safe = $safe -replace '[<>:"/\\|?*\x00-\x1f]', '_'
    $safe = $safe -replace '\s+', '_'
    $safe = $safe.Trim('.', ' ')
    if ([string]::IsNullOrWhiteSpace($safe)) {
        $safe = 'unnamed'
    }
    if ($safe -match '^(?i:con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\.|$)') {
        $safe = "_$safe"
    }
    if ($safe.Length -gt $MaximumLength) {
        $safe = $safe.Substring(0, $MaximumLength)
    }
    return $safe
}

function Protect-IRCaseDirectory {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)

    $resolved = [System.IO.Path]::GetFullPath($Path)
    if ($script:IR.PreserveInheritedCasePermissions) {
        $script:IR.CasePermissionStatus = 'Inherited permissions preserved by request'
        return $script:IR.CasePermissionStatus
    }

    if ($IsWindows) {
        $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent().User
        if ($null -eq $identity) {
            throw 'The current Windows security identifier could not be determined.'
        }
        $security = [System.Security.AccessControl.DirectorySecurity]::new()
        $security.SetAccessRuleProtection($true, $false)
        $rule = [System.Security.AccessControl.FileSystemAccessRule]::new(
            $identity,
            [System.Security.AccessControl.FileSystemRights]::FullControl,
            [System.Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit',
            [System.Security.AccessControl.PropagationFlags]::None,
            [System.Security.AccessControl.AccessControlType]::Allow
        )
        $null = $security.AddAccessRule($rule)
        [System.IO.FileSystemAclExtensions]::SetAccessControl(
            [System.IO.DirectoryInfo]::new($resolved),
            $security
        )
        $script:IR.CasePermissionStatus = "Restricted to current Windows identity $identity"
    }
    else {
        [System.IO.File]::SetUnixFileMode(
            $resolved,
            [System.IO.UnixFileMode]'UserRead, UserWrite, UserExecute'
        )
        $script:IR.CasePermissionStatus = 'Restricted to Unix mode 0700'
    }
    return $script:IR.CasePermissionStatus
}

function Protect-IRCaseFile {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)

    if ($script:IR.PreserveInheritedCasePermissions) {
        return 'Inherited permissions preserved by request'
    }
    $resolved = [System.IO.Path]::GetFullPath($Path)
    if ($IsWindows) {
        $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent().User
        if ($null -eq $identity) {
            throw 'The current Windows security identifier could not be determined.'
        }
        $security = [System.Security.AccessControl.FileSecurity]::new()
        $security.SetAccessRuleProtection($true, $false)
        $rule = [System.Security.AccessControl.FileSystemAccessRule]::new(
            $identity,
            [System.Security.AccessControl.FileSystemRights]::FullControl,
            [System.Security.AccessControl.AccessControlType]::Allow
        )
        $null = $security.AddAccessRule($rule)
        [System.IO.FileSystemAclExtensions]::SetAccessControl(
            [System.IO.FileInfo]::new($resolved),
            $security
        )
        return "Restricted to current Windows identity $identity"
    }

    [System.IO.File]::SetUnixFileMode(
        $resolved,
        [System.IO.UnixFileMode]'UserRead, UserWrite'
    )
    return 'Restricted to Unix mode 0600'
}

function ConvertTo-IRHtml {
    param([AllowNull()][object]$Value)
    if ($null -eq $Value) {
        return ''
    }
    return [System.Net.WebUtility]::HtmlEncode([string]$Value)
}

function Test-IRUpn {
    param([AllowNull()][string]$Value)

    if ([string]::IsNullOrWhiteSpace($Value)) {
        return $false
    }
    $trimmed = $Value.Trim()
    if ($trimmed -notmatch '^[^@\s]+@[^@\s]+\.[^@\s]+$') {
        return $false
    }
    try {
        $address = [System.Net.Mail.MailAddress]::new($trimmed)
        return $address.Address -ieq $trimmed
    }
    catch {
        return $false
    }
}

function Read-IRText {
    param(
        [Parameter(Mandatory)][string]$Prompt,
        [AllowEmptyString()][string]$Default = '',
        [switch]$AllowEmpty
    )

    while ($true) {
        $label = if ([string]::IsNullOrEmpty($Default)) {
            $Prompt
        }
        else {
            "$Prompt [$Default]"
        }
        $value = Read-Host $label
        if ([string]::IsNullOrWhiteSpace($value)) {
            if (-not [string]::IsNullOrEmpty($Default)) {
                return $Default
            }
            if ($AllowEmpty) {
                return ''
            }
            Write-IRWarn 'A value is required.'
            continue
        }
        return $value.Trim()
    }
}

function Read-IRInteger {
    param(
        [Parameter(Mandatory)][string]$Prompt,
        [int]$Default,
        [int]$Minimum = [int]::MinValue,
        [int]$Maximum = [int]::MaxValue
    )

    while ($true) {
        $raw = Read-Host "$Prompt [$Default]"
        if ([string]::IsNullOrWhiteSpace($raw)) {
            return $Default
        }
        $number = 0
        if ([int]::TryParse($raw, [ref]$number) -and $number -ge $Minimum -and $number -le $Maximum) {
            return $number
        }
        Write-IRWarn "Enter a whole number between $Minimum and $Maximum."
    }
}

function Read-IRYesNo {
    param(
        [Parameter(Mandatory)][string]$Prompt,
        [switch]$DefaultYes
    )

    $suffix = if ($DefaultYes) { '[Y/n]' } else { '[y/N]' }
    while ($true) {
        $answer = Read-Host "$Prompt $suffix"
        if ([string]::IsNullOrWhiteSpace($answer)) {
            return $DefaultYes.IsPresent
        }
        switch -Regex ($answer.Trim()) {
            '^(y|yes)$' { return $true }
            '^(n|no)$' { return $false }
            default { Write-IRWarn 'Enter Y or N.' }
        }
    }
}

function Read-IRUpn {
    param(
        [string]$Prompt = 'Target user UPN',
        [AllowEmptyString()][string]$Default = ''
    )

    while ($true) {
        $candidate = Read-IRText -Prompt $Prompt -Default $Default
        if (Test-IRUpn -Value $candidate) {
            return $candidate.ToLowerInvariant()
        }
        Write-IRWarn "'$candidate' is not a valid UPN/email address."
    }
}

function Wait-IRKey {
    if ($script:IR.Interactive) {
        $null = Read-Host 'Press Enter to continue'
    }
}

function Select-IRItem {
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]]$Items,
        [Parameter(Mandatory)]
        [scriptblock]$Label,
        [string]$Prompt = 'Select an item',
        [switch]$AllowMultiple,
        [switch]$AllowCancel
    )

    $array = @($Items)
    if ($array.Count -eq 0) {
        Write-IRWarn 'There are no items to select.'
        return @()
    }

    for ($index = 0; $index -lt $array.Count; $index++) {
        $text = & $Label $array[$index]
        Write-IRConsole -Message ('  {0,3}. {1}' -f ($index + 1), $text)
    }
    if ($AllowCancel) {
        Write-IRConsole -Message '    0. Cancel'
    }

    while ($true) {
        $suffix = if ($AllowMultiple) { ' (comma-separated)' } else { '' }
        $raw = Read-Host "$Prompt$suffix"
        if ($AllowCancel -and $raw.Trim() -eq '0') {
            return @()
        }

        $parts = if ($AllowMultiple) {
            @($raw -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
        }
        else {
            @($raw.Trim())
        }

        $selected = [System.Collections.Generic.List[object]]::new()
        $valid = $parts.Count -gt 0
        foreach ($part in $parts) {
            $choice = 0
            if (-not [int]::TryParse($part, [ref]$choice) -or $choice -lt 1 -or $choice -gt $array.Count) {
                $valid = $false
                break
            }
            if (-not $selected.Contains($array[$choice - 1])) {
                $selected.Add($array[$choice - 1])
            }
        }

        if ($valid) {
            return $selected.ToArray()
        }
        Write-IRWarn 'The selection was not valid.'
    }
}

function Initialize-IRCase {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [string]$CaseId,
        [switch]$ForceNew
    )

    if ($script:IR.CasePath -and -not $ForceNew) {
        return $script:IR.CasePath
    }

    if ([string]::IsNullOrWhiteSpace($CaseId)) {
        $CaseId = 'IR-{0}-{1}' -f [datetime]::UtcNow.ToString('yyyyMMdd-HHmmss'), ([guid]::NewGuid().ToString('N').Substring(0, 8))
    }
    $safeCaseId = ConvertTo-IRSafeFileName -Value $CaseId
    $root = [System.IO.Path]::GetFullPath($script:IR.OutputRoot)
    $casePath = [System.IO.Path]::GetFullPath((Join-Path -Path $root -ChildPath $safeCaseId))

    if (-not (Test-IRPathWithinRoot -Root $root -Candidate $casePath)) {
        throw "Case path '$casePath' is outside output root '$root'."
    }
    if (Test-Path -LiteralPath $casePath) {
        throw "Case path '$casePath' already exists. Choose a new case ID to prevent evidence from different cases being mixed."
    }

    if ($PSCmdlet.ShouldProcess($casePath, 'Create incident response case directory')) {
        $rootCreated = -not (Test-Path -LiteralPath $root -PathType Container)
        $null = New-Item -ItemType Directory -Path $root -Force
        if ($rootCreated -or $script:IR.OutputRootWasDefault) {
            $null = Protect-IRCaseDirectory -Path $root
        }
        $null = New-Item -ItemType Directory -Path $casePath -Force
        try {
            $null = Protect-IRCaseDirectory -Path $casePath
        }
        catch {
            try {
                Remove-Item -LiteralPath $casePath -Force -ErrorAction SilentlyContinue
            }
            catch {
                Write-Verbose "Unable to remove the empty case directory after permission hardening failed: $($_.Exception.Message)"
            }
            throw "Case directory permissions could not be restricted. Use -PreserveInheritedCasePermissions only after reviewing the destination ACL. $($_.Exception.Message)"
        }
        if ($ForceNew) {
            $script:IR.ActionLog.Clear()
            $script:IR.ActionSequence = 0L
            $script:IR.LastActionHash = ('0' * 64)
            $script:IR.Results.Clear()
        }
        $script:IR.CaseId = $safeCaseId
        $script:IR.CasePath = $casePath
        $script:IR.Investigator = Get-IRInvestigator

        $metadata = [ordered]@{
            CaseId = $script:IR.CaseId
            ToolVersion = $script:IR.Version.ToString()
            PowerShellVersion = $PSVersionTable.PSVersion.ToString()
            CreatedUtc = [datetime]::UtcNow.ToString('o')
            Investigator = $script:IR.Investigator
            ComputerName = [Environment]::MachineName
            TenantId = $script:IR.TenantId
            InitialTarget = $script:IR.TargetUpn
            Mode = $script:IR.Mode
            PermissionStatus = $script:IR.CasePermissionStatus
        }
        $metadataPath = Join-Path -Path $casePath -ChildPath 'case_metadata.json'
        $metadata | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $metadataPath -Encoding utf8

        if ($script:IR.ActionLog.Count -gt 0) {
            $logPath = Join-Path -Path $casePath -ChildPath 'action_log.jsonl'
            @($script:IR.ActionLog | ForEach-Object {
                $_ | ConvertTo-Json -Depth 30 -Compress
            }) | Set-Content -LiteralPath $logPath -Encoding utf8
        }
        $null = Add-IRActionLog -Action 'Initialize incident response case' -Status Info -Target $casePath -Details @{
            PermissionStatus = $script:IR.CasePermissionStatus
        } -RequireDurable
    }

    return $script:IR.CasePath
}

function Get-IRCasePath {
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$ChildPath,
        [switch]$CreateDirectory
    )

    if (-not $script:IR.CasePath) {
        $null = Initialize-IRCase
    }

    $caseRoot = [System.IO.Path]::GetFullPath($script:IR.CasePath)
    $candidate = [System.IO.Path]::GetFullPath((Join-Path -Path $caseRoot -ChildPath $ChildPath))
    if (-not (Test-IRPathWithinRoot -Root $caseRoot -Candidate $candidate)) {
        throw "Resolved path '$candidate' is outside case directory '$caseRoot'."
    }

    if ($CreateDirectory -and -not (Test-Path -LiteralPath $candidate -PathType Container)) {
        $null = New-Item -ItemType Directory -Path $candidate -Force
        $null = Protect-IRCaseDirectory -Path $candidate
    }
    return $candidate
}

function Get-IRSha256Hex {
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Value)

    $bytes = [System.Text.Encoding]::UTF8.GetBytes($Value)
    $algorithm = [System.Security.Cryptography.SHA256]::Create()
    try {
        return [System.Convert]::ToHexString($algorithm.ComputeHash($bytes))
    }
    finally {
        $algorithm.Dispose()
    }
}

function Get-IRActionLogHash {
    param(
        [Parameter(Mandatory)][long]$Sequence,
        [Parameter(Mandatory)][string]$TimestampUtc,
        [Parameter(Mandatory)][string]$Status,
        [Parameter(Mandatory)][string]$Action,
        [AllowNull()][string]$Target,
        [Parameter(Mandatory)][string]$Investigator,
        [Parameter(Mandatory)][string]$Mode,
        [AllowNull()][object]$Details,
        [Parameter(Mandatory)][string]$PreviousHash
    )

    $payload = [ordered]@{
        Sequence = $Sequence
        TimestampUtc = $TimestampUtc
        Status = $Status
        Action = $Action
        Target = $Target
        Investigator = $Investigator
        Mode = $Mode
        Details = $Details
        PreviousHash = $PreviousHash
    }
    return Get-IRSha256Hex -Value ($payload | ConvertTo-Json -Depth 30 -Compress)
}

function Add-IRActionLog {
    param(
        [Parameter(Mandatory)][string]$Action,
        [ValidateSet('Info', 'Read', 'Planned', 'Approved', 'Changed', 'Skipped', 'Warning', 'Error')]
        [string]$Status = 'Info',
        [AllowNull()][string]$Target,
        [AllowNull()][object]$Details,
        [switch]$RequireDurable
    )

    if ($RequireDurable -and -not $script:IR.CasePath) {
        $null = Initialize-IRCase
    }

    $sequence = [long]$script:IR.ActionSequence + 1L
    $timestamp = [datetime]::UtcNow.ToString('o')
    $investigator = if ($script:IR.Investigator) { $script:IR.Investigator } else { Get-IRInvestigator }
    $previousHash = [string]$script:IR.LastActionHash
    $entryHash = Get-IRActionLogHash -Sequence $sequence -TimestampUtc $timestamp -Status $Status -Action $Action -Target $Target -Investigator $investigator -Mode $script:IR.Mode -Details $Details -PreviousHash $previousHash
    $entry = [pscustomobject][ordered]@{
        Sequence = $sequence
        TimestampUtc = $timestamp
        Status = $Status
        Action = $Action
        Target = $Target
        Investigator = $investigator
        Mode = $script:IR.Mode
        Details = $Details
        PreviousHash = $previousHash
        EntryHash = $entryHash
    }

    if ($script:IR.CasePath) {
        try {
            $logPath = Join-Path -Path $script:IR.CasePath -ChildPath 'action_log.jsonl'
            $entry | ConvertTo-Json -Depth 30 -Compress | Add-Content -LiteralPath $logPath -Encoding utf8
        }
        catch {
            $message = "Unable to append the case action log: $($_.Exception.Message)"
            if ($RequireDurable) {
                throw $message
            }
            Write-Warning $message
            return $null
        }
    }

    $script:IR.ActionSequence = $sequence
    $script:IR.LastActionHash = $entryHash
    $script:IR.ActionLog.Add($entry)
    return $entry
}

function Test-IRActionLogChain {
    [CmdletBinding()]
    param([string]$Path)

    if ([string]::IsNullOrWhiteSpace($Path)) {
        if (-not $script:IR.CasePath) {
            return [pscustomobject]@{ Valid = $false; Entries = 0; Error = 'No case or action log path was supplied.' }
        }
        $Path = Join-Path -Path $script:IR.CasePath -ChildPath 'action_log.jsonl'
    }
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        return [pscustomobject]@{ Valid = $false; Entries = 0; Error = "Action log not found: $Path" }
    }

    $previousHash = '0' * 64
    $expectedSequence = 1L
    $count = 0
    try {
        foreach ($line in @(Get-Content -LiteralPath $Path -Encoding utf8)) {
            if ([string]::IsNullOrWhiteSpace($line)) { continue }
            $entry = $line | ConvertFrom-Json -Depth 30 -DateKind String -ErrorAction Stop
            if ([long]$entry.Sequence -ne $expectedSequence) {
                throw "Expected sequence $expectedSequence but found $($entry.Sequence)."
            }
            if ([string]$entry.PreviousHash -cne $previousHash) {
                throw "Previous-hash mismatch at sequence $expectedSequence."
            }
            $calculated = Get-IRActionLogHash -Sequence ([long]$entry.Sequence) -TimestampUtc ([string]$entry.TimestampUtc) -Status ([string]$entry.Status) -Action ([string]$entry.Action) -Target ([string]$entry.Target) -Investigator ([string]$entry.Investigator) -Mode ([string]$entry.Mode) -Details $entry.Details -PreviousHash ([string]$entry.PreviousHash)
            if ($calculated -cne [string]$entry.EntryHash) {
                throw "Entry-hash mismatch at sequence $expectedSequence."
            }
            $previousHash = [string]$entry.EntryHash
            $expectedSequence++
            $count++
        }
        return [pscustomobject]@{ Valid = $true; Entries = $count; Error = $null; FinalHash = $previousHash }
    }
    catch {
        return [pscustomobject]@{ Valid = $false; Entries = $count; Error = $_.Exception.Message; FinalHash = $previousHash }
    }
}

function Export-IRData {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]]$Data,
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$BaseName,
        [ValidateSet('Csv', 'Json', 'Clixml')]
        [string]$Format = 'Csv',
        [string]$Subdirectory = 'Exports'
    )

    $items = @($Data | Where-Object { $null -ne $_ })
    if ($items.Count -eq 0) {
        Write-IRWarn "No data was available for '$BaseName'."
        return $null
    }

    $directory = Get-IRCasePath -ChildPath $Subdirectory -CreateDirectory
    $safeName = ConvertTo-IRSafeFileName -Value $BaseName
    $stamp = [datetime]::UtcNow.ToString('yyyyMMdd-HHmmssfff')
    $extension = switch ($Format) {
        'Csv' { 'csv' }
        'Json' { 'json' }
        'Clixml' { 'xml' }
    }
    $path = Join-Path -Path $directory -ChildPath "$safeName-$stamp.$extension"

    switch ($Format) {
        'Csv' {
            $items | Export-Csv -LiteralPath $path -NoTypeInformation -Encoding utf8
        }
        'Json' {
            $items | ConvertTo-Json -Depth 30 | Set-Content -LiteralPath $path -Encoding utf8
        }
        'Clixml' {
            $items | Export-Clixml -LiteralPath $path -Depth 20
        }
    }

    $null = Add-IRActionLog -Action 'Export local evidence' -Status Read -Target $path -Details @{ Records = $items.Count; Format = $Format }
    Write-IRSuccess "Exported $($items.Count) record(s) to $path"
    return $path
}

function Set-IRTarget {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSUseShouldProcessForStateChangingFunctions',
        '',
        Justification = 'This updates only in-memory console target state.'
    )]
    param([Parameter(Mandatory)][string]$Upn)
    if (-not (Test-IRUpn -Value $Upn)) {
        throw "'$Upn' is not a valid target UPN."
    }
    $script:IR.TargetUpn = $Upn.Trim().ToLowerInvariant()
    $null = Add-IRActionLog -Action 'Set target user' -Status Info -Target $script:IR.TargetUpn
    return $script:IR.TargetUpn
}

function Resolve-IRTarget {
    param([AllowNull()][string]$Upn)
    if (-not [string]::IsNullOrWhiteSpace($Upn)) {
        if (-not (Test-IRUpn -Value $Upn)) {
            throw "'$Upn' is not a valid UPN."
        }
        return $Upn.Trim().ToLowerInvariant()
    }
    if (-not [string]::IsNullOrWhiteSpace($script:IR.TargetUpn)) {
        return $script:IR.TargetUpn
    }
    throw 'No target user is set.'
}

function Set-IRMode {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSUseShouldProcessForStateChangingFunctions',
        '',
        Justification = 'This updates only in-memory safety mode after explicit confirmation.'
    )]
    param([Parameter(Mandatory)][ValidateSet('Audit', 'Live')][string]$NewMode)

    $previousMode = $script:IR.Mode
    if ($NewMode -eq 'Live' -and $previousMode -ne 'Live') {
        Write-IRFailure 'LIVE mode allows tenant-changing operations.'
        $token = Read-Host 'Type LIVE to enable tenant changes for this session'
        if ($token -cne 'LIVE') {
            Write-IRWarn 'Mode remains Audit.'
            return $script:IR.Mode
        }
    }
    $script:IR.Mode = $NewMode
    if ($NewMode -eq 'Audit' -and $previousMode -eq 'Live') {
        # Drop any cached write-capable tokens when returning to the safe mode.
        Disconnect-IRService -Confirm:$false
    }
    $null = Add-IRActionLog -Action 'Change execution mode' -Status Info -Target $NewMode
    Write-IRSuccess "Execution mode is now $NewMode."
    return $script:IR.Mode
}

function Invoke-IRChange {
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    param(
        [Parameter(Mandatory)][string]$Target,
        [Parameter(Mandatory)][string]$Action,
        [Parameter(Mandatory)][scriptblock]$Operation,
        [ValidateSet('Low', 'Medium', 'High', 'Critical')]
        [string]$Impact = 'High',
        [string]$ExactConfirmation,
        [AllowNull()][object]$Details
    )

    if ($script:IR.Mode -ne 'Live') {
        Write-IRWarn "[AUDIT MODE] Would $Action on $Target"
        $null = Add-IRActionLog -Action $Action -Status Planned -Target $Target -Details $Details
        return $null
    }

    if ([string]::IsNullOrWhiteSpace($ExactConfirmation)) {
        throw 'Live tenant changes require a non-empty exact-confirmation phrase.'
    }

    if (-not $PSCmdlet.ShouldProcess($Target, $Action)) {
        $null = Add-IRActionLog -Action $Action -Status Skipped -Target $Target -Details 'ShouldProcess declined'
        return $null
    }

    Write-IRFailure "$Impact impact: $Action"
    $typed = Read-Host "Type '$ExactConfirmation' to continue"
    if ($typed -cne $ExactConfirmation) {
        Write-IRWarn 'Confirmation did not match; no change was made.'
        $null = Add-IRActionLog -Action $Action -Status Skipped -Target $Target -Details 'Exact confirmation failed'
        return $null
    }

    $approvalDetails = [ordered]@{
        Impact = $Impact
        ConfirmationPhraseMatched = $true
        OperationDetails = $Details
    }
    $null = Add-IRActionLog -Action $Action -Status Approved -Target $Target -Details $approvalDetails -RequireDurable

    try {
        $result = & $Operation
        try {
            $null = Add-IRActionLog -Action $Action -Status Changed -Target $Target -Details $Details -RequireDurable
        }
        catch {
            throw "The tenant operation returned successfully, but its completion could not be written to the durable action log. Verify the target state before retrying. $($_.Exception.Message)"
        }
        Write-IRSuccess "$Action completed for $Target"
        return $result
    }
    catch {
        $operationError = $_
        try {
            $null = Add-IRActionLog -Action $Action -Status Error -Target $Target -Details $operationError.Exception.Message -RequireDurable
        }
        catch {
            Write-Warning "The tenant operation failed and the failure could not be appended to the durable action log: $($_.Exception.Message)"
        }
        throw $operationError
    }
}

function Get-IRRetryDelay {
    param([AllowNull()][object]$ErrorRecord)

    $exception = if ($ErrorRecord -is [System.Management.Automation.ErrorRecord]) {
        $ErrorRecord.Exception
    }
    elseif ($ErrorRecord -is [System.Exception]) {
        $ErrorRecord
    }
    else {
        $null
    }

    while ($null -ne $exception) {
        $responseProperty = $exception.PSObject.Properties['Response']
        if ($null -ne $responseProperty -and $null -ne $responseProperty.Value) {
            $headersProperty = $responseProperty.Value.PSObject.Properties['Headers']
            if ($null -ne $headersProperty -and $null -ne $headersProperty.Value) {
                $retryAfterProperty = $headersProperty.Value.PSObject.Properties['RetryAfter']
                if ($null -ne $retryAfterProperty -and $null -ne $retryAfterProperty.Value) {
                    $deltaProperty = $retryAfterProperty.Value.PSObject.Properties['Delta']
                    if ($null -ne $deltaProperty -and $null -ne $deltaProperty.Value) {
                        return [math]::Max(0.0, ([timespan]$deltaProperty.Value).TotalSeconds)
                    }
                    $dateProperty = $retryAfterProperty.Value.PSObject.Properties['Date']
                    if ($null -ne $dateProperty -and $null -ne $dateProperty.Value) {
                        return [math]::Max(0.0, ([datetimeoffset]$dateProperty.Value - [datetimeoffset]::UtcNow).TotalSeconds)
                    }
                }
                try {
                    $values = $null
                    if ($headersProperty.Value.TryGetValues('Retry-After', [ref]$values)) {
                        $raw = [string](@($values)[0])
                        $seconds = 0.0
                        if ([double]::TryParse($raw, [System.Globalization.NumberStyles]::Float, [System.Globalization.CultureInfo]::InvariantCulture, [ref]$seconds)) {
                            return [math]::Max(0.0, $seconds)
                        }
                        $date = [datetimeoffset]::MinValue
                        if ([datetimeoffset]::TryParse($raw, [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::AssumeUniversal, [ref]$date)) {
                            return [math]::Max(0.0, ($date.ToUniversalTime() - [datetimeoffset]::UtcNow).TotalSeconds)
                        }
                    }
                }
                catch {
                    Write-Verbose "Retry-After header parsing failed: $($_.Exception.Message)"
                }
            }
        }
        $exception = $exception.InnerException
    }
    return $null
}

function Invoke-IRRetry {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][scriptblock]$Operation,
        [ValidateRange(1, 8)][int]$MaximumAttempts = 5
    )

    $attempt = 0
    $delaySeconds = 1.0
    while ($true) {
        $attempt++
        try {
            return & $Operation
        }
        catch {
            $message = $_.Exception.Message
            $statusCode = Get-IRHttpStatusCode -ErrorRecord $_
            $transientStatus = $statusCode -in @(408, 429, 500, 502, 503, 504)
            $transient = $transientStatus -or
                $message -match '(?i)(429|throttl|too many requests|timeout|timed out|temporar|502|503|504|service unavailable|bad gateway|gateway timeout)'
            if (-not $transient -or $attempt -ge $MaximumAttempts) {
                throw
            }

            $jitter = [System.Security.Cryptography.RandomNumberGenerator]::GetInt32(0, 1000) / 1000.0
            $retryAfter = Get-IRRetryDelay -ErrorRecord $_
            $baseSleep = if ($null -ne $retryAfter) { [double]$retryAfter } else { $delaySeconds }
            $sleep = [math]::Min(300.0, $baseSleep + $jitter)
            Write-IRWarn "Transient service error. Retrying in $([math]::Round($sleep, 1)) seconds ($attempt/$MaximumAttempts)."
            Start-Sleep -Seconds $sleep
            $delaySeconds = [math]::Min(30.0, $delaySeconds * 2)
        }
    }
}

function Get-IRHttpStatusCode {
    param([AllowNull()][object]$ErrorRecord)

    $exception = if ($ErrorRecord -is [System.Management.Automation.ErrorRecord]) {
        $ErrorRecord.Exception
    }
    elseif ($ErrorRecord -is [System.Exception]) {
        $ErrorRecord
    }
    else {
        $null
    }

    while ($null -ne $exception) {
        foreach ($propertyName in @('StatusCode', 'ResponseStatusCode')) {
            $property = $exception.PSObject.Properties[$propertyName]
            if ($null -ne $property -and $null -ne $property.Value) {
                try { return [int]$property.Value }
                catch { Write-Verbose "HTTP status property '$propertyName' was not numeric." }
            }
        }
        $response = $exception.PSObject.Properties['Response']
        if ($null -ne $response -and $null -ne $response.Value) {
            $status = $response.Value.PSObject.Properties['StatusCode']
            if ($null -ne $status -and $null -ne $status.Value) {
                try { return [int]$status.Value }
                catch { Write-Verbose 'HTTP response status was not numeric.' }
            }
        }
        $exception = $exception.InnerException
    }
    return $null
}

function Test-IRNotFoundError {
    param([Parameter(Mandatory)][object]$ErrorRecord)

    $statusCode = Get-IRHttpStatusCode -ErrorRecord $ErrorRecord
    if ($statusCode -eq 404) {
        return $true
    }
    return [string]$ErrorRecord.Exception.Message -match '(?i)(Request_ResourceNotFound|ResourceNotFound|\b404\b)'
}

function New-IRRandomPassword {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSUseShouldProcessForStateChangingFunctions',
        '',
        Justification = 'This function only creates a random in-memory string.'
    )]
    [CmdletBinding()]
    [OutputType([string])]
    param([ValidateRange(14, 128)][int]$Length = 24)

    $sets = @(
        'abcdefghijkmnopqrstuvwxyz',
        'ABCDEFGHJKLMNPQRSTUVWXYZ',
        '23456789',
        '!@#$%^&*()-_=+?'
    )
    $all = $sets -join ''
    $characters = [System.Collections.Generic.List[char]]::new()
    foreach ($set in $sets) {
        $characters.Add($set[[System.Security.Cryptography.RandomNumberGenerator]::GetInt32($set.Length)])
    }
    while ($characters.Count -lt $Length) {
        $characters.Add($all[[System.Security.Cryptography.RandomNumberGenerator]::GetInt32($all.Length)])
    }
    for ($index = $characters.Count - 1; $index -gt 0; $index--) {
        $swap = [System.Security.Cryptography.RandomNumberGenerator]::GetInt32($index + 1)
        $temporary = $characters[$index]
        $characters[$index] = $characters[$swap]
        $characters[$swap] = $temporary
    }
    return -join $characters
}

function ConvertTo-IRSecureString {
    param([Parameter(Mandatory)][string]$PlainText)
    $secure = [System.Security.SecureString]::new()
    foreach ($character in $PlainText.ToCharArray()) {
        $secure.AppendChar($character)
    }
    $secure.MakeReadOnly()
    return $secure
}

if (-not [string]::IsNullOrWhiteSpace($UserPrincipalName)) {
    $null = Set-IRTarget -Upn $UserPrincipalName
}

# ---------------------------------------------------------------------------
# Module management and service connections
# ---------------------------------------------------------------------------

function Get-IRModuleStatus {
    param([Parameter(Mandatory)][string]$Name)

    if (-not $script:IRModuleCatalog.Contains($Name)) {
        throw "Unknown module requirement '$Name'."
    }
    $requirement = $script:IRModuleCatalog[$Name]
    $available = Get-Module -ListAvailable -Name $Name -ErrorAction SilentlyContinue |
        Sort-Object -Property Version -Descending |
        Select-Object -First 1
    $loaded = Get-Module -Name $Name -ErrorAction SilentlyContinue |
        Sort-Object -Property Version -Descending |
        Select-Object -First 1

    return [pscustomobject][ordered]@{
        Name = $Name
        Required = $requirement.MinimumVersion
        Available = if ($available) { [version]$available.Version } else { $null }
        Loaded = if ($loaded) { [version]$loaded.Version } else { $null }
        MeetsMinimum = $null -ne $available -and [version]$available.Version -ge [version]$requirement.MinimumVersion
        Optional = [bool]$requirement.Optional
        Purpose = [string]$requirement.Purpose
        Path = if ($available) { $available.Path } else { $null }
    }
}

function Install-IRModule {
    [CmdletBinding(SupportsShouldProcess)]
    param([Parameter(Mandatory)][string]$Name)

    if (-not $script:IRModuleCatalog.Contains($Name)) {
        throw "Unknown module requirement '$Name'."
    }
    if (-not $script:IR.InstallMissingModules) {
        throw "Module '$Name' is missing or outdated. Restart with -InstallMissingModules, or install it manually from PSGallery."
    }

    $minimum = [version]$script:IRModuleCatalog[$Name].MinimumVersion
    if (-not $PSCmdlet.ShouldProcess("$Name (minimum $minimum)", 'Install module from PSGallery for CurrentUser')) {
        return
    }

    Write-IRInfo "Installing the current PSGallery release of '$Name'..."
    if (Get-Command -Name Install-PSResource -ErrorAction SilentlyContinue) {
        Install-PSResource -Name $Name -Repository PSGallery -Scope CurrentUser -TrustRepository -AcceptLicense -ErrorAction Stop
    }
    elseif (Get-Command -Name Install-Module -ErrorAction SilentlyContinue) {
        Install-Module -Name $Name -Repository PSGallery -Scope CurrentUser -MinimumVersion $minimum -Force -AllowClobber -ErrorAction Stop
    }
    else {
        throw 'Neither Install-PSResource nor Install-Module is available.'
    }

    $after = Get-IRModuleStatus -Name $Name
    if (-not $after.MeetsMinimum) {
        throw "Installation completed, but '$Name' at or above $minimum is still not discoverable."
    }
    Write-IRSuccess "Installed $Name $($after.Available)."
}

function Import-IRModule {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Name)

    $status = Get-IRModuleStatus -Name $Name
    if (-not $status.MeetsMinimum) {
        Install-IRModule -Name $Name
        $status = Get-IRModuleStatus -Name $Name
    }

    if ($status.Loaded -and $status.Loaded -ge $status.Required) {
        return Get-Module -Name $Name |
            Sort-Object Version -Descending |
            Select-Object -First 1
    }

    if ($status.Loaded -and $Name -like 'Microsoft.Graph*') {
        throw "A lower version of '$Name' is already loaded. Close this PowerShell process, open a fresh PowerShell 7.6 window, and run the console again."
    }

    Import-Module -Name $Name -MinimumVersion $status.Required -ErrorAction Stop
    $loaded = Get-Module -Name $Name |
        Sort-Object Version -Descending |
        Select-Object -First 1
    if (-not $loaded -or [version]$loaded.Version -lt $status.Required) {
        throw "Failed to import '$Name' at or above $($status.Required)."
    }
    return $loaded
}

function Assert-IRCommand {
    param(
        [Parameter(Mandatory)][string[]]$Name,
        [string]$Service
    )

    $missing = @($Name | Where-Object {
        $null -eq (Get-Command -Name $_ -ErrorAction SilentlyContinue)
    })
    if ($missing.Count -gt 0) {
        $suffix = if ($Service) { " Connect to $Service and verify your assigned roles." } else { '' }
        throw "Required command(s) are unavailable: $($missing -join ', ').$suffix"
    }
}

function Test-IRGraphConnected {
    try {
        $context = Get-MgContext -ErrorAction Stop
        return $null -ne $context -and -not [string]::IsNullOrWhiteSpace([string]$context.TenantId)
    }
    catch {
        return $false
    }
}

function Test-IRGraphWriteScope {
    param([AllowNull()][string]$Scope)

    if ([string]::IsNullOrWhiteSpace($Scope)) {
        return $false
    }
    return $Scope -match '(?i)(ReadWrite|\.Write(?:\.|$)|Mail\.Send$|RevokeSessions|PasswordProfile)'
}

function Test-IRGraphScopeSatisfied {
    param(
        [Parameter(Mandatory)][string]$RequestedScope,
        [AllowEmptyCollection()][string[]]$GrantedScopes = @()
    )

    if ($RequestedScope -in @($GrantedScopes)) {
        return $true
    }

    # Microsoft identity tokens can expose a previously consented write-capable
    # superset even when this invocation requested only the read permission.
    # Recognize only the explicit pairs reviewed by the Audit-mode mapper.
    $reviewedSuperset = @{
        'User.Read' = 'User.ReadWrite.All'
        'User.Read.All' = 'User.ReadWrite.All'
        'Policy.Read.All' = 'Policy.ReadWrite.ConditionalAccess'
        'DelegatedPermissionGrant.Read.All' = 'DelegatedPermissionGrant.ReadWrite.All'
        'AppRoleAssignment.Read.All' = 'AppRoleAssignment.ReadWrite.All'
        'DeviceManagementManagedDevices.Read.All' = 'DeviceManagementManagedDevices.ReadWrite.All'
    }
    return $reviewedSuperset.ContainsKey($RequestedScope) -and
        $reviewedSuperset[$RequestedScope] -in @($GrantedScopes)
}

function ConvertTo-IRAuditGraphScope {
    param([Parameter(Mandatory)][AllowEmptyCollection()][string[]]$Scopes)

    $readOnlyReplacement = @{
        'User.RevokeSessions.All' = 'User.Read.All'
        'User-PasswordProfile.ReadWrite.All' = 'User.Read.All'
        'User.ReadWrite.All' = 'User.Read.All'
        'Policy.ReadWrite.ConditionalAccess' = 'Policy.Read.All'
        'Mail.Send' = 'User.Read'
        'DelegatedPermissionGrant.ReadWrite.All' = 'DelegatedPermissionGrant.Read.All'
        'AppRoleAssignment.ReadWrite.All' = 'AppRoleAssignment.Read.All'
        'DeviceManagementManagedDevices.ReadWrite.All' = 'DeviceManagementManagedDevices.Read.All'
    }

    $normalized = [System.Collections.Generic.List[string]]::new()
    foreach ($scope in @($Scopes | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })) {
        if ($readOnlyReplacement.ContainsKey($scope)) {
            $normalized.Add($readOnlyReplacement[$scope])
            continue
        }
        if (Test-IRGraphWriteScope -Scope $scope) {
            throw "Audit mode has no reviewed read-only replacement for Microsoft Graph scope '$scope'."
        }
        $normalized.Add($scope)
    }
    return @($normalized | Sort-Object -Unique)
}

function Connect-IRGraph {
    [CmdletBinding()]
    param(
        [string[]]$Scopes = @('User.Read.All'),
        [string[]]$Modules = @('Microsoft.Graph.Users')
    )

    $null = Import-IRModule -Name 'Microsoft.Graph.Authentication'
    foreach ($module in @($Modules | Where-Object { $_ } | Sort-Object -Unique)) {
        $null = Import-IRModule -Name $module
    }

    $auditOnly = $script:IR.Mode -ne 'Live' -or $WhatIfPreference
    $requested = if ($auditOnly) {
        @(ConvertTo-IRAuditGraphScope -Scopes $Scopes)
    }
    else {
        @($Scopes | Where-Object { $_ } | Sort-Object -Unique)
    }
    $context = $null
    if (Test-IRGraphConnected) {
        $context = Get-MgContext
        # A tenant domain (contoso.onmicrosoft.com) is valid for Connect-MgGraph,
        # but Get-MgContext returns the tenant GUID. Compare only GUID-to-GUID.
        $configuredTenantIsGuid = [guid]::Empty
        $tenantMismatch = (-not $script:IR.TenantSelectionValidated) -or
            ([guid]::TryParse([string]$script:IR.TenantId, [ref]$configuredTenantIsGuid) -and
             [string]$context.TenantId -ine [string]$script:IR.TenantId)
        $missingScopes = @($requested | Where-Object {
            -not (Test-IRGraphScopeSatisfied -RequestedScope $_ -GrantedScopes @($context.Scopes))
        })
        $writeScopesInContext = @(if ($auditOnly) {
            $context.Scopes | Where-Object { Test-IRGraphWriteScope -Scope $_ }
        })
        $refreshBroadAuditContext = $writeScopesInContext.Count -gt 0 -and
            -not $script:IR.GraphBroadConsentAcknowledged
        if ($tenantMismatch -or $missingScopes.Count -gt 0 -or $refreshBroadAuditContext) {
            if ($tenantMismatch) {
                Write-IRWarn "The active Graph context is tenant $($context.TenantId), not $($script:IR.TenantId). Reconnecting."
            }
            elseif ($writeScopesInContext.Count -gt 0) {
                Write-IRInfo 'Reconnecting Graph without cached write-capable scopes for Audit mode.'
            }
            else {
                Write-IRInfo "Reconnecting Graph to request additional scope(s): $($missingScopes -join ', ')"
            }
            if (-not $auditOnly) {
                $requested = @($requested + @($context.Scopes) | Where-Object { $_ } | Sort-Object -Unique)
            }
            Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
            $context = $null
        }
    }

    if (-not $context) {
        $parameters = @{
            Scopes = $requested
            ContextScope = 'Process'
            NoWelcome = $true
            ErrorAction = 'Stop'
        }
        if (-not [string]::IsNullOrWhiteSpace($script:IR.TenantId)) {
            $parameters.TenantId = $script:IR.TenantId
        }
        if ($script:IR.UseDeviceAuthentication) {
            $parameters.UseDeviceCode = $true
        }
        Write-IRInfo "Connecting to Microsoft Graph with scope(s): $($requested -join ', ')"
        Connect-MgGraph @parameters | Out-Null
        $context = Get-MgContext -ErrorAction Stop
    }

    $stillMissing = @($requested | Where-Object {
        -not (Test-IRGraphScopeSatisfied -RequestedScope $_ -GrantedScopes @($context.Scopes))
    })
    if ($stillMissing.Count -gt 0) {
        throw "Graph connected, but consent is missing for: $($stillMissing -join ', ')."
    }

    $remainingWriteScopes = @(if ($auditOnly) {
        $context.Scopes | Where-Object { Test-IRGraphWriteScope -Scope $_ }
    })
    if ($remainingWriteScopes.Count -gt 0) {
        if (-not $script:IR.GraphBroadConsentAcknowledged) {
            Write-IRWarn 'The identity platform returned previously consented write-capable Graph scopes even though this Audit-mode connection requested only read scopes. The broader consent is recorded; tenant-changing operations remain blocked by the Audit-mode execution gateway.'
        }
        $script:IR.GraphBroadConsentAcknowledged = $true
    }

    $script:IR.Connections.Graph = $true
    $script:IR.TenantId = [string]$context.TenantId
    $script:IR.TenantSelectionValidated = $true
    Write-IRSuccess "Graph connected as $($context.Account) to tenant $($context.TenantId)."
    return $context
}

function Test-IRExchangeConnected {
    try {
        $connections = @(Get-ConnectionInformation -ErrorAction Stop)
        return @($connections | Where-Object {
            $_.State -eq 'Connected' -and
            [string]$_.ConnectionUri -notlike '*compliance.protection.outlook.com*' -and
            [string]$_.ConnectionUri -notlike '*ps.compliance.protection.outlook.com*'
        }).Count -gt 0
    }
    catch {
        return $false
    }
}

function Connect-IRExchange {
    [CmdletBinding()]
    param()

    $null = Import-IRModule -Name ExchangeOnlineManagement

    if (-not (Test-IRExchangeConnected)) {
        Write-IRInfo 'Connecting to Exchange Online...'
        $parameters = @{
            ShowBanner = $false
            ErrorAction = 'Stop'
        }
        $command = Get-Command Connect-ExchangeOnline -ErrorAction Stop
        if ($script:IR.UseDeviceAuthentication -and $command.Parameters.ContainsKey('Device')) {
            $parameters.Device = $true
        }
        if (-not [string]::IsNullOrWhiteSpace($script:IR.TargetUpn) -and
            $command.Parameters.ContainsKey('UserPrincipalName')) {
            $parameters.UserPrincipalName = $script:IR.TargetUpn
        }
        Connect-ExchangeOnline @parameters | Out-Null
    }
    if (-not (Test-IRExchangeConnected)) {
        throw 'Exchange Online did not report a connected REST session.'
    }

    $script:IR.Connections.Exchange = $true
    Write-IRSuccess 'Exchange Online connected.'
}

function Test-IRPurviewConnected {
    try {
        $connections = @(Get-ConnectionInformation -ErrorAction Stop)
        return @($connections | Where-Object {
            $_.State -eq 'Connected' -and
            ([string]$_.ConnectionUri -like '*compliance.protection.outlook.com*' -or
             [string]$_.ConnectionUri -like '*ps.compliance.protection.outlook.com*')
        }).Count -gt 0
    }
    catch {
        return $false
    }
}

function Connect-IRPurview {
    [CmdletBinding()]
    param()

    $null = Import-IRModule -Name ExchangeOnlineManagement
    if (-not (Test-IRPurviewConnected)) {
        Write-IRInfo 'Connecting to Microsoft Purview Security & Compliance PowerShell...'
        Connect-IPPSSession -EnableSearchOnlySession -ShowBanner:$false -ErrorAction Stop | Out-Null
    }
    if (-not (Test-IRPurviewConnected)) {
        throw 'Microsoft Purview did not report a connected session.'
    }

    $script:IR.Connections.Purview = $true
    Write-IRSuccess 'Microsoft Purview connected in search-only mode.'
}

function Connect-IRTeamService {
    [CmdletBinding()]
    param()

    $null = Import-IRModule -Name MicrosoftTeams
    Assert-IRCommand -Name 'Connect-MicrosoftTeams' -Service 'Microsoft Teams'
    if ($script:IR.Connections.Teams -and (Get-Command Get-CsTenant -ErrorAction SilentlyContinue)) {
        try {
            $null = Get-CsTenant -ErrorAction Stop
            Write-IRSuccess 'Microsoft Teams is already connected.'
            return
        }
        catch {
            $script:IR.Connections.Teams = $false
        }
    }
    Write-IRInfo 'Connecting to Microsoft Teams...'
    $parameters = @{ ErrorAction = 'Stop' }
    $command = Get-Command Connect-MicrosoftTeams -ErrorAction Stop
    if ($script:IR.UseDeviceAuthentication -and $command.Parameters.ContainsKey('UseDeviceAuthentication')) {
        $parameters.UseDeviceAuthentication = $true
    }
    Connect-MicrosoftTeams @parameters | Out-Null
    $script:IR.Connections.Teams = $true
    Write-IRSuccess 'Microsoft Teams connected.'
}

function Get-IRSharePointAdminUrl {
    param([AllowNull()][string]$AdminUrl)

    if (-not [string]::IsNullOrWhiteSpace($AdminUrl)) {
        if ($AdminUrl -notmatch '^https://[a-zA-Z0-9-]+-admin\.sharepoint\.(com|us|de|cn)/?$') {
            throw "'$AdminUrl' is not a recognized SharePoint Online admin-center URL."
        }
        return $AdminUrl.TrimEnd('/')
    }

    if ($script:IR.TenantId -match '^([a-zA-Z0-9-]+)\.onmicrosoft\.com$') {
        return "https://$($Matches[1])-admin.sharepoint.com"
    }

    try {
        $null = Connect-IRGraph -Scopes @('Organization.Read.All') -Modules @('Microsoft.Graph.Identity.DirectoryManagement')
        $organization = Get-MgOrganization -Property Id, VerifiedDomains -ErrorAction Stop
        $initialDomain = @($organization.VerifiedDomains | Where-Object { $_.IsInitial } | Select-Object -First 1).Name
        if ($initialDomain -match '^([a-zA-Z0-9-]+)\.onmicrosoft\.com$') {
            return "https://$($Matches[1])-admin.sharepoint.com"
        }
    }
    catch {
        Write-IRWarn "Could not derive the SharePoint admin URL: $($_.Exception.Message)"
    }

    return Read-IRText -Prompt 'SharePoint admin URL (for example, https://contoso-admin.sharepoint.com)'
}

function Connect-IRSharePoint {
    [CmdletBinding()]
    param([string]$AdminUrl)

    if (-not $IsWindows) {
        throw 'The SharePoint Online Management Shell used by this feature requires Windows.'
    }
    $null = Import-IRModule -Name 'Microsoft.Online.SharePoint.PowerShell'
    Assert-IRCommand -Name 'Connect-SPOService' -Service 'SharePoint Online'
    $resolvedUrl = Get-IRSharePointAdminUrl -AdminUrl $AdminUrl
    Write-IRInfo "Connecting to SharePoint Online at $resolvedUrl..."
    Connect-SPOService -Url $resolvedUrl -ErrorAction Stop
    $script:IR.Connections.SharePoint = $true
    Write-IRSuccess 'SharePoint Online connected.'
    return $resolvedUrl
}

function Disconnect-IRService {
    [CmdletBinding(SupportsShouldProcess)]
    param()

    if ($PSCmdlet.ShouldProcess('Current process', 'Disconnect Microsoft 365 service sessions')) {
        try {
            if (Get-Command Disconnect-ExchangeOnline -ErrorAction SilentlyContinue) {
                Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue
            }
        }
        catch {
            Write-Verbose "Exchange disconnect failed: $($_.Exception.Message)"
        }
        try {
            if (Get-Command Disconnect-MgGraph -ErrorAction SilentlyContinue) {
                Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
            }
        }
        catch {
            Write-Verbose "Graph disconnect failed: $($_.Exception.Message)"
        }
        try {
            if (Get-Command Disconnect-MicrosoftTeams -ErrorAction SilentlyContinue) {
                Disconnect-MicrosoftTeams -ErrorAction SilentlyContinue | Out-Null
            }
        }
        catch {
            Write-Verbose "Teams disconnect failed: $($_.Exception.Message)"
        }
        try {
            if (Get-Command Disconnect-SPOService -ErrorAction SilentlyContinue) {
                Disconnect-SPOService -ErrorAction SilentlyContinue
            }
        }
        catch {
            Write-Verbose "SharePoint disconnect failed: $($_.Exception.Message)"
        }
        foreach ($key in @($script:IR.Connections.Keys)) {
            $script:IR.Connections[$key] = $false
        }
        $script:IR.GraphBroadConsentAcknowledged = $false
        Write-IRSuccess 'Service sessions disconnected.'
    }
}

function Get-IRConnectionStatus {
    $graphContext = $null
    if (Get-Command Get-MgContext -ErrorAction SilentlyContinue) {
        $graphContext = Get-MgContext -ErrorAction SilentlyContinue
    }
    $script:IR.Connections.Graph = $null -ne $graphContext
    $script:IR.Connections.Exchange = Test-IRExchangeConnected
    $script:IR.Connections.Purview = Test-IRPurviewConnected

    return @(
        [pscustomobject]@{ Service = 'Microsoft Graph'; Connected = $script:IR.Connections.Graph; Identity = if ($graphContext) { $graphContext.Account } else { $null } }
        [pscustomobject]@{ Service = 'Exchange Online'; Connected = $script:IR.Connections.Exchange; Identity = $null }
        [pscustomobject]@{ Service = 'Microsoft Purview'; Connected = $script:IR.Connections.Purview; Identity = $null }
        [pscustomobject]@{ Service = 'Microsoft Teams'; Connected = $script:IR.Connections.Teams; Identity = $null }
        [pscustomobject]@{ Service = 'SharePoint Online'; Connected = $script:IR.Connections.SharePoint; Identity = $null }
    )
}

function Get-IRGraphUser {
    [CmdletBinding()]
    param([string]$UserPrincipalName)

    $upn = Resolve-IRTarget -Upn $UserPrincipalName
    $null = Connect-IRGraph -Scopes @('User.Read.All') -Modules @('Microsoft.Graph.Users')
    return Invoke-IRRetry -Operation {
        Get-MgUser -UserId $upn -Property Id, UserPrincipalName, DisplayName, AccountEnabled, Mail, MySite -ErrorAction Stop
    }
}

# ---------------------------------------------------------------------------
# Preflight
# ---------------------------------------------------------------------------

function Test-IRPreflight {
    [CmdletBinding()]
    param([switch]$Online)

    $checks = [System.Collections.Generic.List[object]]::new()
    $addCheck = {
        param($Name, $Status, $Required, $Detail)
        $checks.Add([pscustomobject][ordered]@{
            Check = $Name
            Status = $Status
            Required = $Required
            Detail = $Detail
        })
    }

    $runtimeOk = $PSVersionTable.PSEdition -eq 'Core' -and
        [version]$PSVersionTable.PSVersion -ge $script:IRMinimumPowerShell
    & $addCheck 'PowerShell runtime' $(if ($runtimeOk) { 'Pass' } else { 'Fail' }) $true "$($PSVersionTable.PSEdition) $($PSVersionTable.PSVersion)"

    & $addCheck 'Operating system' 'Info' $false "$($PSVersionTable.OS)"
    & $addCheck 'Execution policy' 'Info' $false "$(Get-ExecutionPolicy)"

    foreach ($name in $script:IRModuleCatalog.Keys) {
        $status = Get-IRModuleStatus -Name $name
        $checkStatus = if ($status.MeetsMinimum) {
            'Pass'
        }
        elseif ($status.Optional) {
            'Warn'
        }
        else {
            'Fail'
        }
        $detail = if ($status.Available) {
            "Installed $($status.Available); minimum $($status.Required)"
        }
        else {
            "Not installed; minimum $($status.Required)"
        }
        & $addCheck "Module: $name" $checkStatus (-not $status.Optional) $detail
    }

    try {
        $null = New-Item -ItemType Directory -Path $script:IR.OutputRoot -Force
        if ($script:IR.OutputRootWasDefault) {
            $null = Protect-IRCaseDirectory -Path $script:IR.OutputRoot
        }
        $testFile = Join-Path -Path $script:IR.OutputRoot -ChildPath ('.write-test-{0}.tmp' -f [guid]::NewGuid().ToString('N'))
        Set-Content -LiteralPath $testFile -Value 'test' -Encoding utf8
        Remove-Item -LiteralPath $testFile -Force
        & $addCheck 'Case output path' 'Pass' $true $script:IR.OutputRoot
    }
    catch {
        & $addCheck 'Case output path' 'Fail' $true $_.Exception.Message
    }

    if ($Online) {
        try {
            # Connect Exchange first. The current Exchange and Graph module
            # baselines bundle different MSAL versions, and Exchange-first
            # loading avoids the known Graph-first assembly collision.
            Connect-IRExchange
            & $addCheck 'Exchange authentication' 'Pass' $true 'Connected REST session'
        }
        catch {
            & $addCheck 'Exchange authentication' 'Fail' $true $_.Exception.Message
        }

        try {
            $null = Connect-IRGraph -Scopes @('User.Read.All') -Modules @('Microsoft.Graph.Users')
            $context = Get-MgContext
            & $addCheck 'Graph authentication' 'Pass' $true "$($context.Account) / $($context.TenantId)"
        }
        catch {
            & $addCheck 'Graph authentication' 'Fail' $true $_.Exception.Message
        }

        if ($script:IR.TargetUpn) {
            try {
                $user = Get-IRGraphUser -UserPrincipalName $script:IR.TargetUpn
                & $addCheck 'Target user lookup' 'Pass' $true "$($user.DisplayName) <$($user.UserPrincipalName)>"
            }
            catch {
                & $addCheck 'Target user lookup' 'Fail' $true $_.Exception.Message
            }
        }

        $commands = @(
            'Get-EXOMailbox',
            'Get-EXOMailboxPermission',
            'Get-EXORecipientPermission',
            'Get-MessageTraceV2',
            'Search-UnifiedAuditLog',
            'Get-MgUser',
            'Revoke-MgUserSignInSession',
            'Get-MgIdentityConditionalAccessPolicy',
            'Get-MgAuditLogSignIn',
            'Get-MgRiskyUser'
        )
        foreach ($command in $commands) {
            $available = $null -ne (Get-Command -Name $command -ErrorAction SilentlyContinue)
            & $addCheck "Command: $command" $(if ($available) { 'Pass' } else { 'Warn' }) $false $(if ($available) { 'Available' } else { 'Unavailable until service/role exposes it' })
        }
    }

    $requiredFailure = @($checks | Where-Object { $_.Required -and $_.Status -eq 'Fail' }).Count -gt 0
    $overall = if ($requiredFailure) {
        'Fail'
    }
    elseif (@($checks | Where-Object Status -eq 'Warn').Count -gt 0) {
        'Warn'
    }
    else {
        'Pass'
    }

    return [pscustomobject]@{
        TimestampUtc = [datetime]::UtcNow
        Online = $Online.IsPresent
        Overall = $overall
        Checks = $checks.ToArray()
    }
}

function Show-IRPreflight {
    param([Parameter(Mandatory)][psobject]$Report)

    Write-IRConsole
    Write-IRConsole -Message 'PRE-FLIGHT REPORT' -Color Cyan
    Write-IRConsole -Message ('-' * 100) -Color DarkGray
    $Report.Checks | Format-Table -Property Check, Status, Required, Detail -Wrap -AutoSize | Out-Host
    $color = switch ($Report.Overall) {
        'Pass' { [System.ConsoleColor]::Green }
        'Warn' { [System.ConsoleColor]::Yellow }
        default { [System.ConsoleColor]::Red }
    }
    Write-IRConsole -Message "Overall: $($Report.Overall)" -Color $color
    Write-IRConsole
}

# ---------------------------------------------------------------------------
# Account containment and identity remediation
# ---------------------------------------------------------------------------

function Revoke-IRUserSession {
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    param([string]$UserPrincipalName)

    $user = Get-IRGraphUser -UserPrincipalName $UserPrincipalName
    $null = Connect-IRGraph -Scopes @('User.RevokeSessions.All', 'User.Read.All') -Modules @(
        'Microsoft.Graph.Users',
        'Microsoft.Graph.Users.Actions'
    )

    $operation = {
        Invoke-IRRetry -Operation {
            Revoke-MgUserSignInSession -UserId $user.Id -ErrorAction Stop
        } | Out-Null
    }
    return Invoke-IRChange -Target $user.UserPrincipalName -Action 'Revoke all sign-in sessions' -Impact High -ExactConfirmation $user.UserPrincipalName -Operation $operation -Confirm:$false
}

function Show-IRSecureString {
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)][System.Security.SecureString]$SecureString)

    $pointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecureString)
    try {
        return [Runtime.InteropServices.Marshal]::PtrToStringBSTR($pointer)
    }
    finally {
        [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($pointer)
    }
}

function Reset-IRUserPassword {
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    param(
        [string]$UserPrincipalName,
        [ValidateRange(14, 128)][int]$Length = 24,
        [bool]$ForceChangePasswordNextSignIn = $true,
        [switch]$DisplayOnce
    )

    $user = Get-IRGraphUser -UserPrincipalName $UserPrincipalName
    $null = Connect-IRGraph -Scopes @(
        'User.Read.All',
        'User-PasswordProfile.ReadWrite.All'
    ) -Modules @('Microsoft.Graph.Users')

    $operation = {
        $plainTextPassword = New-IRRandomPassword -Length $Length
        $passwordProfile = @{
            Password = $plainTextPassword
            ForceChangePasswordNextSignIn = $ForceChangePasswordNextSignIn
            ForceChangePasswordNextSignInWithMfa = $false
        }
        try {
            Invoke-IRRetry -Operation {
                Update-MgUser -UserId $user.Id -PasswordProfile $passwordProfile -ErrorAction Stop
            } | Out-Null
            $secure = ConvertTo-IRSecureString -PlainText $plainTextPassword
            return [pscustomobject]@{
                UserPrincipalName = $user.UserPrincipalName
                Password = $secure
                ForceChangePasswordNextSignIn = $ForceChangePasswordNextSignIn
                ResetAtUtc = [datetime]::UtcNow
            }
        }
        finally {
            $passwordProfile.Password = $null
            $plainTextPassword = $null
        }
    }

    $result = Invoke-IRChange -Target $user.UserPrincipalName -Action 'Reset user password' -Impact Critical -ExactConfirmation "RESET $($user.UserPrincipalName)" -Operation $operation -Details @{
        ForceChangePasswordNextSignIn = $ForceChangePasswordNextSignIn
        Length = $Length
    } -Confirm:$false

    if ($result -and $DisplayOnce) {
        $plain = Show-IRSecureString -SecureString $result.Password
        try {
            Write-IRConsole
            Write-IRConsole -Message "Temporary password for $($result.UserPrincipalName): $plain" -Color Yellow
            Write-IRWarn 'Deliver it out-of-band. It is not written to the action log or evidence files.'
            Write-IRConsole
        }
        finally {
            $plain = $null
        }
    }
    elseif ($result) {
        Write-IRInfo 'The returned result contains the password as a SecureString. Use Show-IRSecureString only when necessary.'
    }
    return $result
}

function Set-IRUserSignIn {
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    param(
        [string]$UserPrincipalName,
        [Parameter(Mandatory)]
        [ValidateSet('Block', 'Unblock')]
        [string]$Action
    )

    $user = Get-IRGraphUser -UserPrincipalName $UserPrincipalName
    $null = Connect-IRGraph -Scopes @('User.ReadWrite.All') -Modules @('Microsoft.Graph.Users')
    $enabled = $Action -eq 'Unblock'
    $operation = {
        Invoke-IRRetry -Operation {
            Update-MgUser -UserId $user.Id -AccountEnabled:$enabled -ErrorAction Stop
        } | Out-Null
    }
    $token = "$($Action.ToUpperInvariant()) $($user.UserPrincipalName)"
    return Invoke-IRChange -Target $user.UserPrincipalName -Action "$Action user sign-in" -Impact Critical -ExactConfirmation $token -Operation $operation -Details @{
        PreviousAccountEnabled = $user.AccountEnabled
        NewAccountEnabled = $enabled
    } -Confirm:$false
}

function Get-IRConditionalAccessReview {
    [CmdletBinding()]
    param([string]$UserPrincipalName)

    $user = Get-IRGraphUser -UserPrincipalName $UserPrincipalName
    $null = Connect-IRGraph -Scopes @('Policy.Read.All', 'User.Read.All') -Modules @(
        'Microsoft.Graph.Identity.SignIns',
        'Microsoft.Graph.Users'
    )

    $policies = @(Invoke-IRRetry -Operation {
        Get-MgIdentityConditionalAccessPolicy -All -ErrorAction Stop
    })

    $rows = foreach ($policy in $policies) {
        $conditions = Get-IRProperty -InputObject $policy -Name Conditions
        $users = Get-IRProperty -InputObject $conditions -Name Users
        $includeUsers = @(Get-IRProperty -InputObject $users -Name IncludeUsers -Default @())
        $excludeUsers = @(Get-IRProperty -InputObject $users -Name ExcludeUsers -Default @())
        $includeGroups = @(Get-IRProperty -InputObject $users -Name IncludeGroups -Default @())
        $excludeGroups = @(Get-IRProperty -InputObject $users -Name ExcludeGroups -Default @())
        $grant = Get-IRProperty -InputObject $policy -Name GrantControls
        $builtIn = @(Get-IRProperty -InputObject $grant -Name BuiltInControls -Default @())
        $authStrength = Get-IRProperty -InputObject $grant -Name AuthenticationStrength

        [pscustomobject]@{
            PolicyId = $policy.Id
            DisplayName = $policy.DisplayName
            State = $policy.State
            DirectUserIncluded = $includeUsers -contains $user.Id
            AllUsersIncluded = $includeUsers -contains 'All'
            DirectUserExcluded = $excludeUsers -contains $user.Id
            IncludeGroupCount = $includeGroups.Count
            ExcludeGroupCount = $excludeGroups.Count
            RequiresMfa = $builtIn -contains 'mfa'
            BlocksAccess = $builtIn -contains 'block'
            AuthenticationStrength = if ($authStrength) { $authStrength.DisplayName } else { $null }
            DirectScopeAssessment = if ($excludeUsers -contains $user.Id) {
                'Excluded directly'
            }
            elseif ($includeUsers -contains $user.Id -or $includeUsers -contains 'All') {
                'Included directly or through All'
            }
            elseif ($includeGroups.Count -gt 0) {
                'Group membership evaluation required'
            }
            else {
                'No direct match'
            }
        }
    }

    $script:IR.Results.ConditionalAccess = @($rows)
    $null = Add-IRActionLog -Action 'Review Conditional Access policies' -Status Read -Target $user.UserPrincipalName -Details @{
        PolicyCount = @($rows).Count
        Note = 'Direct scope assessment does not calculate group membership or every condition.'
    }
    return $rows
}

function New-IRTemporaryMfaPolicy {
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    param(
        [string]$UserPrincipalName,
        [ValidateRange(1, 168)][int]$LifetimeHours = 24,
        [ValidateSet('enabledForReportingButNotEnabled', 'enabled')]
        [string]$State = 'enabledForReportingButNotEnabled'
    )

    $user = Get-IRGraphUser -UserPrincipalName $UserPrincipalName
    $null = Connect-IRGraph -Scopes @(
        'Policy.ReadWrite.ConditionalAccess',
        'User.Read.All'
    ) -Modules @(
        'Microsoft.Graph.Identity.SignIns',
        'Microsoft.Graph.Users'
    )

    $expires = [datetime]::UtcNow.AddHours($LifetimeHours)
    $displayName = 'IR Targeted MFA - {0} - {1}' -f $user.UserPrincipalName, $expires.ToString('yyyyMMddTHHmmssZ')
    $description = 'ManagedBy=M365-IR-Console;CaseId={0};Target={1};ExpiresUtc={2}' -f $script:IR.CaseId, $user.UserPrincipalName, $expires.ToString('o')

    $existing = @(Invoke-IRRetry -Operation {
        Get-MgIdentityConditionalAccessPolicy -All -ErrorAction Stop
    } | Where-Object {
        $_.DisplayName -eq $displayName -or
        ([string]$_.Description -like "*ManagedBy=M365-IR-Console*Target=$($user.UserPrincipalName)*")
    })
    if ($existing.Count -gt 0) {
        Write-IRWarn 'A managed targeted-MFA policy already exists for this user.'
        return $existing
    }

    $body = @{
        DisplayName = $displayName
        Description = $description
        State = $State
        Conditions = @{
            ClientAppTypes = @('all')
            Users = @{
                IncludeUsers = @($user.Id)
            }
            Applications = @{
                IncludeApplications = @('All')
            }
        }
        GrantControls = @{
            Operator = 'OR'
            BuiltInControls = @('mfa')
        }
    }

    $operation = {
        Invoke-IRRetry -Operation {
            New-MgIdentityConditionalAccessPolicy -BodyParameter $body -ErrorAction Stop
        }
    }
    $token = if ($State -eq 'enabled') { "ENABLE MFA $($user.UserPrincipalName)" } else { "CREATE MFA $($user.UserPrincipalName)" }
    return Invoke-IRChange -Target $displayName -Action "Create targeted MFA Conditional Access policy in state '$State'" -Impact High -ExactConfirmation $token -Operation $operation -Details @{
        TargetUserId = $user.Id
        ExpiresUtc = $expires
        State = $State
    } -Confirm:$false
}

function Get-IRManagedConditionalAccessPolicy {
    [CmdletBinding()]
    param([switch]$ExpiredOnly)

    $null = Connect-IRGraph -Scopes @('Policy.Read.All') -Modules @('Microsoft.Graph.Identity.SignIns')
    $now = [datetime]::UtcNow
    $managed = @(Invoke-IRRetry -Operation {
        Get-MgIdentityConditionalAccessPolicy -All -ErrorAction Stop
    } | Where-Object {
        [string]$_.Description -like '*ManagedBy=M365-IR-Console*'
    })

    foreach ($policy in $managed) {
        $expires = $null
        if ([string]$policy.Description -match 'ExpiresUtc=([^;]+)') {
            $parsed = [datetime]::MinValue
            if ([datetime]::TryParse($Matches[1], [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::RoundtripKind, [ref]$parsed)) {
                $expires = $parsed.ToUniversalTime()
            }
        }
        if (-not $ExpiredOnly -or ($expires -and $expires -le $now)) {
            [pscustomobject]@{
                Id = $policy.Id
                DisplayName = $policy.DisplayName
                State = $policy.State
                ExpiresUtc = $expires
                Expired = $null -ne $expires -and $expires -le $now
                Description = $policy.Description
                Policy = $policy
            }
        }
    }
}

function Remove-IRManagedConditionalAccessPolicy {
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    param(
        [Parameter(Mandatory)]
        [object[]]$Policy
    )

    $null = Connect-IRGraph -Scopes @('Policy.ReadWrite.ConditionalAccess') -Modules @('Microsoft.Graph.Identity.SignIns')
    $removed = [System.Collections.Generic.List[object]]::new()
    foreach ($item in @($Policy)) {
        $id = [string](Get-IRProperty -InputObject $item -Name Id)
        $name = [string](Get-IRProperty -InputObject $item -Name DisplayName -Default $id)
        if ([string]::IsNullOrWhiteSpace($id)) {
            throw 'A selected policy has no ID.'
        }
        $operation = {
            Invoke-IRRetry -Operation {
                Remove-MgIdentityConditionalAccessPolicy -ConditionalAccessPolicyId $id -ErrorAction Stop
            } | Out-Null
            return $item
        }
        $result = Invoke-IRChange -Target "$name ($id)" -Action 'Delete managed Conditional Access policy' -Impact High -ExactConfirmation "DELETE $id" -Operation $operation -Confirm:$false
        if ($result) {
            $removed.Add($result)
        }
    }
    return $removed.ToArray()
}

function Invoke-IRContainmentRunbook {
    [CmdletBinding()]
    param([string]$UserPrincipalName)

    $upn = Resolve-IRTarget -Upn $UserPrincipalName
    Write-IRConsole
    Write-IRConsole -Message "CONTAINMENT RUNBOOK: $upn" -Color Red
    Write-IRWarn "Current execution mode: $($script:IR.Mode)"

    $results = [ordered]@{}
    if (Read-IRYesNo -Prompt 'Block user sign-in?') {
        try {
            $results.BlockSignIn = Set-IRUserSignIn -UserPrincipalName $upn -Action Block
        }
        catch {
            $results.BlockSignIn = "Failed: $($_.Exception.Message)"
            Write-IRFailure -Message ([string]$results.BlockSignIn)
        }
    }
    if (Read-IRYesNo -Prompt 'Revoke all user sessions?' -DefaultYes) {
        try {
            $results.RevokeSessions = Revoke-IRUserSession -UserPrincipalName $upn
        }
        catch {
            $results.RevokeSessions = "Failed: $($_.Exception.Message)"
            Write-IRFailure -Message ([string]$results.RevokeSessions)
        }
    }
    if (Read-IRYesNo -Prompt 'Reset the user password?') {
        try {
            $results.PasswordReset = Reset-IRUserPassword -UserPrincipalName $upn -DisplayOnce
        }
        catch {
            $results.PasswordReset = "Failed: $($_.Exception.Message)"
            Write-IRFailure -Message ([string]$results.PasswordReset)
        }
    }
    if (Read-IRYesNo -Prompt 'Create a targeted Conditional Access MFA policy in report-only mode?') {
        try {
            $results.TargetedMfa = New-IRTemporaryMfaPolicy -UserPrincipalName $upn
        }
        catch {
            $results.TargetedMfa = "Failed: $($_.Exception.Message)"
            Write-IRFailure -Message ([string]$results.TargetedMfa)
        }
    }

    return [pscustomobject]$results
}

# ---------------------------------------------------------------------------
# Message trace and phishing investigation
# ---------------------------------------------------------------------------

function Get-IRAcceptedDomain {
    [CmdletBinding()]
    param()

    Connect-IRExchange
    if (-not (Get-Command Get-AcceptedDomain -ErrorAction SilentlyContinue)) {
        return @()
    }
    return @(Invoke-IRRetry -Operation {
        Get-AcceptedDomain -ErrorAction Stop
    } | ForEach-Object {
        [string]$_.DomainName
    } | Where-Object {
        -not [string]::IsNullOrWhiteSpace($_)
    } | Sort-Object -Unique)
}

function Get-IRMessageTrace {
    [CmdletBinding()]
    param(
        [string]$UserPrincipalName,
        [ValidateSet('Sent', 'Received', 'Both')]
        [string]$Direction = 'Both',
        [ValidateRange(1, 90)]
        [int]$DaysBack = $script:IR.Days,
        [datetime]$StartDateUtc,
        [datetime]$EndDateUtc,
        [AllowEmptyString()][string]$SubjectContains = '',
        [ValidateRange(1, 5000)][int]$PageSize = 5000,
        [ValidateRange(1, 500000)][int]$MaximumResults = 100000,
        [ValidateRange(1, 95)][int]$MaximumQueries = 90
    )

    $upn = Resolve-IRTarget -Upn $UserPrincipalName
    Connect-IRExchange
    Assert-IRCommand -Name 'Get-MessageTraceV2' -Service 'Exchange Online'

    $end = if ($PSBoundParameters.ContainsKey('EndDateUtc')) {
        $EndDateUtc.ToUniversalTime()
    }
    else {
        [datetime]::UtcNow
    }
    $start = if ($PSBoundParameters.ContainsKey('StartDateUtc')) {
        $StartDateUtc.ToUniversalTime()
    }
    else {
        $end.AddDays(-$DaysBack)
    }
    $retentionFloor = [datetime]::UtcNow.AddDays(-90)
    if ($start -lt $retentionFloor) {
        Write-IRWarn 'Message trace retains at most 90 days. The start time was moved to the retention boundary.'
        $start = $retentionFloor
    }
    if ($start -ge $end) {
        throw 'Message trace StartDateUtc must be earlier than EndDateUtc.'
    }

    $directions = if ($Direction -eq 'Both') { @('Sent', 'Received') } else { @($Direction) }
    $results = [System.Collections.Generic.List[object]]::new()
    $seen = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $queryCount = 0
    $incomplete = $false

    foreach ($currentDirection in $directions) {
        $windowEnd = $end
        while ($windowEnd -gt $start -and $results.Count -lt $MaximumResults) {
            $windowStart = $windowEnd.AddDays(-10)
            if ($windowStart -lt $start) {
                $windowStart = $start
            }
            $cursorEnd = $windowEnd
            $cursorRecipient = $null

            while ($results.Count -lt $MaximumResults) {
                if ($queryCount -ge $MaximumQueries) {
                    $incomplete = $true
                    Write-IRWarn "Message trace stopped at the configured $MaximumQueries-query ceiling."
                    break
                }
                $queryCount++

                $parameters = @{
                    StartDate = $windowStart
                    EndDate = $cursorEnd
                    ResultSize = $PageSize
                    ErrorAction = 'Stop'
                }
                if ($currentDirection -eq 'Sent') {
                    $parameters.SenderAddress = $upn
                }
                else {
                    $parameters.RecipientAddress = $upn
                }
                if (-not [string]::IsNullOrWhiteSpace($cursorRecipient)) {
                    $parameters.StartingRecipientAddress = $cursorRecipient
                }

                $batch = @(Invoke-IRRetry -Operation {
                    Get-MessageTraceV2 @parameters
                })
                if ($batch.Count -eq 0) {
                    break
                }

                foreach ($record in $batch) {
                    $received = [datetime](Get-IRProperty -InputObject $record -Name Received -Default [datetime]::MinValue)
                    $senderAddress = [string](Get-IRProperty -InputObject $record -Name SenderAddress)
                    $recipient = [string](Get-IRProperty -InputObject $record -Name RecipientAddress)
                    $subject = [string](Get-IRProperty -InputObject $record -Name Subject)
                    if (-not [string]::IsNullOrWhiteSpace($SubjectContains) -and $subject -notlike "*$SubjectContains*") {
                        continue
                    }
                    $traceId = [string](Get-IRProperty -InputObject $record -Name MessageTraceId)
                    $messageId = [string](Get-IRProperty -InputObject $record -Name MessageId)
                    $key = '{0}|{1}|{2:o}|{3}|{4}' -f $currentDirection, $traceId, $received.ToUniversalTime(), $recipient, $messageId
                    if ($seen.Add($key)) {
                        $results.Add([pscustomobject][ordered]@{
                            ReceivedUtc = $received.ToUniversalTime()
                            Direction = $currentDirection
                            SenderAddress = $senderAddress
                            RecipientAddress = $recipient
                            Subject = $subject
                            Status = Get-IRProperty -InputObject $record -Name Status
                            Size = Get-IRProperty -InputObject $record -Name Size
                            MessageId = $messageId
                            MessageTraceId = $traceId
                            FromIP = Get-IRProperty -InputObject $record -Name FromIP
                            ToIP = Get-IRProperty -InputObject $record -Name ToIP
                        })
                    }
                    if ($results.Count -ge $MaximumResults) {
                        $incomplete = $true
                        break
                    }
                }

                if ($batch.Count -lt $PageSize) {
                    break
                }
                $last = $batch[-1]
                $nextEnd = [datetime](Get-IRProperty -InputObject $last -Name Received)
                $nextRecipient = [string](Get-IRProperty -InputObject $last -Name RecipientAddress)
                if ($nextEnd -eq $cursorEnd -and $nextRecipient -eq $cursorRecipient) {
                    $incomplete = $true
                    Write-IRWarn "Message trace pagination stalled at $cursorEnd / $cursorRecipient. Narrow the time range for complete coverage."
                    break
                }
                $cursorEnd = $nextEnd
                $cursorRecipient = $nextRecipient
            }

            if ($queryCount -ge $MaximumQueries) {
                break
            }
            # Overlap exactly at the boundary and rely on the record key to
            # deduplicate. This avoids a precision gap between service windows.
            $windowEnd = $windowStart
        }
    }

    $ordered = @($results.ToArray() | Sort-Object -Property ReceivedUtc -Descending)
    $script:IR.Results.MessageTrace = $ordered
    $script:IR.Results.MessageTraceMetadata = [pscustomobject]@{
        StartUtc = $start
        EndUtc = $end
        Direction = $Direction
        Records = $ordered.Count
        Queries = $queryCount
        Incomplete = $incomplete
        MaximumResults = $MaximumResults
    }
    $null = Add-IRActionLog -Action 'Query message trace V2' -Status Read -Target $upn -Details @{
        StartUtc = $script:IR.Results.MessageTraceMetadata.StartUtc
        EndUtc = $script:IR.Results.MessageTraceMetadata.EndUtc
        Direction = $script:IR.Results.MessageTraceMetadata.Direction
        Records = $script:IR.Results.MessageTraceMetadata.Records
        Queries = $script:IR.Results.MessageTraceMetadata.Queries
        Incomplete = $script:IR.Results.MessageTraceMetadata.Incomplete
        MaximumResults = $script:IR.Results.MessageTraceMetadata.MaximumResults
    }
    if ($incomplete) {
        Write-IRWarn 'The returned trace is explicitly marked incomplete in the action log.'
    }
    return $ordered
}

function Get-IRMessageAnalysis {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]]$Messages,
        [string]$UserPrincipalName,
        [string[]]$InternalDomains,
        [string]$TimeZoneId = [System.TimeZoneInfo]::Local.Id
    )

    $upn = Resolve-IRTarget -Upn $UserPrincipalName
    $items = @($Messages)
    $targetDomain = ($upn -split '@', 2)[1]
    $domains = @($InternalDomains + $targetDomain | Where-Object { $_ } | ForEach-Object { $_.ToLowerInvariant() } | Sort-Object -Unique)
    $timeZone = [System.TimeZoneInfo]::FindSystemTimeZoneById($TimeZoneId)

    $anomalies = [System.Collections.Generic.List[object]]::new()
    $sent = @($items | Where-Object Direction -eq 'Sent')
    $received = @($items | Where-Object Direction -eq 'Received')

    $sentAfterHours = @($sent | Where-Object {
        $local = [System.TimeZoneInfo]::ConvertTimeFromUtc(([datetime]$_.ReceivedUtc).ToUniversalTime(), $timeZone)
        $local.Hour -lt 6 -or $local.Hour -ge 22
    })
    if ($sentAfterHours.Count -gt 0) {
        $anomalies.Add([pscustomobject]@{
            Type = 'After-hours sending'
            Severity = 'Medium'
            Count = $sentAfterHours.Count
            Detail = "Sent outside 06:00-22:00 in $TimeZoneId"
        })
    }

    $massMail = @($sent | Group-Object -Property Subject | Where-Object {
        -not [string]::IsNullOrWhiteSpace($_.Name) -and $_.Count -ge 10
    })
    foreach ($group in $massMail) {
        $anomalies.Add([pscustomobject]@{
            Type = 'Repeated subject'
            Severity = 'Medium'
            Count = $group.Count
            Detail = $group.Name
        })
    }

    $externalSent = @($sent | Where-Object {
        $domain = ([string]$_.RecipientAddress -split '@', 2)[-1].ToLowerInvariant()
        $domain -notin $domains
    })
    if ($sent.Count -ge 10 -and ($externalSent.Count / [double]$sent.Count) -ge 0.70) {
        $anomalies.Add([pscustomobject]@{
            Type = 'High external-recipient ratio'
            Severity = 'Medium'
            Count = $externalSent.Count
            Detail = '{0:P1} of sent trace rows are external' -f ($externalSent.Count / [double]$sent.Count)
        })
    }

    $largeExternal = @($externalSent | Where-Object {
        $size = Get-IRProperty -InputObject $_ -Name Size -Default 0
        $null -ne $size -and [double]$size -ge 10MB
    })
    if ($largeExternal.Count -gt 0) {
        $anomalies.Add([pscustomobject]@{
            Type = 'Large external messages'
            Severity = 'High'
            Count = $largeExternal.Count
            Detail = 'Trace rows at or above 10 MB'
        })
    }

    $suspiciousSubjectPattern = '(?i)\b(urgent|verify|suspend(?:ed)?|password|credential|invoice|payment|wire|gift card|confidential)\b'
    $suspiciousSubjects = @($items | Where-Object { [string]$_.Subject -match $suspiciousSubjectPattern })
    if ($suspiciousSubjects.Count -gt 0) {
        $anomalies.Add([pscustomobject]@{
            Type = 'Subject keyword heuristic'
            Severity = 'Low'
            Count = $suspiciousSubjects.Count
            Detail = 'Review manually; keyword matching is not a malware verdict.'
        })
    }

    $topRecipientDomains = @($sent | ForEach-Object {
        ([string]$_.RecipientAddress -split '@', 2)[-1].ToLowerInvariant()
    } | Where-Object { $_ } | Group-Object | Sort-Object Count -Descending | Select-Object -First 20 Name, Count)
    $topSenderDomains = @($received | ForEach-Object {
        ([string]$_.SenderAddress -split '@', 2)[-1].ToLowerInvariant()
    } | Where-Object { $_ } | Group-Object | Sort-Object Count -Descending | Select-Object -First 20 Name, Count)

    return [pscustomobject][ordered]@{
        Target = $upn
        GeneratedUtc = [datetime]::UtcNow
        TimeZone = $TimeZoneId
        TotalRows = $items.Count
        SentRows = $sent.Count
        ReceivedRows = $received.Count
        ExternalSentRows = $externalSent.Count
        TotalSentBytes = [long](($sent | Measure-Object -Property Size -Sum).Sum)
        UniqueRecipients = @($sent.RecipientAddress | Sort-Object -Unique).Count
        UniqueSenders = @($received.SenderAddress | Sort-Object -Unique).Count
        TopRecipientDomains = $topRecipientDomains
        TopSenderDomains = $topSenderDomains
        Anomalies = $anomalies.ToArray()
        HeuristicNotice = 'Anomalies are triage indicators, not proof of compromise.'
    }
}

function Export-IRMessageInvestigation {
    [CmdletBinding()]
    param(
        [string]$UserPrincipalName,
        [ValidateRange(1, 90)][int]$DaysBack = $script:IR.Days,
        [AllowEmptyString()][string]$SubjectContains = ''
    )

    $upn = Resolve-IRTarget -Upn $UserPrincipalName
    $messages = @(Get-IRMessageTrace -UserPrincipalName $upn -Direction Both -DaysBack $DaysBack -SubjectContains $SubjectContains)
    if ($messages.Count -eq 0) {
        Write-IRWarn 'No matching message trace records were returned.'
        return [pscustomobject]@{ Messages = @(); Analysis = $null; Paths = @(); Complete = -not [bool]$script:IR.Results.MessageTraceMetadata.Incomplete }
    }

    $internalDomains = @()
    try {
        $internalDomains = @(Get-IRAcceptedDomain)
    }
    catch {
        Write-IRWarn "Accepted domains could not be enumerated; using the target UPN domain only. $($_.Exception.Message)"
    }
    $analysis = Get-IRMessageAnalysis -Messages $messages -UserPrincipalName $upn -InternalDomains $internalDomains

    $safeUpn = ConvertTo-IRSafeFileName -Value $upn
    $paths = [System.Collections.Generic.List[string]]::new()
    $messagePath = Export-IRData -Data $messages -BaseName "MessageTrace-$safeUpn" -Format Csv -Subdirectory 'MessageTrace'
    if ($messagePath) { $paths.Add($messagePath) }
    $analysisPath = Export-IRData -Data @($analysis) -BaseName "MessageAnalysis-$safeUpn" -Format Json -Subdirectory 'MessageTrace'
    if ($analysisPath) { $paths.Add($analysisPath) }

    $timeline = @($messages | Select-Object ReceivedUtc, Direction, SenderAddress, RecipientAddress, Subject, Status, Size, MessageId)
    $timelinePath = Export-IRData -Data $timeline -BaseName "MessageTimeline-$safeUpn" -Format Csv -Subdirectory 'MessageTrace'
    if ($timelinePath) { $paths.Add($timelinePath) }

    Write-IRInfo "Message analysis: $($analysis.SentRows) sent, $($analysis.ReceivedRows) received, $(@($analysis.Anomalies).Count) heuristic finding(s)."
    return [pscustomobject]@{
        Messages = $messages
        Analysis = $analysis
        Paths = $paths.ToArray()
        Complete = -not [bool]$script:IR.Results.MessageTraceMetadata.Incomplete
    }
}

function Find-IRPhishingSpread {
    [CmdletBinding()]
    param(
        [string]$SenderAddress,
        [AllowEmptyString()][string]$SubjectContains = '',
        [ValidateRange(1, 90)][int]$DaysBack = 7
    )

    $sourceAddress = if ([string]::IsNullOrWhiteSpace($SenderAddress)) {
        Resolve-IRTarget
    }
    else {
        if (-not (Test-IRUpn -Value $SenderAddress)) {
            throw "'$SenderAddress' is not a valid sender address."
        }
        $SenderAddress.Trim().ToLowerInvariant()
    }

    $messages = @(Get-IRMessageTrace -UserPrincipalName $sourceAddress -Direction Sent -DaysBack $DaysBack -SubjectContains $SubjectContains)
    $internalDomains = @()
    try {
        $internalDomains = @(Get-IRAcceptedDomain | ForEach-Object { $_.ToLowerInvariant() })
    }
    catch {
        $internalDomains = @((($sourceAddress -split '@', 2)[1]).ToLowerInvariant())
    }

    $summary = @($messages | Group-Object -Property RecipientAddress | ForEach-Object {
        $recipient = [string]$_.Name
        $domain = ($recipient -split '@', 2)[-1].ToLowerInvariant()
        [pscustomobject]@{
            Recipient = $recipient
            MessageCount = $_.Count
            Internal = $domain -in $internalDomains
            FirstReceivedUtc = ($_.Group | Sort-Object ReceivedUtc | Select-Object -First 1).ReceivedUtc
            LastReceivedUtc = ($_.Group | Sort-Object ReceivedUtc -Descending | Select-Object -First 1).ReceivedUtc
            Subjects = @($_.Group.Subject | Sort-Object -Unique) -join ' | '
        }
    } | Sort-Object -Property MessageCount -Descending)

    $script:IR.Results.PhishingSpread = $summary
    if ($summary.Count -gt 0) {
        $null = Export-IRData -Data $summary -BaseName "PhishingSpread-$(ConvertTo-IRSafeFileName $sourceAddress)" -Format Csv -Subdirectory 'Phishing'
    }
    $null = Add-IRActionLog -Action 'Investigate phishing spread' -Status Read -Target $sourceAddress -Details @{
        SubjectContains = $SubjectContains
        TraceRows = $messages.Count
        UniqueRecipients = $summary.Count
    }
    return $summary
}

function Send-IRPhishingWarning {
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string[]]$Recipients,
        [string]$Subject = 'SECURITY ALERT: Review a potentially malicious email',
        [string]$MessageBody = @'
Our security team identified a message that may be malicious.

Do not click links or open attachments from the suspicious message. If you already entered credentials, contact the security team immediately and follow your organization incident-response procedure.

This notification was sent by the security response team.
'@
    )

    $cleanRecipients = @($Recipients | ForEach-Object { $_.Trim().ToLowerInvariant() } | Where-Object {
        Test-IRUpn -Value $_
    } | Sort-Object -Unique)
    if ($cleanRecipients.Count -eq 0) {
        throw 'No valid recipient addresses were supplied.'
    }
    if ($cleanRecipients.Count -gt 200) {
        throw 'A single warning operation is limited to 200 recipients. Split the recipient list and review each batch.'
    }

    $context = Connect-IRGraph -Scopes @('Mail.Send') -Modules @(
        'Microsoft.Graph.Users.Actions'
    )
    $sendingAccount = [string]$context.Account
    $mailBody = $MessageBody
    if (-not (Test-IRUpn -Value $sendingAccount)) {
        throw 'The signed-in Graph context does not expose a delegated mailbox identity. Sign in with the mailbox that should send the warning.'
    }

    $operation = {
        $statuses = [System.Collections.Generic.List[object]]::new()
        foreach ($recipient in $cleanRecipients) {
            $message = @{
                Message = @{
                    Subject = $Subject
                    Body = @{
                        ContentType = 'Text'
                        Content = $mailBody
                    }
                    ToRecipients = @(
                        @{
                            EmailAddress = @{
                                Address = $recipient
                            }
                        }
                    )
                }
                SaveToSentItems = $true
            }
            try {
                # Sending is intentionally not retried: a timeout can occur after
                # delivery and an automatic retry could create duplicate notices.
                Send-MgUserMail -UserId $sendingAccount -BodyParameter $message -ErrorAction Stop
                $statuses.Add([pscustomobject]@{ Recipient = $recipient; Status = 'Sent'; Error = $null })
            }
            catch {
                $statuses.Add([pscustomobject]@{ Recipient = $recipient; Status = 'Failed'; Error = $_.Exception.Message })
            }
        }
        return $statuses.ToArray()
    }

    $result = Invoke-IRChange -Target "$($cleanRecipients.Count) recipient(s)" -Action "Send phishing-warning mail as $sendingAccount" -Impact High -ExactConfirmation "SEND $($cleanRecipients.Count)" -Operation $operation -Details @{
        Sender = $sendingAccount
        Recipients = $cleanRecipients
        Subject = $Subject
    } -Confirm:$false
    if ($result) {
        $script:IR.Results.WarningMail = @($result)
        $null = Export-IRData -Data @($result) -BaseName 'PhishingWarningDelivery' -Format Csv -Subdirectory 'Phishing'
        $failedDeliveries = @($result | Where-Object Status -eq 'Failed')
        if ($failedDeliveries.Count -gt 0) {
            Write-IRWarn "$($failedDeliveries.Count) warning message(s) failed. Review the exported per-recipient status."
            $null = Add-IRActionLog -Action 'Phishing warning partial delivery' -Status Warning -Target $sendingAccount -Details @{ FailedRecipients = @($failedDeliveries.Recipient) }
        }
    }
    return $result
}

# ---------------------------------------------------------------------------
# Unified audit log collection and normalization
# ---------------------------------------------------------------------------

function Get-IRIPAddressCategory {
    param([AllowNull()][string]$IPAddress)

    if ([string]::IsNullOrWhiteSpace($IPAddress)) {
        return 'Unknown'
    }
    $candidate = $IPAddress.Trim()
    if ($candidate.StartsWith('[') -and $candidate.Contains(']')) {
        $candidate = $candidate.TrimStart('[').Split(']')[0]
    }
    elseif ($candidate -match '^(\d{1,3}(?:\.\d{1,3}){3}):\d+$') {
        $candidate = $Matches[1]
    }

    $parsed = $null
    if (-not [System.Net.IPAddress]::TryParse($candidate, [ref]$parsed)) {
        return 'Invalid'
    }
    if ([System.Net.IPAddress]::IsLoopback($parsed)) {
        return 'Loopback'
    }
    if ($parsed.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetworkV6) {
        if ($parsed.IsIPv4MappedToIPv6) {
            return 'IPv4Mapped-{0}' -f (Get-IRIPAddressCategory -IPAddress $parsed.MapToIPv4().ToString())
        }
        if ($parsed.Equals([System.Net.IPAddress]::IPv6Any)) {
            return 'UnspecifiedIPv6'
        }
        if ($parsed.IsIPv6LinkLocal) {
            return 'LinkLocalIPv6'
        }
        if ($parsed.IsIPv6SiteLocal) {
            return 'SiteLocalIPv6'
        }
        if ($parsed.IsIPv6UniqueLocal) {
            return 'PrivateIPv6'
        }
        $ipv6Bytes = $parsed.GetAddressBytes()
        if ($ipv6Bytes[0] -eq 0xff) {
            return 'MulticastIPv6'
        }
        if ($ipv6Bytes[0] -eq 0x20 -and $ipv6Bytes[1] -eq 0x01 -and $ipv6Bytes[2] -eq 0x0d -and $ipv6Bytes[3] -eq 0xb8) {
            return 'DocumentationIPv6'
        }
        if (($ipv6Bytes[0] -eq 0x20 -and $ipv6Bytes[1] -eq 0x02) -or
            ($ipv6Bytes[0] -eq 0x20 -and $ipv6Bytes[1] -eq 0x01 -and $ipv6Bytes[2] -eq 0x00 -and $ipv6Bytes[3] -eq 0x00)) {
            return 'TransitionIPv6'
        }
        return 'PublicIPv6'
    }

    $bytes = $parsed.GetAddressBytes()
    if ($bytes[0] -eq 0) {
        return 'ReservedIPv4'
    }
    if ($bytes[0] -eq 10 -or
        ($bytes[0] -eq 172 -and $bytes[1] -ge 16 -and $bytes[1] -le 31) -or
        ($bytes[0] -eq 192 -and $bytes[1] -eq 168)) {
        return 'PrivateIPv4'
    }
    if ($bytes[0] -eq 100 -and $bytes[1] -ge 64 -and $bytes[1] -le 127) {
        return 'CarrierGradeNATIPv4'
    }
    if ($bytes[0] -eq 169 -and $bytes[1] -eq 254) {
        return 'LinkLocalIPv4'
    }
    if (($bytes[0] -eq 192 -and $bytes[1] -eq 0 -and $bytes[2] -eq 2) -or
        ($bytes[0] -eq 198 -and $bytes[1] -eq 51 -and $bytes[2] -eq 100) -or
        ($bytes[0] -eq 203 -and $bytes[1] -eq 0 -and $bytes[2] -eq 113)) {
        return 'DocumentationIPv4'
    }
    if ($bytes[0] -eq 198 -and ($bytes[1] -eq 18 -or $bytes[1] -eq 19)) {
        return 'BenchmarkIPv4'
    }
    if ($bytes[0] -ge 224 -and $bytes[0] -le 239) {
        return 'MulticastIPv4'
    }
    if ($bytes[0] -ge 240) {
        return 'ReservedIPv4'
    }
    return 'PublicIPv4'
}

function Get-IRAuditCategory {
    param([AllowNull()][string]$Operation)

    if ([string]::IsNullOrWhiteSpace($Operation)) {
        return 'Other'
    }
    switch -Regex ($Operation) {
        '(?i)(login|logon|signin|authentication)' { return 'Authentication' }
        '(?i)(inboxrule|mailboxmessageconfiguration|autoreply|mailboxregional|forward)' { return 'RulesAndSettings' }
        '(?i)(permission|delegate|role(group)?member|app.?role|consent)' { return 'Permissions' }
        '(?i)^(send|sendas|sendonbehalf|mailitemsaccessed|messagebind|create|copy|move|softdelete|harddelete|update)$' { return 'EmailActivity' }
        '(?i)(file|folder|listitem|listcolumn|site|sharing|securelink|pageview|searchquery)' { return 'SharePointOneDrive' }
        '(?i)(team|channel|tab|connector|meeting|chat|messageupdated|messagedeleted)' { return 'Teams' }
        '(?i)(compliancesearch|compliancecase|hold|purge|ediscovery)' { return 'Compliance' }
        '(?i)(malware|phish|alert|quarantine|dlp|threat)' { return 'Security' }
        '(?i)^(new-|set-|add-|remove-|update-)' { return 'Administrative' }
        default { return 'Other' }
    }
}

function Search-IRUnifiedAuditLog {
    [CmdletBinding()]
    param(
        [string[]]$UserIds,
        [string[]]$Operations,
        [string]$RecordType,
        [ValidateRange(1, 180)][int]$DaysBack = $script:IR.Days,
        [datetime]$StartDateUtc,
        [datetime]$EndDateUtc,
        [ValidateRange(1, 5000)][int]$PageSize = 5000,
        [ValidateRange(1, 50000)][int]$MaximumResults = 50000
    )

    Connect-IRExchange
    if (-not (Get-Command Search-UnifiedAuditLog -ErrorAction SilentlyContinue)) {
        Connect-IRPurview
    }
    Assert-IRCommand -Name 'Search-UnifiedAuditLog' -Service 'Exchange Online or Microsoft Purview'

    $end = if ($PSBoundParameters.ContainsKey('EndDateUtc')) { $EndDateUtc.ToUniversalTime() } else { [datetime]::UtcNow }
    $start = if ($PSBoundParameters.ContainsKey('StartDateUtc')) { $StartDateUtc.ToUniversalTime() } else { $end.AddDays(-$DaysBack) }
    if ($start -ge $end) {
        throw 'Unified audit log StartDateUtc must be earlier than EndDateUtc.'
    }

    $sessionId = [guid]::NewGuid().ToString()
    $results = [System.Collections.Generic.List[object]]::new()
    $seen = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
    $page = 0
    $incomplete = $false
    $consecutiveDuplicatePages = 0
    while ($results.Count -lt $MaximumResults) {
        $page++
        if ($page -gt 200) {
            $incomplete = $true
            Write-IRWarn 'Unified audit log paging guard was reached.'
            break
        }

        $parameters = @{
            StartDate = $start
            EndDate = $end
            SessionId = $sessionId
            SessionCommand = 'ReturnLargeSet'
            ResultSize = $PageSize
            ErrorAction = 'Stop'
        }
        if ($UserIds) { $parameters.UserIds = $UserIds }
        if ($Operations) { $parameters.Operations = $Operations }
        if (-not [string]::IsNullOrWhiteSpace($RecordType)) { $parameters.RecordType = $RecordType }

        $batch = @(Invoke-IRRetry -Operation {
            Search-UnifiedAuditLog @parameters
        })
        if ($batch.Count -eq 0) {
            break
        }
        $addedThisPage = 0
        foreach ($record in $batch) {
            if ($results.Count -ge $MaximumResults) {
                $incomplete = $true
                break
            }
            $identity = [string](Get-IRProperty -InputObject $record -Name 'Identity')
            $recordKey = if (-not [string]::IsNullOrWhiteSpace($identity)) {
                $identity
            }
            else {
                '{0}|{1}|{2}|{3}' -f
                    (Get-IRProperty -InputObject $record -Name 'CreationDate'),
                    (Get-IRProperty -InputObject $record -Name 'RecordType'),
                    (Get-IRProperty -InputObject $record -Name 'Operations'),
                    (Get-IRProperty -InputObject $record -Name 'AuditData')
            }
            if ($seen.Add($recordKey)) {
                $results.Add($record)
                $addedThisPage++
            }
        }
        Write-IRInfo ('Unified audit log page {0}: {1} row(s); total {2}.' -f $page, $batch.Count, $results.Count)
        if ($addedThisPage -eq 0) {
            $consecutiveDuplicatePages++
            if ($consecutiveDuplicatePages -ge 2) {
                $incomplete = $true
                Write-IRWarn 'Unified audit log returned repeated pages without new records; paging stopped to avoid an infinite loop.'
                break
            }
        }
        else { $consecutiveDuplicatePages = 0 }
    }

    if ($results.Count -ge $MaximumResults) {
        $incomplete = $true
        Write-IRWarn "Unified audit log reached the configured $MaximumResults-record ceiling. Narrow the time window or filters."
    }
    $array = $results.ToArray()
    $script:IR.Results.UnifiedAuditRaw = $array
    $script:IR.Results.UnifiedAuditMetadata = [pscustomobject]@{
        StartUtc = $start
        EndUtc = $end
        Operations = $Operations
        RecordType = $RecordType
        Records = $array.Count
        Pages = $page
        Incomplete = $incomplete
    }
    $null = Add-IRActionLog -Action 'Search Unified Audit Log' -Status Read -Target ($UserIds -join ',') -Details @{
        StartUtc = $start
        EndUtc = $end
        Operations = $Operations
        RecordType = $RecordType
        Records = $array.Count
        Incomplete = $incomplete
    }
    return $array
}

function ConvertFrom-IRAuditRecord {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [object]$Record
    )

    process {
        $json = [string](Get-IRProperty -InputObject $Record -Name AuditData -Default '{}')
        $data = $null
        $parseError = $null
        try {
            $data = $json | ConvertFrom-Json -Depth 100 -ErrorAction Stop
        }
        catch {
            $parseError = $_.Exception.Message
            $data = [pscustomobject]@{}
        }

        $creation = Get-IRProperty -InputObject $Record -Name CreationDate
        if (-not $creation) {
            $creation = Get-IRProperty -InputObject $data -Name CreationTime
        }
        $operation = [string](Get-IRProperty -InputObject $Record -Name Operations)
        if ([string]::IsNullOrWhiteSpace($operation)) {
            $operation = [string](Get-IRProperty -InputObject $data -Name Operation)
        }
        $userId = Get-IRProperty -InputObject $data -Name UserId
        if (-not $userId) {
            $userId = Get-IRProperty -InputObject $Record -Name UserIds
        }
        $clientIp = [string](Get-IRProperty -InputObject $data -Name ClientIP)
        if ([string]::IsNullOrWhiteSpace($clientIp)) {
            $clientIp = [string](Get-IRProperty -InputObject $data -Name ActorIpAddress)
        }
        $extended = @(Get-IRProperty -InputObject $data -Name ExtendedProperties -Default @())
        $userAgentProperty = @($extended | Where-Object {
            [string](Get-IRProperty -InputObject $_ -Name Name) -eq 'UserAgent'
        } | Select-Object -First 1)
        $userAgent = if ($userAgentProperty.Count -gt 0) {
            Get-IRProperty -InputObject $userAgentProperty[0] -Name Value
        }
        else {
            Get-IRProperty -InputObject $data -Name UserAgent
        }

        [pscustomobject][ordered]@{
            CreationUtc = if ($creation) { ([datetime]$creation).ToUniversalTime() } else { $null }
            Operation = $operation
            Category = Get-IRAuditCategory -Operation $operation
            UserId = [string]$userId
            ClientIP = $clientIp
            IPAddressCategory = Get-IRIPAddressCategory -IPAddress $clientIp
            UserAgent = $userAgent
            Workload = Get-IRProperty -InputObject $data -Name Workload
            ResultStatus = Get-IRProperty -InputObject $data -Name ResultStatus
            ObjectId = Get-IRProperty -InputObject $data -Name ObjectId
            ItemType = Get-IRProperty -InputObject $data -Name ItemType
            SiteUrl = Get-IRProperty -InputObject $data -Name SiteUrl
            SourceFileName = Get-IRProperty -InputObject $data -Name SourceFileName
            SourceRelativeUrl = Get-IRProperty -InputObject $data -Name SourceRelativeUrl
            ExternalAccess = Get-IRProperty -InputObject $data -Name ExternalAccess
            LogonType = Get-IRProperty -InputObject $data -Name LogonType
            RecordType = Get-IRProperty -InputObject $Record -Name RecordType
            ResultIndex = Get-IRProperty -InputObject $Record -Name ResultIndex
            ResultCount = Get-IRProperty -InputObject $Record -Name ResultCount
            ParseError = $parseError
            RawAuditData = $json
        }
    }
}

function Get-IRAuditFinding {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]]$Events,
        [string]$TimeZoneId = [System.TimeZoneInfo]::Local.Id
    )

    $timeZone = [System.TimeZoneInfo]::FindSystemTimeZoneById($TimeZoneId)
    $highRiskOperations = @(
        'Add-MailboxPermission',
        'Add-RecipientPermission',
        'Add-RoleGroupMember',
        'New-InboxRule',
        'Set-InboxRule',
        'UpdateInboxRules',
        'Set-AdminAuditLogConfig',
        'Set-OrganizationConfig',
        'HardDelete',
        'Purge-ComplianceSearchAction'
    )

    $findings = foreach ($auditEvent in @($Events)) {
        $reasons = [System.Collections.Generic.List[string]]::new()
        $severity = 'Info'
        if ([string]$auditEvent.Operation -in $highRiskOperations) {
            $reasons.Add('High-risk operation')
            $severity = 'High'
        }
        if ([string]$auditEvent.ResultStatus -match '(?i)(fail|partial)') {
            $reasons.Add('Failed or partially successful operation')
            if ($severity -eq 'Info') { $severity = 'Medium' }
        }
        if ($auditEvent.CreationUtc) {
            $local = [System.TimeZoneInfo]::ConvertTimeFromUtc(([datetime]$auditEvent.CreationUtc).ToUniversalTime(), $timeZone)
            if ($local.Hour -lt 6 -or $local.Hour -ge 22) {
                $reasons.Add("After-hours activity in $TimeZoneId")
                if ($severity -eq 'Info') { $severity = 'Low' }
            }
        }
        if ($reasons.Count -gt 0 -and [string]$auditEvent.IPAddressCategory -match 'Public') {
            $reasons.Add('Public source IP is context for this finding; validate against known locations')
        }
        if ($reasons.Count -gt 0) {
            [pscustomobject][ordered]@{
                CreationUtc = $auditEvent.CreationUtc
                Severity = $severity
                Operation = $auditEvent.Operation
                Category = $auditEvent.Category
                UserId = $auditEvent.UserId
                ClientIP = $auditEvent.ClientIP
                ObjectId = $auditEvent.ObjectId
                Reasons = $reasons -join '; '
            }
        }
    }

    $rapidFileFindings = [System.Collections.Generic.List[object]]::new()
    $fileEvents = @($Events | Where-Object {
        $_.Category -eq 'SharePointOneDrive' -and $_.CreationUtc
    } | Sort-Object CreationUtc)
    if ($fileEvents.Count -ge 20) {
        $groups = $fileEvents | Group-Object {
            ([datetime]$_.CreationUtc).ToString('yyyyMMddHHmm')
        }
        foreach ($group in $groups | Where-Object Count -ge 20) {
            $rapidFileFindings.Add([pscustomobject]@{
                CreationUtc = ($group.Group | Select-Object -First 1).CreationUtc
                Severity = 'Medium'
                Operation = 'RapidFileActivity'
                Category = 'SharePointOneDrive'
                UserId = @($group.Group.UserId | Sort-Object -Unique) -join ','
                ClientIP = @($group.Group.ClientIP | Sort-Object -Unique) -join ','
                ObjectId = $null
                Reasons = "$($group.Count) file-related events in one UTC minute"
            })
        }
    }

    return @($findings) + $rapidFileFindings.ToArray()
}

function Export-IRUserAuditInvestigation {
    [CmdletBinding()]
    param(
        [string]$UserPrincipalName,
        [ValidateRange(1, 180)][int]$DaysBack = $script:IR.Days,
        [switch]$IncludeAdminOnlyExport
    )

    $upn = Resolve-IRTarget -Upn $UserPrincipalName
    $raw = @(Search-IRUnifiedAuditLog -UserIds @($upn) -DaysBack $DaysBack)
    $mainAuditIncomplete = [bool]$script:IR.Results.UnifiedAuditMetadata.Incomplete
    $events = @($raw | ConvertFrom-IRAuditRecord | Sort-Object CreationUtc)
    $findings = @(Get-IRAuditFinding -Events $events)
    $safeUpn = ConvertTo-IRSafeFileName -Value $upn
    $paths = [System.Collections.Generic.List[string]]::new()

    if ($events.Count -gt 0) {
        $eventPath = Export-IRData -Data $events -BaseName "UnifiedAudit-$safeUpn" -Format Csv -Subdirectory 'Audit'
        if ($eventPath) { $paths.Add($eventPath) }
        $rawPath = Export-IRData -Data $raw -BaseName "UnifiedAuditRaw-$safeUpn" -Format Json -Subdirectory 'Audit'
        if ($rawPath) { $paths.Add($rawPath) }
        $timelinePath = Export-IRData -Data @($events | Select-Object CreationUtc, Operation, Category, UserId, ClientIP, ObjectId, ResultStatus) -BaseName "AuditTimeline-$safeUpn" -Format Csv -Subdirectory 'Audit'
        if ($timelinePath) { $paths.Add($timelinePath) }
        $heatmap = @($events | Where-Object CreationUtc | Group-Object {
            $utc = ([datetime]$_.CreationUtc).ToUniversalTime()
            '{0}|{1:D2}' -f $utc.DayOfWeek, $utc.Hour
        } | ForEach-Object {
            $parts = $_.Name -split '\|', 2
            [pscustomobject]@{
                DayOfWeekUtc = $parts[0]
                HourUtc = [int]$parts[1]
                EventCount = $_.Count
            }
        } | Sort-Object DayOfWeekUtc, HourUtc)
        $heatmapPath = Export-IRData -Data $heatmap -BaseName "AuditActivityHeatmap-$safeUpn" -Format Csv -Subdirectory 'Audit'
        if ($heatmapPath) { $paths.Add($heatmapPath) }
    }
    if ($findings.Count -gt 0) {
        $findingPath = Export-IRData -Data $findings -BaseName "AuditFindings-$safeUpn" -Format Csv -Subdirectory 'Audit'
        if ($findingPath) { $paths.Add($findingPath) }
    }
    $adminAuditIncomplete = $false
    if ($IncludeAdminOnlyExport) {
        $adminRaw = @(Search-IRUnifiedAuditLog -UserIds @($upn) -RecordType ExchangeAdmin -DaysBack $DaysBack)
        $adminAuditIncomplete = [bool]$script:IR.Results.UnifiedAuditMetadata.Incomplete
        $adminEvents = @($adminRaw | ConvertFrom-IRAuditRecord)
        if ($adminEvents.Count -gt 0) {
            $adminPath = Export-IRData -Data $adminEvents -BaseName "ExchangeAdminAudit-$safeUpn" -Format Csv -Subdirectory 'Audit'
            if ($adminPath) { $paths.Add($adminPath) }
        }
    }

    $summary = [pscustomobject][ordered]@{
        Target = $upn
        Days = $DaysBack
        EventCount = $events.Count
        FindingCount = $findings.Count
        FailedOrPartial = @($events | Where-Object { [string]$_.ResultStatus -match '(?i)(fail|partial)' }).Count
        PublicSourceIPEvents = @($events | Where-Object { [string]$_.IPAddressCategory -match '^Public' }).Count
        Categories = @($events | Group-Object Category | Sort-Object Count -Descending | Select-Object Name, Count)
        Operations = @($events | Group-Object Operation | Sort-Object Count -Descending | Select-Object -First 25 Name, Count)
        ScopeNotice = 'The UserIds filter identifies records attributed to the user. It does not guarantee discovery of every event where the user was only the target.'
        HeuristicNotice = 'Findings require analyst validation.'
    }
    $summaryPath = Export-IRData -Data @($summary) -BaseName "AuditSummary-$safeUpn" -Format Json -Subdirectory 'Audit'
    if ($summaryPath) { $paths.Add($summaryPath) }

    $script:IR.Results.AuditEvents = $events
    $script:IR.Results.AuditFindings = $findings
    return [pscustomobject]@{
        Events = $events
        Findings = $findings
        Summary = $summary
        Paths = $paths.ToArray()
        Complete = -not ($mainAuditIncomplete -or $adminAuditIncomplete)
    }
}

# ---------------------------------------------------------------------------
# Exchange mailbox configuration, persistence, delegates, and applications
# ---------------------------------------------------------------------------

function ConvertTo-IRDisplayString {
    param([AllowNull()][object]$Value)

    if ($null -eq $Value) {
        return $null
    }
    $values = if ($Value -is [string]) { @($Value) } else { @($Value) }
    return @($values | ForEach-Object {
        $candidate = $_
        foreach ($propertyName in @('Address', 'PrimarySmtpAddress', 'WindowsEmailAddress', 'Name', 'DisplayName')) {
            $propertyValue = Get-IRProperty -InputObject $candidate -Name $propertyName
            if (-not [string]::IsNullOrWhiteSpace([string]$propertyValue)) {
                $candidate = $propertyValue
                break
            }
        }
        [string]$candidate
    } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }) -join '; '
}

function Get-IRMailboxSnapshot {
    [CmdletBinding()]
    param([string]$UserPrincipalName)

    $upn = Resolve-IRTarget -Upn $UserPrincipalName
    Connect-IRExchange
    Assert-IRCommand -Name @('Get-Mailbox', 'Get-MailboxStatistics', 'Get-InboxRule') -Service 'Exchange Online'

    $mailbox = Get-Mailbox -Identity $upn -ErrorAction Stop
    $statistics = Get-MailboxStatistics -Identity $upn -ErrorAction Stop
    $ruleParameters = @{ Mailbox = $upn; ErrorAction = 'Stop' }
    $ruleCommand = Get-Command Get-InboxRule -ErrorAction Stop
    if ($ruleCommand.Parameters.ContainsKey('IncludeHidden')) {
        $ruleParameters.IncludeHidden = $true
    }
    $rawRules = @(Get-InboxRule @ruleParameters)
    $rules = foreach ($rule in $rawRules) {
        $forwardTo = ConvertTo-IRDisplayString -Value (Get-IRProperty -InputObject $rule -Name 'ForwardTo')
        $redirectTo = ConvertTo-IRDisplayString -Value (Get-IRProperty -InputObject $rule -Name 'RedirectTo')
        $attachmentTo = ConvertTo-IRDisplayString -Value (Get-IRProperty -InputObject $rule -Name 'ForwardAsAttachmentTo')
        $reasons = [System.Collections.Generic.List[string]]::new()
        if ($forwardTo -or $redirectTo -or $attachmentTo) { $reasons.Add('Forwards or redirects messages') }
        if ([bool](Get-IRProperty -InputObject $rule -Name 'DeleteMessage' -Default $false)) { $reasons.Add('Deletes messages') }
        if ([bool](Get-IRProperty -InputObject $rule -Name 'MarkAsRead' -Default $false)) { $reasons.Add('Marks messages as read') }
        if ([string](Get-IRProperty -InputObject $rule -Name 'MoveToFolder') -match '(?i)(rss|archive|deleted|junk)') { $reasons.Add('Moves messages to a low-visibility folder') }
        if ([string]$rule.Name -match '(?i)(invoice|payment|security|alert|verify|microsoft|admin)') { $reasons.Add('Security-sensitive rule name') }

        [pscustomobject][ordered]@{
            Identity = [string]$rule.Identity
            Name = [string]$rule.Name
            Enabled = [bool]$rule.Enabled
            Priority = Get-IRProperty -InputObject $rule -Name 'Priority'
            From = ConvertTo-IRDisplayString -Value (Get-IRProperty -InputObject $rule -Name 'From')
            SubjectContainsWords = ConvertTo-IRDisplayString -Value (Get-IRProperty -InputObject $rule -Name 'SubjectContainsWords')
            ForwardTo = $forwardTo
            RedirectTo = $redirectTo
            ForwardAsAttachmentTo = $attachmentTo
            MoveToFolder = [string](Get-IRProperty -InputObject $rule -Name 'MoveToFolder')
            DeleteMessage = [bool](Get-IRProperty -InputObject $rule -Name 'DeleteMessage' -Default $false)
            MarkAsRead = [bool](Get-IRProperty -InputObject $rule -Name 'MarkAsRead' -Default $false)
            StopProcessingRules = [bool](Get-IRProperty -InputObject $rule -Name 'StopProcessingRules' -Default $false)
            Risk = if ($reasons.Count -gt 1) { 'High' } elseif ($reasons.Count -eq 1) { 'Medium' } else { 'Review' }
            Reasons = $reasons -join '; '
            Description = [string](Get-IRProperty -InputObject $rule -Name 'Description')
        }
    }

    $forwardingAddress = ConvertTo-IRDisplayString -Value (Get-IRProperty -InputObject $mailbox -Name 'ForwardingAddress')
    $forwardingSmtp = ConvertTo-IRDisplayString -Value (Get-IRProperty -InputObject $mailbox -Name 'ForwardingSmtpAddress')
    $summary = [pscustomobject][ordered]@{
        UserPrincipalName = $upn
        DisplayName = [string](Get-IRProperty -InputObject $mailbox -Name 'DisplayName')
        PrimarySmtpAddress = [string](Get-IRProperty -InputObject $mailbox -Name 'PrimarySmtpAddress')
        RecipientTypeDetails = [string](Get-IRProperty -InputObject $mailbox -Name 'RecipientTypeDetails')
        ExternalDirectoryObjectId = [string](Get-IRProperty -InputObject $mailbox -Name 'ExternalDirectoryObjectId')
        ForwardingAddress = $forwardingAddress
        ForwardingSmtpAddress = $forwardingSmtp
        DeliverToMailboxAndForward = [bool](Get-IRProperty -InputObject $mailbox -Name 'DeliverToMailboxAndForward' -Default $false)
        HasForwarding = [bool]($forwardingAddress -or $forwardingSmtp)
        GrantSendOnBehalfTo = ConvertTo-IRDisplayString -Value (Get-IRProperty -InputObject $mailbox -Name 'GrantSendOnBehalfTo')
        AuditEnabled = Get-IRProperty -InputObject $mailbox -Name 'AuditEnabled'
        DefaultAuditSet = ConvertTo-IRDisplayString -Value (Get-IRProperty -InputObject $mailbox -Name 'DefaultAuditSet')
        LitigationHoldEnabled = Get-IRProperty -InputObject $mailbox -Name 'LitigationHoldEnabled'
        SingleItemRecoveryEnabled = Get-IRProperty -InputObject $mailbox -Name 'SingleItemRecoveryEnabled'
        RetentionPolicy = [string](Get-IRProperty -InputObject $mailbox -Name 'RetentionPolicy')
        HiddenFromAddressListsEnabled = Get-IRProperty -InputObject $mailbox -Name 'HiddenFromAddressListsEnabled'
        WhenMailboxCreated = Get-IRProperty -InputObject $mailbox -Name 'WhenMailboxCreated'
        LastLogonTime = Get-IRProperty -InputObject $statistics -Name 'LastLogonTime'
        LastUserActionTime = Get-IRProperty -InputObject $statistics -Name 'LastUserActionTime'
        ItemCount = Get-IRProperty -InputObject $statistics -Name 'ItemCount'
        TotalItemSize = [string](Get-IRProperty -InputObject $statistics -Name 'TotalItemSize')
        DeletedItemCount = Get-IRProperty -InputObject $statistics -Name 'DeletedItemCount'
        TotalDeletedItemSize = [string](Get-IRProperty -InputObject $statistics -Name 'TotalDeletedItemSize')
        InboxRuleCount = @($rules).Count
        RiskyInboxRuleCount = @($rules | Where-Object Risk -in @('High', 'Medium')).Count
    }

    $script:IR.Results.MailboxSnapshot = $summary
    $script:IR.Results.InboxRules = @($rules)
    $null = Add-IRActionLog -Action 'Collect mailbox configuration and inbox rules' -Status Read -Target $upn -Details @{ Rules = @($rules).Count }
    return [pscustomobject]@{ Summary = $summary; InboxRules = @($rules); RawMailbox = $mailbox; RawStatistics = $statistics }
}

function ConvertTo-IRMailboxFolderIdentity {
    param(
        [Parameter(Mandatory)][string]$UserPrincipalName,
        [AllowEmptyString()][string]$FolderPath,
        [AllowEmptyString()][string]$ReportedIdentity
    )

    if (-not [string]::IsNullOrWhiteSpace($FolderPath)) {
        $relative = $FolderPath.Trim().TrimStart('/').Replace('/', '\')
        # Exchange represents a literal slash in a folder name as U+F8FF in
        # FolderPath. Restore it for Get-MailboxFolderPermission identities.
        $relative = $relative.Replace([char]0xF8FF, '/')
        if ([string]::IsNullOrWhiteSpace($relative)) {
            return '{0}:\' -f $UserPrincipalName
        }
        return '{0}:\{1}' -f $UserPrincipalName, $relative
    }

    if (-not [string]::IsNullOrWhiteSpace($ReportedIdentity)) {
        if ($ReportedIdentity -match ':\\') {
            return $ReportedIdentity
        }
        $prefix = "$UserPrincipalName\"
        if ($ReportedIdentity.StartsWith($prefix, [System.StringComparison]::OrdinalIgnoreCase)) {
            return '{0}:\{1}' -f $UserPrincipalName, $ReportedIdentity.Substring($prefix.Length)
        }
    }

    throw 'Mailbox folder statistics did not include a usable FolderPath or Identity.'
}

function Get-IRMailboxPermissionInventory {
    [CmdletBinding()]
    param(
        [string]$UserPrincipalName,
        [switch]$IncludeAllFolders
    )

    $upn = Resolve-IRTarget -Upn $UserPrincipalName
    Connect-IRExchange
    Assert-IRCommand -Name @('Get-Mailbox', 'Get-MailboxPermission', 'Get-RecipientPermission', 'Get-MailboxFolderStatistics', 'Get-MailboxFolderPermission') -Service 'Exchange Online'

    $mailbox = Get-Mailbox -Identity $upn -ErrorAction Stop
    $fullAccess = @(Get-MailboxPermission -Identity $upn -ErrorAction Stop | Where-Object {
        -not [bool](Get-IRProperty -InputObject $_ -Name 'IsInherited' -Default $false) -and
        [string]$_.User -notmatch '^(NT AUTHORITY\\SELF|S-1-5-10)$'
    } | ForEach-Object {
        [pscustomobject]@{
            PermissionType = 'FullAccess'
            Resource = $upn
            Trustee = [string]$_.User
            AccessRights = (ConvertTo-IRDisplayString -Value $_.AccessRights)
            Deny = [bool](Get-IRProperty -InputObject $_ -Name 'Deny' -Default $false)
            IsInherited = [bool](Get-IRProperty -InputObject $_ -Name 'IsInherited' -Default $false)
        }
    })

    $sendAs = @(Get-RecipientPermission -Identity $upn -ErrorAction Stop | Where-Object {
        -not [bool](Get-IRProperty -InputObject $_ -Name 'IsInherited' -Default $false) -and
        [string]$_.Trustee -notmatch '^(NT AUTHORITY\\SELF|S-1-5-10)$'
    } | ForEach-Object {
        [pscustomobject]@{
            PermissionType = 'SendAs'
            Resource = $upn
            Trustee = [string]$_.Trustee
            AccessRights = (ConvertTo-IRDisplayString -Value $_.AccessRights)
            Deny = $false
            IsInherited = [bool](Get-IRProperty -InputObject $_ -Name 'IsInherited' -Default $false)
        }
    })

    $sendOnBehalf = @(@(Get-IRProperty -InputObject $mailbox -Name 'GrantSendOnBehalfTo' -Default @()) | ForEach-Object {
        [pscustomobject]@{
            PermissionType = 'SendOnBehalf'
            Resource = $upn
            Trustee = ConvertTo-IRDisplayString -Value $_
            AccessRights = 'SendOnBehalf'
            Deny = $false
            IsInherited = $false
        }
    })

    $folderPermissions = [System.Collections.Generic.List[object]]::new()
    $folderErrors = [System.Collections.Generic.List[object]]::new()
    $skippedFolders = [System.Collections.Generic.List[object]]::new()
    $nonQueryableFolderTypes = @(
        'Root',
        'Audits',
        'CalendarLogging',
        'RecoverableItemsRoot',
        'RecoverableItemsDeletions',
        'RecoverableItemsDiscoveryHolds',
        'RecoverableItemsPurges',
        'RecoverableItemsSubstrateHolds',
        'RecoverableItemsVersions'
    )
    $folderParameters = @{ Identity = $upn; ErrorAction = 'Stop' }
    if (-not $IncludeAllFolders) { $folderParameters.FolderScope = 'Calendar' }
    $folders = @(Get-MailboxFolderStatistics @folderParameters)
    foreach ($folder in $folders) {
        $reportedIdentity = [string](Get-IRProperty -InputObject $folder -Name 'Identity')
        $folderPath = [string](Get-IRProperty -InputObject $folder -Name 'FolderPath')
        $folderType = [string](Get-IRProperty -InputObject $folder -Name 'FolderType')
        if ($folderType -in $nonQueryableFolderTypes) {
            $skippedFolders.Add([pscustomobject]@{
                Folder = $reportedIdentity
                FolderType = $folderType
                Reason = 'Exchange does not expose this internal system folder through Get-MailboxFolderPermission.'
            })
            continue
        }
        try {
            $identity = ConvertTo-IRMailboxFolderIdentity -UserPrincipalName $upn -FolderPath $folderPath -ReportedIdentity $reportedIdentity
            foreach ($permission in @(Get-MailboxFolderPermission -Identity $identity -ErrorAction Stop)) {
                $trustee = ConvertTo-IRDisplayString -Value (Get-IRProperty -InputObject $permission -Name 'User')
                if ($trustee -in @('Default', 'Anonymous')) { continue }
                $folderPermissions.Add([pscustomobject]@{
                    PermissionType = 'Folder'
                    Resource = $identity
                    Trustee = $trustee
                    AccessRights = ConvertTo-IRDisplayString -Value (Get-IRProperty -InputObject $permission -Name 'AccessRights')
                    SharingPermissionFlags = ConvertTo-IRDisplayString -Value (Get-IRProperty -InputObject $permission -Name 'SharingPermissionFlags')
                    FolderType = [string](Get-IRProperty -InputObject $folder -Name 'FolderType')
                })
            }
        }
        catch {
            $folderErrors.Add([pscustomobject]@{ Folder = $reportedIdentity; Error = $_.Exception.Message })
        }
    }

    $resourceDelegates = @()
    if ([string](Get-IRProperty -InputObject $mailbox -Name 'RecipientTypeDetails') -match '^(RoomMailbox|EquipmentMailbox)$' -and
        (Get-Command Get-CalendarProcessing -ErrorAction SilentlyContinue)) {
        $processing = Get-CalendarProcessing -Identity $upn -ErrorAction Stop
        $resourceDelegates = @(@(Get-IRProperty -InputObject $processing -Name 'ResourceDelegates' -Default @()) | ForEach-Object {
            [pscustomobject]@{
                PermissionType = 'ResourceDelegate'
                Resource = $upn
                Trustee = ConvertTo-IRDisplayString -Value $_
                AccessRights = 'ResourceDelegate'
                Deny = $false
                IsInherited = $false
            }
        })
    }

    $all = @($fullAccess) + @($sendAs) + @($sendOnBehalf) + @($folderPermissions) + @($resourceDelegates)
    $result = [pscustomobject]@{
        Target = $upn
        Permissions = $all
        FolderErrors = $folderErrors.ToArray()
        SkippedFolders = $skippedFolders.ToArray()
        Complete = $folderErrors.Count -eq 0
        Scope = if ($IncludeAllFolders) { 'All mailbox folders' } else { 'Calendar folders plus mailbox-level delegation' }
    }
    $script:IR.Results.MailboxPermissions = $all
    $null = Add-IRActionLog -Action 'Collect mailbox permissions' -Status Read -Target $upn -Details @{ Permissions = $all.Count; FolderErrors = $folderErrors.Count; SkippedSystemFolders = $skippedFolders.Count }
    return $result
}

function Get-IRMailboxApplication {
    [CmdletBinding()]
    param([string]$UserPrincipalName)

    $upn = Resolve-IRTarget -Upn $UserPrincipalName
    Connect-IRExchange
    Assert-IRCommand -Name 'Get-App' -Service 'Exchange Online'
    $apps = @(Get-App -Mailbox $upn -ErrorAction Stop | ForEach-Object {
        [pscustomobject]@{
            Identity = [string]$_.Identity
            DisplayName = [string]$_.DisplayName
            Enabled = [bool]$_.Enabled
            AppVersion = [string](Get-IRProperty -InputObject $_ -Name 'AppVersion')
            ProviderName = [string](Get-IRProperty -InputObject $_ -Name 'ProviderName')
            DefaultStateForUser = [string](Get-IRProperty -InputObject $_ -Name 'DefaultStateForUser')
            MarketplaceAssetId = [string](Get-IRProperty -InputObject $_ -Name 'MarketplaceAssetId')
            Type = [string](Get-IRProperty -InputObject $_ -Name 'Type')
        }
    })
    $script:IR.Results.MailboxApps = $apps
    $null = Add-IRActionLog -Action 'Collect mailbox applications' -Status Read -Target $upn -Details @{ Applications = $apps.Count }
    return $apps
}

function Get-IRTransportRuleReview {
    [CmdletBinding()]
    param()

    Connect-IRExchange
    Assert-IRCommand -Name 'Get-TransportRule' -Service 'Exchange Online'
    $rules = @(Get-TransportRule -ErrorAction Stop | ForEach-Object {
        $description = [string](Get-IRProperty -InputObject $_ -Name 'Description')
        $reasons = [System.Collections.Generic.List[string]]::new()
        if ($description -match '(?i)(redirect|blind copy|bcc|delete|quarantine|set the spam confidence)') { $reasons.Add('Message-routing or disposition action') }
        if ([string](Get-IRProperty -InputObject $_ -Name 'Mode') -ine 'Enforce') { $reasons.Add('Rule is not in Enforce mode') }
        if ([string](Get-IRProperty -InputObject $_ -Name 'State') -ieq 'Disabled') { $reasons.Add('Rule is disabled') }
        [pscustomobject]@{
            Identity = [string]$_.Identity
            Name = [string]$_.Name
            State = [string](Get-IRProperty -InputObject $_ -Name 'State')
            Mode = [string](Get-IRProperty -InputObject $_ -Name 'Mode')
            Priority = Get-IRProperty -InputObject $_ -Name 'Priority'
            Comments = [string](Get-IRProperty -InputObject $_ -Name 'Comments')
            WhenChanged = Get-IRProperty -InputObject $_ -Name 'WhenChanged'
            RiskReasons = $reasons -join '; '
            Description = $description
        }
    })
    $script:IR.Results.TransportRules = $rules
    $null = Add-IRActionLog -Action 'Review transport rules' -Status Read -Target 'Tenant' -Details @{ Rules = $rules.Count }
    return $rules
}

function Set-IRInboxRuleEnabled {
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    param(
        [Parameter(Mandatory)][string]$Identity,
        [bool]$Enabled,
        [string]$UserPrincipalName
    )

    $upn = Resolve-IRTarget -Upn $UserPrincipalName
    Connect-IRExchange
    $command = if ($Enabled) { 'Enable-InboxRule' } else { 'Disable-InboxRule' }
    Assert-IRCommand -Name $command -Service 'Exchange Online'
    Invoke-IRChange -Target "$upn / $Identity" -Action "$command selected inbox rule" -Impact High -ExactConfirmation $Identity -Operation {
        & $command -Mailbox $upn -Identity $Identity -Confirm:$false -ErrorAction Stop
    }
}

function Remove-IRInboxRule {
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    param(
        [Parameter(Mandatory)][string]$Identity,
        [string]$UserPrincipalName
    )

    $upn = Resolve-IRTarget -Upn $UserPrincipalName
    Connect-IRExchange
    Assert-IRCommand -Name 'Remove-InboxRule' -Service 'Exchange Online'
    Invoke-IRChange -Target "$upn / $Identity" -Action 'Remove selected inbox rule' -Impact High -ExactConfirmation $Identity -Operation {
        Remove-InboxRule -Mailbox $upn -Identity $Identity -Confirm:$false -ErrorAction Stop
    }
}

function Clear-IRMailboxForwarding {
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    param([string]$UserPrincipalName)

    $upn = Resolve-IRTarget -Upn $UserPrincipalName
    Connect-IRExchange
    Assert-IRCommand -Name 'Set-Mailbox' -Service 'Exchange Online'
    Invoke-IRChange -Target $upn -Action 'Clear mailbox forwarding' -Impact High -ExactConfirmation $upn -Operation {
        Set-Mailbox -Identity $upn -ForwardingAddress $null -ForwardingSmtpAddress $null -DeliverToMailboxAndForward:$false -ErrorAction Stop
    }
}

function Disable-IRTransportRule {
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    param([Parameter(Mandatory)][string]$Identity)

    Connect-IRExchange
    Assert-IRCommand -Name 'Disable-TransportRule' -Service 'Exchange Online'
    Invoke-IRChange -Target $Identity -Action 'Disable selected transport rule' -Impact Critical -ExactConfirmation $Identity -Operation {
        Disable-TransportRule -Identity $Identity -Confirm:$false -ErrorAction Stop
    }
}

function Disable-IRMailboxApplication {
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    param(
        [Parameter(Mandatory)][string]$Identity,
        [string]$UserPrincipalName
    )

    $upn = Resolve-IRTarget -Upn $UserPrincipalName
    Connect-IRExchange
    Assert-IRCommand -Name 'Disable-App' -Service 'Exchange Online'
    Invoke-IRChange -Target "$upn / $Identity" -Action 'Disable selected mailbox application' -Impact High -ExactConfirmation $Identity -Operation {
        Disable-App -Mailbox $upn -Identity $Identity -Confirm:$false -ErrorAction Stop
    }
}

function Remove-IRMailboxDelegation {
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    param(
        [Parameter(Mandatory)][ValidateSet('FullAccess', 'SendAs', 'SendOnBehalf', 'Folder', 'ResourceDelegate')][string]$PermissionType,
        [Parameter(Mandatory)][string]$Trustee,
        [string]$Resource,
        [string]$UserPrincipalName
    )

    $upn = Resolve-IRTarget -Upn $UserPrincipalName
    if ([string]::IsNullOrWhiteSpace($Resource)) { $Resource = $upn }
    Connect-IRExchange
    $action = "Remove $PermissionType permission for $Trustee"
    Invoke-IRChange -Target $Resource -Action $action -Impact Critical -ExactConfirmation $Trustee -Details @{ PermissionType = $PermissionType; Trustee = $Trustee } -Operation {
        switch ($PermissionType) {
            'FullAccess' {
                Assert-IRCommand -Name 'Remove-MailboxPermission' -Service 'Exchange Online'
                Remove-MailboxPermission -Identity $Resource -User $Trustee -AccessRights FullAccess -Confirm:$false -ErrorAction Stop
            }
            'SendAs' {
                Assert-IRCommand -Name 'Remove-RecipientPermission' -Service 'Exchange Online'
                Remove-RecipientPermission -Identity $Resource -Trustee $Trustee -AccessRights SendAs -Confirm:$false -ErrorAction Stop
            }
            'SendOnBehalf' {
                Assert-IRCommand -Name 'Set-Mailbox' -Service 'Exchange Online'
                Set-Mailbox -Identity $Resource -GrantSendOnBehalfTo @{ Remove = $Trustee } -ErrorAction Stop
            }
            'Folder' {
                Assert-IRCommand -Name 'Remove-MailboxFolderPermission' -Service 'Exchange Online'
                Remove-MailboxFolderPermission -Identity $Resource -User $Trustee -Confirm:$false -ErrorAction Stop
            }
            'ResourceDelegate' {
                Assert-IRCommand -Name 'Set-CalendarProcessing' -Service 'Exchange Online'
                Set-CalendarProcessing -Identity $Resource -ResourceDelegates @{ Remove = $Trustee } -ErrorAction Stop
            }
        }
    }
}

function Export-IRMailboxInvestigation {
    [CmdletBinding()]
    param(
        [string]$UserPrincipalName,
        [switch]$IncludeAllFolders
    )

    $upn = Resolve-IRTarget -Upn $UserPrincipalName
    $snapshot = Get-IRMailboxSnapshot -UserPrincipalName $upn
    $permissions = Get-IRMailboxPermissionInventory -UserPrincipalName $upn -IncludeAllFolders:$IncludeAllFolders
    $apps = @(Get-IRMailboxApplication -UserPrincipalName $upn)
    $safe = ConvertTo-IRSafeFileName -Value $upn
    $paths = [System.Collections.Generic.List[string]]::new()
    foreach ($export in @(
        @{ Data = @($snapshot.Summary); Name = "MailboxSummary-$safe"; Format = 'Json' },
        @{ Data = @($snapshot.InboxRules); Name = "InboxRules-$safe"; Format = 'Csv' },
        @{ Data = @($permissions.Permissions); Name = "MailboxPermissions-$safe"; Format = 'Csv' },
        @{ Data = @($permissions.FolderErrors); Name = "MailboxFolderErrors-$safe"; Format = 'Csv' },
        @{ Data = @($permissions.SkippedFolders); Name = "MailboxSystemFoldersNotQueryable-$safe"; Format = 'Csv' },
        @{ Data = $apps; Name = "MailboxApplications-$safe"; Format = 'Csv' }
    )) {
        if (@($export.Data).Count -eq 0) { continue }
        $path = Export-IRData -Data @($export.Data) -BaseName $export.Name -Format $export.Format -Subdirectory 'Mailbox'
        if ($path) { $paths.Add($path) }
    }
    return [pscustomobject]@{
        Snapshot = $snapshot
        Permissions = $permissions
        Applications = $apps
        Paths = $paths.ToArray()
        Errors = @($permissions.FolderErrors)
        Complete = @($permissions.FolderErrors).Count -eq 0
    }
}

# ---------------------------------------------------------------------------
# Microsoft Entra applications, sign-ins, risk, authentication, and devices
# ---------------------------------------------------------------------------

function Get-IROAuthGrant {
    [CmdletBinding()]
    param([string]$UserPrincipalName)

    $user = Get-IRGraphUser -UserPrincipalName $UserPrincipalName
    $null = Connect-IRGraph -Scopes @(
        'User.Read.All',
        'DelegatedPermissionGrant.Read.All',
        'Application.Read.All'
    ) -Modules @(
        'Microsoft.Graph.Users',
        'Microsoft.Graph.Applications'
    )
    Assert-IRCommand -Name @('Get-MgUserOauth2PermissionGrant', 'Get-MgServicePrincipal') -Service 'Microsoft Graph'

    $grants = @(Invoke-IRRetry -Operation {
        Get-MgUserOauth2PermissionGrant -UserId $user.Id -All -ErrorAction Stop
    })
    $servicePrincipalCache = @{}
    $rows = foreach ($grant in $grants) {
        $clientId = [string](Get-IRProperty -InputObject $grant -Name 'ClientId')
        $resourceId = [string](Get-IRProperty -InputObject $grant -Name 'ResourceId')
        foreach ($id in @($clientId, $resourceId)) {
            if ([string]::IsNullOrWhiteSpace($id) -or $servicePrincipalCache.ContainsKey($id)) { continue }
            try {
                $servicePrincipalCache[$id] = Invoke-IRRetry -Operation {
                    Get-MgServicePrincipal -ServicePrincipalId $id -Property Id, AppId, DisplayName, PublisherName, VerifiedPublisher -ErrorAction Stop
                }
            }
            catch {
                $servicePrincipalCache[$id] = $null
            }
        }
        $client = $servicePrincipalCache[$clientId]
        $resource = $servicePrincipalCache[$resourceId]
        $scopes = @(([string](Get-IRProperty -InputObject $grant -Name 'Scope')) -split '\s+' | Where-Object { $_ })
        $highRisk = @($scopes | Where-Object {
            $_ -match '(?i)(\.ReadWrite(\.All)?$|\.All$|Mail\.|Files\.|Directory\.|RoleManagement\.|offline_access)'
        })
        [pscustomobject][ordered]@{
            GrantId = [string]$grant.Id
            UserPrincipalName = $user.UserPrincipalName
            ClientServicePrincipalId = $clientId
            ClientApplication = [string](Get-IRProperty -InputObject $client -Name 'DisplayName' -Default $clientId)
            ClientAppId = [string](Get-IRProperty -InputObject $client -Name 'AppId')
            Publisher = [string](Get-IRProperty -InputObject $client -Name 'PublisherName')
            ResourceServicePrincipalId = $resourceId
            Resource = [string](Get-IRProperty -InputObject $resource -Name 'DisplayName' -Default $resourceId)
            ConsentType = [string](Get-IRProperty -InputObject $grant -Name 'ConsentType')
            Scope = $scopes -join ' '
            HighRiskScopes = $highRisk -join ' '
            Risk = if ($highRisk.Count -gt 0) { 'ReviewHigh' } else { 'Review' }
        }
    }
    $script:IR.Results.OAuthGrants = @($rows)
    $null = Add-IRActionLog -Action 'Collect delegated OAuth grants' -Status Read -Target $user.UserPrincipalName -Details @{ Grants = @($rows).Count }
    return @($rows)
}

function Remove-IROAuthGrant {
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    param(
        [Parameter(Mandatory)][string]$GrantId,
        [string]$UserPrincipalName
    )

    $upn = Resolve-IRTarget -Upn $UserPrincipalName
    $null = Connect-IRGraph -Scopes @('DelegatedPermissionGrant.ReadWrite.All') -Modules @('Microsoft.Graph.Identity.SignIns')
    Assert-IRCommand -Name 'Remove-MgOauth2PermissionGrant' -Service 'Microsoft Graph'
    Invoke-IRChange -Target "$upn / $GrantId" -Action 'Remove selected delegated OAuth grant' -Impact Critical -ExactConfirmation $GrantId -Operation {
        Remove-MgOauth2PermissionGrant -OAuth2PermissionGrantId $GrantId -Confirm:$false -ErrorAction Stop
    }
}

function Get-IRAppRoleAssignment {
    [CmdletBinding()]
    param([string]$UserPrincipalName)

    $user = Get-IRGraphUser -UserPrincipalName $UserPrincipalName
    $null = Connect-IRGraph -Scopes @('User.Read.All', 'AppRoleAssignment.Read.All', 'Application.Read.All') -Modules @('Microsoft.Graph.Applications')
    Assert-IRCommand -Name @('Get-MgUserAppRoleAssignment', 'Get-MgServicePrincipal') -Service 'Microsoft Graph'
    $assignments = @(Invoke-IRRetry -Operation {
        Get-MgUserAppRoleAssignment -UserId $user.Id -All -ErrorAction Stop
    })
    $cache = @{}
    $rows = foreach ($assignment in $assignments) {
        $resourceId = [string](Get-IRProperty -InputObject $assignment -Name 'ResourceId')
        if (-not $cache.ContainsKey($resourceId)) {
            try {
                $cache[$resourceId] = Get-MgServicePrincipal -ServicePrincipalId $resourceId -Property Id, AppId, DisplayName, PublisherName, AppRoles -ErrorAction Stop
            }
            catch { $cache[$resourceId] = $null }
        }
        $servicePrincipal = $cache[$resourceId]
        $roleId = [string](Get-IRProperty -InputObject $assignment -Name 'AppRoleId')
        $role = @((Get-IRProperty -InputObject $servicePrincipal -Name 'AppRoles' -Default @()) | Where-Object { [string]$_.Id -eq $roleId } | Select-Object -First 1)
        [pscustomobject][ordered]@{
            AssignmentId = [string]$assignment.Id
            UserId = [string]$user.Id
            UserPrincipalName = $user.UserPrincipalName
            ResourceId = $resourceId
            Application = [string](Get-IRProperty -InputObject $servicePrincipal -Name 'DisplayName' -Default (Get-IRProperty -InputObject $assignment -Name 'ResourceDisplayName'))
            AppId = [string](Get-IRProperty -InputObject $servicePrincipal -Name 'AppId')
            Publisher = [string](Get-IRProperty -InputObject $servicePrincipal -Name 'PublisherName')
            AppRoleId = $roleId
            AppRoleValue = [string](Get-IRProperty -InputObject ($role | Select-Object -First 1) -Name 'Value')
            AppRoleDisplayName = [string](Get-IRProperty -InputObject ($role | Select-Object -First 1) -Name 'DisplayName')
            CreatedDateTime = Get-IRProperty -InputObject $assignment -Name 'CreatedDateTime'
        }
    }
    $script:IR.Results.AppRoleAssignments = @($rows)
    $null = Add-IRActionLog -Action 'Collect enterprise application assignments' -Status Read -Target $user.UserPrincipalName -Details @{ Assignments = @($rows).Count }
    return @($rows)
}

function Remove-IRAppRoleAssignment {
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    param(
        [Parameter(Mandatory)][string]$AssignmentId,
        [string]$UserPrincipalName
    )

    $user = Get-IRGraphUser -UserPrincipalName $UserPrincipalName
    $null = Connect-IRGraph -Scopes @('AppRoleAssignment.ReadWrite.All') -Modules @('Microsoft.Graph.Applications')
    Assert-IRCommand -Name 'Remove-MgUserAppRoleAssignment' -Service 'Microsoft Graph'
    Invoke-IRChange -Target "$($user.UserPrincipalName) / $AssignmentId" -Action 'Remove selected application role assignment' -Impact Critical -ExactConfirmation $AssignmentId -Operation {
        Remove-MgUserAppRoleAssignment -UserId $user.Id -AppRoleAssignmentId $AssignmentId -Confirm:$false -ErrorAction Stop
    }
}

function Get-IRUserSignInLog {
    [CmdletBinding()]
    param(
        [string]$UserPrincipalName,
        [ValidateRange(1, 180)][int]$DaysBack = $script:IR.Days
    )

    $upn = Resolve-IRTarget -Upn $UserPrincipalName
    $null = Connect-IRGraph -Scopes @('AuditLog.Read.All', 'User.Read.All') -Modules @('Microsoft.Graph.Reports')
    Assert-IRCommand -Name 'Get-MgAuditLogSignIn' -Service 'Microsoft Graph'
    $escaped = ConvertTo-IRODataLiteral -Value $upn
    $start = [datetime]::UtcNow.AddDays(-$DaysBack).ToString('yyyy-MM-ddTHH:mm:ssZ')
    $filter = "userPrincipalName eq '$escaped' and createdDateTime ge $start"
    $signIns = @(Invoke-IRRetry -Operation {
        Get-MgAuditLogSignIn -Filter $filter -All -ErrorAction Stop
    })
    $rows = foreach ($signIn in $signIns) {
        $status = Get-IRProperty -InputObject $signIn -Name 'Status'
        $device = Get-IRProperty -InputObject $signIn -Name 'DeviceDetail'
        $location = Get-IRProperty -InputObject $signIn -Name 'Location'
        $geo = Get-IRProperty -InputObject $location -Name 'GeoCoordinates'
        $ip = [string](Get-IRProperty -InputObject $signIn -Name 'IpAddress')
        [pscustomobject][ordered]@{
            CreatedDateTime = Get-IRProperty -InputObject $signIn -Name 'CreatedDateTime'
            UserPrincipalName = [string](Get-IRProperty -InputObject $signIn -Name 'UserPrincipalName')
            AppDisplayName = [string](Get-IRProperty -InputObject $signIn -Name 'AppDisplayName')
            ResourceDisplayName = [string](Get-IRProperty -InputObject $signIn -Name 'ResourceDisplayName')
            ClientAppUsed = [string](Get-IRProperty -InputObject $signIn -Name 'ClientAppUsed')
            IPAddress = $ip
            IPAddressCategory = Get-IRIPAddressCategory -IPAddress $ip
            CountryOrRegion = [string](Get-IRProperty -InputObject $location -Name 'CountryOrRegion')
            State = [string](Get-IRProperty -InputObject $location -Name 'State')
            City = [string](Get-IRProperty -InputObject $location -Name 'City')
            Latitude = Get-IRProperty -InputObject $geo -Name 'Latitude'
            Longitude = Get-IRProperty -InputObject $geo -Name 'Longitude'
            OperatingSystem = [string](Get-IRProperty -InputObject $device -Name 'OperatingSystem')
            Browser = [string](Get-IRProperty -InputObject $device -Name 'Browser')
            DeviceId = [string](Get-IRProperty -InputObject $device -Name 'DeviceId')
            IsManaged = Get-IRProperty -InputObject $device -Name 'IsManaged'
            IsCompliant = Get-IRProperty -InputObject $device -Name 'IsCompliant'
            TrustType = [string](Get-IRProperty -InputObject $device -Name 'TrustType')
            ConditionalAccessStatus = [string](Get-IRProperty -InputObject $signIn -Name 'ConditionalAccessStatus')
            RiskLevelAggregated = [string](Get-IRProperty -InputObject $signIn -Name 'RiskLevelAggregated')
            RiskLevelDuringSignIn = [string](Get-IRProperty -InputObject $signIn -Name 'RiskLevelDuringSignIn')
            RiskState = [string](Get-IRProperty -InputObject $signIn -Name 'RiskState')
            ErrorCode = Get-IRProperty -InputObject $status -Name 'ErrorCode'
            FailureReason = [string](Get-IRProperty -InputObject $status -Name 'FailureReason')
            CorrelationId = [string](Get-IRProperty -InputObject $signIn -Name 'CorrelationId')
            SignInId = [string](Get-IRProperty -InputObject $signIn -Name 'Id')
        }
    }
    $script:IR.Results.SignIns = @($rows)
    $null = Add-IRActionLog -Action 'Collect Microsoft Entra sign-in logs' -Status Read -Target $upn -Details @{ Records = @($rows).Count; Days = $DaysBack }
    return @($rows)
}

function Get-IRRiskyUser {
    [CmdletBinding()]
    param([string]$UserPrincipalName)

    $user = Get-IRGraphUser -UserPrincipalName $UserPrincipalName
    $null = Connect-IRGraph -Scopes @('IdentityRiskyUser.Read.All') -Modules @('Microsoft.Graph.Identity.SignIns')
    Assert-IRCommand -Name 'Get-MgRiskyUser' -Service 'Microsoft Graph'
    $risk = try {
        Invoke-IRRetry -Operation {
            Get-MgRiskyUser -RiskyUserId $user.Id -ErrorAction Stop
        }
    }
    catch {
        if (Test-IRNotFoundError -ErrorRecord $_) {
            $null
        }
        else {
            throw
        }
    }
    $result = [pscustomobject][ordered]@{
        Id = if ($risk) { [string]$risk.Id } else { [string]$user.Id }
        UserPrincipalName = [string](Get-IRProperty -InputObject $risk -Name 'UserPrincipalName' -Default $user.UserPrincipalName)
        ListingStatus = if ($risk) { 'ListedAsRisky' } else { 'NotListedAsRisky' }
        RiskLevel = [string](Get-IRProperty -InputObject $risk -Name 'RiskLevel' -Default 'none')
        RiskState = [string](Get-IRProperty -InputObject $risk -Name 'RiskState' -Default 'none')
        RiskDetail = [string](Get-IRProperty -InputObject $risk -Name 'RiskDetail')
        RiskLastUpdatedDateTime = Get-IRProperty -InputObject $risk -Name 'RiskLastUpdatedDateTime'
        IsDeleted = Get-IRProperty -InputObject $risk -Name 'IsDeleted'
        Note = if ($risk) {
            'Microsoft Entra ID Protection returned a risky-user record.'
        }
        else {
            'Microsoft Entra ID Protection did not list this user as risky at collection time.'
        }
    }
    $script:IR.Results.RiskyUser = $result
    $null = Add-IRActionLog -Action 'Collect risky-user status' -Status Read -Target $user.UserPrincipalName -Details @{
        ListingStatus = $result.ListingStatus
    }
    return $result
}

function Get-IRAuthenticationMethod {
    [CmdletBinding()]
    param([string]$UserPrincipalName)

    $user = Get-IRGraphUser -UserPrincipalName $UserPrincipalName
    $null = Connect-IRGraph -Scopes @('UserAuthenticationMethod.Read.All') -Modules @('Microsoft.Graph.Identity.SignIns')
    Assert-IRCommand -Name 'Get-MgUserAuthenticationMethod' -Service 'Microsoft Graph'
    $methods = @(Get-MgUserAuthenticationMethod -UserId $user.Id -All -ErrorAction Stop)
    $rows = foreach ($method in $methods) {
        $additional = Get-IRProperty -InputObject $method -Name 'AdditionalProperties' -Default @{}
        [pscustomobject]@{
            Id = [string]$method.Id
            UserPrincipalName = $user.UserPrincipalName
            MethodType = [string](Get-IRProperty -InputObject $additional -Name '@odata.type' -Default $method.GetType().Name)
            DisplayName = [string](Get-IRProperty -InputObject $method -Name 'DisplayName')
            CreatedDateTime = Get-IRProperty -InputObject $method -Name 'CreatedDateTime'
            PhoneType = [string](Get-IRProperty -InputObject $method -Name 'PhoneType')
            EmailAddress = [string](Get-IRProperty -InputObject $method -Name 'EmailAddress')
        }
    }
    $script:IR.Results.AuthenticationMethods = @($rows)
    $null = Add-IRActionLog -Action 'Collect authentication method inventory' -Status Read -Target $user.UserPrincipalName -Details @{ Methods = @($rows).Count }
    return @($rows)
}

function Get-IRExchangeMobileDevice {
    [CmdletBinding()]
    param([string]$UserPrincipalName)

    $upn = Resolve-IRTarget -Upn $UserPrincipalName
    Connect-IRExchange
    Assert-IRCommand -Name 'Get-MobileDeviceStatistics' -Service 'Exchange Online'
    $devices = @(Get-MobileDeviceStatistics -Mailbox $upn -ErrorAction Stop | ForEach-Object {
        [pscustomobject][ordered]@{
            Identity = [string]$_.Identity
            UserPrincipalName = $upn
            DeviceId = [string](Get-IRProperty -InputObject $_ -Name 'DeviceId')
            DeviceType = [string](Get-IRProperty -InputObject $_ -Name 'DeviceType')
            DeviceModel = [string](Get-IRProperty -InputObject $_ -Name 'DeviceModel')
            DeviceOS = [string](Get-IRProperty -InputObject $_ -Name 'DeviceOS')
            DeviceUserAgent = [string](Get-IRProperty -InputObject $_ -Name 'DeviceUserAgent')
            DeviceAccessState = [string](Get-IRProperty -InputObject $_ -Name 'DeviceAccessState')
            DeviceAccessStateReason = [string](Get-IRProperty -InputObject $_ -Name 'DeviceAccessStateReason')
            FirstSyncTime = Get-IRProperty -InputObject $_ -Name 'FirstSyncTime'
            LastSuccessSync = Get-IRProperty -InputObject $_ -Name 'LastSuccessSync'
            LastSyncAttemptTime = Get-IRProperty -InputObject $_ -Name 'LastSyncAttemptTime'
        }
    })
    $script:IR.Results.ExchangeMobileDevices = $devices
    $null = Add-IRActionLog -Action 'Collect Exchange mobile-device inventory' -Status Read -Target $upn -Details @{ Devices = $devices.Count }
    return $devices
}

function Remove-IRExchangeMobileDevice {
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    param([Parameter(Mandatory)][string]$Identity)

    Connect-IRExchange
    Assert-IRCommand -Name 'Remove-MobileDevice' -Service 'Exchange Online'
    Invoke-IRChange -Target $Identity -Action 'Remove selected Exchange mobile-device partnership' -Impact High -ExactConfirmation $Identity -Operation {
        Remove-MobileDevice -Identity $Identity -Confirm:$false -ErrorAction Stop
    }
}

function Get-IRIntuneManagedDevice {
    [CmdletBinding()]
    param([string]$UserPrincipalName)

    $user = Get-IRGraphUser -UserPrincipalName $UserPrincipalName
    $null = Connect-IRGraph -Scopes @('DeviceManagementManagedDevices.Read.All') -Modules @('Microsoft.Graph.Devices.CorporateManagement')
    Assert-IRCommand -Name 'Get-MgUserManagedDevice' -Service 'Microsoft Graph / Intune'
    $devices = @(Get-MgUserManagedDevice -UserId $user.Id -All -ErrorAction Stop | ForEach-Object {
        [pscustomobject][ordered]@{
            ManagedDeviceId = [string]$_.Id
            UserPrincipalName = $user.UserPrincipalName
            DeviceName = [string](Get-IRProperty -InputObject $_ -Name 'DeviceName')
            OperatingSystem = [string](Get-IRProperty -InputObject $_ -Name 'OperatingSystem')
            OSVersion = [string](Get-IRProperty -InputObject $_ -Name 'OSVersion')
            Model = [string](Get-IRProperty -InputObject $_ -Name 'Model')
            Manufacturer = [string](Get-IRProperty -InputObject $_ -Name 'Manufacturer')
            SerialNumber = [string](Get-IRProperty -InputObject $_ -Name 'SerialNumber')
            ComplianceState = [string](Get-IRProperty -InputObject $_ -Name 'ComplianceState')
            ManagementAgent = [string](Get-IRProperty -InputObject $_ -Name 'ManagementAgent')
            EnrolledDateTime = Get-IRProperty -InputObject $_ -Name 'EnrolledDateTime'
            LastSyncDateTime = Get-IRProperty -InputObject $_ -Name 'LastSyncDateTime'
            AzureAdDeviceId = [string](Get-IRProperty -InputObject $_ -Name 'AzureAdDeviceId')
        }
    })
    $script:IR.Results.IntuneDevices = $devices
    $null = Add-IRActionLog -Action 'Collect Intune managed-device inventory' -Status Read -Target $user.UserPrincipalName -Details @{ Devices = $devices.Count }
    return $devices
}

function Remove-IRIntuneManagedDevice {
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    param([Parameter(Mandatory)][string]$ManagedDeviceId)

    $null = Connect-IRGraph -Scopes @('DeviceManagementManagedDevices.ReadWrite.All') -Modules @('Microsoft.Graph.DeviceManagement')
    Assert-IRCommand -Name 'Remove-MgDeviceManagementManagedDevice' -Service 'Microsoft Graph / Intune'
    Invoke-IRChange -Target $ManagedDeviceId -Action 'Delete selected Intune managed-device record' -Impact Critical -ExactConfirmation $ManagedDeviceId -Operation {
        Remove-MgDeviceManagementManagedDevice -ManagedDeviceId $ManagedDeviceId -Confirm:$false -ErrorAction Stop
    }
}

function Export-IRIdentityInvestigation {
    [CmdletBinding()]
    param(
        [string]$UserPrincipalName,
        [ValidateRange(1, 180)][int]$DaysBack = $script:IR.Days
    )

    $upn = Resolve-IRTarget -Upn $UserPrincipalName
    $lookbackDays = $DaysBack
    $safe = ConvertTo-IRSafeFileName -Value $upn
    $sets = [ordered]@{}
    $errors = [System.Collections.Generic.List[object]]::new()
    foreach ($item in @(
        @{ Name = 'OAuthGrants'; Operation = { @(Get-IROAuthGrant -UserPrincipalName $upn) } },
        @{ Name = 'AppRoleAssignments'; Operation = { @(Get-IRAppRoleAssignment -UserPrincipalName $upn) } },
        @{ Name = 'SignIns'; Operation = { @(Get-IRUserSignInLog -UserPrincipalName $upn -DaysBack $lookbackDays) } },
        @{ Name = 'AuthenticationMethods'; Operation = { @(Get-IRAuthenticationMethod -UserPrincipalName $upn) } },
        @{ Name = 'RiskyUser'; Operation = { @(Get-IRRiskyUser -UserPrincipalName $upn) } }
    )) {
        try { $sets[$item.Name] = @(& $item.Operation) }
        catch {
            $sets[$item.Name] = @()
            $errors.Add([pscustomobject]@{ Component = $item.Name; Error = $_.Exception.Message })
            Write-IRWarn "$($item.Name) was not collected: $($_.Exception.Message)"
        }
    }
    $paths = [System.Collections.Generic.List[string]]::new()
    foreach ($key in $sets.Keys) {
        if (@($sets[$key]).Count -eq 0) { continue }
        $path = Export-IRData -Data @($sets[$key]) -BaseName "$key-$safe" -Format Csv -Subdirectory 'Identity'
        if ($path) { $paths.Add($path) }
    }
    if ($errors.Count -gt 0) {
        $path = Export-IRData -Data $errors.ToArray() -BaseName "IdentityCollectionErrors-$safe" -Format Csv -Subdirectory 'Identity'
        if ($path) { $paths.Add($path) }
    }
    return [pscustomobject]@{ DataSets = $sets; Errors = $errors.ToArray(); Paths = $paths.ToArray(); Complete = $errors.Count -eq 0 }
}

# ---------------------------------------------------------------------------
# Microsoft Teams and SharePoint Online evidence
# ---------------------------------------------------------------------------

function Get-IRTeamsForensicData {
    [CmdletBinding()]
    param(
        [string]$UserPrincipalName,
        [switch]$IncludeAuditEvents,
        [ValidateRange(1, 180)][int]$DaysBack = $script:IR.Days
    )

    $upn = Resolve-IRTarget -Upn $UserPrincipalName
    Connect-IRTeamService
    Assert-IRCommand -Name @('Get-Team', 'Get-TeamUser', 'Get-TeamChannel') -Service 'Microsoft Teams'
    $teams = @(Get-Team -User $upn -ErrorAction Stop)
    $teamRows = [System.Collections.Generic.List[object]]::new()
    $memberRows = [System.Collections.Generic.List[object]]::new()
    $channelRows = [System.Collections.Generic.List[object]]::new()
    $errors = [System.Collections.Generic.List[object]]::new()

    foreach ($team in $teams) {
        $groupId = [string](Get-IRProperty -InputObject $team -Name 'GroupId')
        $teamRows.Add([pscustomobject]@{
            GroupId = $groupId
            DisplayName = [string](Get-IRProperty -InputObject $team -Name 'DisplayName')
            Description = [string](Get-IRProperty -InputObject $team -Name 'Description')
            Visibility = [string](Get-IRProperty -InputObject $team -Name 'Visibility')
            Archived = Get-IRProperty -InputObject $team -Name 'Archived'
            MailNickName = [string](Get-IRProperty -InputObject $team -Name 'MailNickName')
        })
        try {
            foreach ($member in @(Get-TeamUser -GroupId $groupId -ErrorAction Stop)) {
                $memberRows.Add([pscustomobject]@{
                    GroupId = $groupId
                    Team = [string](Get-IRProperty -InputObject $team -Name 'DisplayName')
                    User = [string](Get-IRProperty -InputObject $member -Name 'User')
                    Name = [string](Get-IRProperty -InputObject $member -Name 'Name')
                    Role = [string](Get-IRProperty -InputObject $member -Name 'Role')
                })
            }
        }
        catch { $errors.Add([pscustomobject]@{ Component = 'Members'; GroupId = $groupId; Error = $_.Exception.Message }) }
        try {
            foreach ($channel in @(Get-TeamChannel -GroupId $groupId -ErrorAction Stop)) {
                $channelRows.Add([pscustomobject]@{
                    GroupId = $groupId
                    Team = [string](Get-IRProperty -InputObject $team -Name 'DisplayName')
                    ChannelId = [string](Get-IRProperty -InputObject $channel -Name 'Id')
                    DisplayName = [string](Get-IRProperty -InputObject $channel -Name 'DisplayName')
                    Description = [string](Get-IRProperty -InputObject $channel -Name 'Description')
                    MembershipType = [string](Get-IRProperty -InputObject $channel -Name 'MembershipType')
                })
            }
        }
        catch { $errors.Add([pscustomobject]@{ Component = 'Channels'; GroupId = $groupId; Error = $_.Exception.Message }) }
    }

    $auditEvents = @()
    if ($IncludeAuditEvents) {
        try {
            $auditEvents = @(Search-IRUnifiedAuditLog -UserIds @($upn) -RecordType MicrosoftTeams -DaysBack $DaysBack | ConvertFrom-IRAuditRecord)
        }
        catch {
            $errors.Add([pscustomobject]@{ Component = 'TeamsAudit'; GroupId = $null; Error = $_.Exception.Message })
        }
    }
    $result = [pscustomobject]@{
        Target = $upn
        Teams = $teamRows.ToArray()
        Members = $memberRows.ToArray()
        Channels = $channelRows.ToArray()
        AuditEvents = $auditEvents
        Errors = $errors.ToArray()
        Complete = $errors.Count -eq 0
    }
    $script:IR.Results.Teams = $result
    $null = Add-IRActionLog -Action 'Collect Teams membership and channel evidence' -Status Read -Target $upn -Details @{ Teams = $teamRows.Count; Errors = $errors.Count }
    return $result
}

function Export-IRTeamsForensicData {
    [CmdletBinding()]
    param(
        [string]$UserPrincipalName,
        [switch]$IncludeAuditEvents,
        [ValidateRange(1, 180)][int]$DaysBack = $script:IR.Days
    )

    $upn = Resolve-IRTarget -Upn $UserPrincipalName
    $data = Get-IRTeamsForensicData -UserPrincipalName $upn -IncludeAuditEvents:$IncludeAuditEvents -DaysBack $DaysBack
    $safe = ConvertTo-IRSafeFileName -Value $upn
    $paths = [System.Collections.Generic.List[string]]::new()
    foreach ($item in @(
        @{ Data = $data.Teams; Name = "Teams-$safe" },
        @{ Data = $data.Members; Name = "TeamMembers-$safe" },
        @{ Data = $data.Channels; Name = "TeamChannels-$safe" },
        @{ Data = $data.AuditEvents; Name = "TeamsAudit-$safe" },
        @{ Data = $data.Errors; Name = "TeamsErrors-$safe" }
    )) {
        if (@($item.Data).Count -eq 0) { continue }
        $path = Export-IRData -Data @($item.Data) -BaseName $item.Name -Format Csv -Subdirectory 'Teams'
        if ($path) { $paths.Add($path) }
    }
    return [pscustomobject]@{ Data = $data; Paths = $paths.ToArray() }
}

function Get-IRSharePointUserAccess {
    [CmdletBinding()]
    param(
        [string]$UserPrincipalName,
        [ValidateRange(1, 100000)][int]$MaximumSites = 500,
        [string]$AdminUrl
    )

    $upn = Resolve-IRTarget -Upn $UserPrincipalName
    $connectedUrl = Connect-IRSharePoint -AdminUrl $AdminUrl
    Assert-IRCommand -Name @('Get-SPOSite', 'Get-SPOUser') -Service 'SharePoint Online'
    $allSites = @(Get-SPOSite -Limit All -IncludePersonalSite $true -ErrorAction Stop | Sort-Object Url)
    $sites = @($allSites | Select-Object -First $MaximumSites)
    $access = [System.Collections.Generic.List[object]]::new()
    $errors = [System.Collections.Generic.List[object]]::new()
    $index = 0
    foreach ($site in $sites) {
        $index++
        Write-Progress -Activity 'SharePoint access review' -Status ([string]$site.Url) -PercentComplete ([math]::Round(($index / [math]::Max(1, $sites.Count)) * 100))
        try {
            $principals = @(Get-SPOUser -Site $site.Url -Limit All -ErrorAction Stop | Where-Object {
                [string](Get-IRProperty -InputObject $_ -Name 'LoginName') -match [regex]::Escape($upn) -or
                [string](Get-IRProperty -InputObject $_ -Name 'Email') -ieq $upn
            })
            foreach ($principal in $principals) {
                $access.Add([pscustomobject]@{
                    SiteUrl = [string]$site.Url
                    SiteTitle = [string](Get-IRProperty -InputObject $site -Name 'Title')
                    Template = [string](Get-IRProperty -InputObject $site -Name 'Template')
                    SharingCapability = [string](Get-IRProperty -InputObject $site -Name 'SharingCapability')
                    StorageUsageCurrent = Get-IRProperty -InputObject $site -Name 'StorageUsageCurrent'
                    LoginName = [string](Get-IRProperty -InputObject $principal -Name 'LoginName')
                    Email = [string](Get-IRProperty -InputObject $principal -Name 'Email')
                    DisplayName = [string](Get-IRProperty -InputObject $principal -Name 'DisplayName')
                    IsSiteAdmin = Get-IRProperty -InputObject $principal -Name 'IsSiteAdmin'
                    IsGroup = Get-IRProperty -InputObject $principal -Name 'IsGroup'
                    AccessInterpretation = 'Principal was returned by Get-SPOUser for this site; validate group-derived versus direct access in the site.'
                })
            }
        }
        catch { $errors.Add([pscustomobject]@{ SiteUrl = [string]$site.Url; Error = $_.Exception.Message }) }
    }
    Write-Progress -Activity 'SharePoint access review' -Completed
    $result = [pscustomobject]@{
        Target = $upn
        AdminUrl = $connectedUrl
        TotalSitesAvailable = $allSites.Count
        SitesScanned = $sites.Count
        Truncated = $allSites.Count -gt $sites.Count
        Access = $access.ToArray()
        Errors = $errors.ToArray()
        Complete = $errors.Count -eq 0 -and $allSites.Count -le $sites.Count
    }
    $script:IR.Results.SharePointAccess = $result
    $null = Add-IRActionLog -Action 'Scan SharePoint site access' -Status Read -Target $upn -Details @{ SitesScanned = $sites.Count; Matches = $access.Count; Errors = $errors.Count; Truncated = $result.Truncated }
    return $result
}

function Export-IRSharePointUserAccess {
    [CmdletBinding()]
    param(
        [string]$UserPrincipalName,
        [ValidateRange(1, 100000)][int]$MaximumSites = 500,
        [string]$AdminUrl
    )

    $upn = Resolve-IRTarget -Upn $UserPrincipalName
    $data = Get-IRSharePointUserAccess -UserPrincipalName $upn -MaximumSites $MaximumSites -AdminUrl $AdminUrl
    $safe = ConvertTo-IRSafeFileName -Value $upn
    $paths = [System.Collections.Generic.List[string]]::new()
    if ($data.Access.Count -gt 0) {
        $paths.Add((Export-IRData -Data $data.Access -BaseName "SharePointAccess-$safe" -Format Csv -Subdirectory 'SharePoint'))
    }
    if ($data.Errors.Count -gt 0) {
        $paths.Add((Export-IRData -Data $data.Errors -BaseName "SharePointAccessErrors-$safe" -Format Csv -Subdirectory 'SharePoint'))
    }
    $summary = $data | Select-Object Target, AdminUrl, TotalSitesAvailable, SitesScanned, Truncated, Complete
    $paths.Add((Export-IRData -Data @($summary) -BaseName "SharePointAccessSummary-$safe" -Format Json -Subdirectory 'SharePoint'))
    return [pscustomobject]@{ Data = $data; Paths = @($paths | Where-Object { $_ }) }
}

function Get-IRSharePointFileAccess {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$PathFragment,
        [string]$UserPrincipalName,
        [ValidateRange(1, 180)][int]$DaysBack = $script:IR.Days,
        [ValidateRange(1, 50000)][int]$MaximumResults = 50000
    )

    $userIds = if ([string]::IsNullOrWhiteSpace($UserPrincipalName) -and [string]::IsNullOrWhiteSpace($script:IR.TargetUpn)) {
        @()
    }
    else { @(Resolve-IRTarget -Upn $UserPrincipalName) }
    $raw = @(Search-IRUnifiedAuditLog -UserIds $userIds -RecordType SharePointFileOperation -DaysBack $DaysBack -MaximumResults $MaximumResults)
    $events = @($raw | ConvertFrom-IRAuditRecord | Where-Object {
        [string]$_.ObjectId -like "*$PathFragment*" -or
        [string]$_.SourceFileName -like "*$PathFragment*" -or
        [string]$_.SiteUrl -like "*$PathFragment*"
    })
    $script:IR.Results.SharePointFileAccess = $events
    $null = Add-IRActionLog -Action 'Collect SharePoint file access by path' -Status Read -Target $PathFragment -Details @{ RecordsExamined = $raw.Count; Matches = $events.Count; UserFilter = $userIds }
    return $events
}

# ---------------------------------------------------------------------------
# Defender mail detections and transparent heuristic threat analysis
# ---------------------------------------------------------------------------

function Get-IRLevenshteinDistance {
    param(
        [Parameter(Mandatory)][AllowEmptyString()][string]$String1,
        [Parameter(Mandatory)][AllowEmptyString()][string]$String2
    )

    $left = $String1.ToLowerInvariant()
    $right = $String2.ToLowerInvariant()
    $matrix = [int[,]]::new($left.Length + 1, $right.Length + 1)
    for ($row = 0; $row -le $left.Length; $row++) { $matrix[$row, 0] = $row }
    for ($column = 0; $column -le $right.Length; $column++) { $matrix[0, $column] = $column }
    for ($row = 1; $row -le $left.Length; $row++) {
        for ($column = 1; $column -le $right.Length; $column++) {
            $cost = if ($left[$row - 1] -eq $right[$column - 1]) { 0 } else { 1 }
            $matrix[$row, $column] = [math]::Min(
                [math]::Min($matrix[($row - 1), $column] + 1, $matrix[$row, ($column - 1)] + 1),
                $matrix[($row - 1), ($column - 1)] + $cost
            )
        }
    }
    return $matrix[$left.Length, $right.Length]
}

function Get-IRDefenderMailDetection {
    [CmdletBinding()]
    param(
        [string]$UserPrincipalName,
        [ValidateRange(1, 10)][int]$DaysBack = [math]::Min(10, $script:IR.Days),
        [ValidateRange(1, 10000)][int]$MaximumResults = 10000
    )

    $upn = Resolve-IRTarget -Upn $UserPrincipalName
    Connect-IRExchange
    Assert-IRCommand -Name 'Get-MailDetailATPReport' -Service 'Exchange Online / Microsoft Defender for Office 365'
    $command = Get-Command Get-MailDetailATPReport -ErrorAction Stop
    $base = @{
        StartDate = (Get-Date).AddDays(-$DaysBack)
        EndDate = Get-Date
        RecipientAddress = $upn
        ErrorAction = 'Stop'
    }
    if ($command.Parameters.ContainsKey('PageSize')) { $base.PageSize = 5000 }
    $results = [System.Collections.Generic.List[object]]::new()
    $page = 1
    while ($results.Count -lt $MaximumResults) {
        $parameters = $base.Clone()
        if ($command.Parameters.ContainsKey('Page')) { $parameters.Page = $page }
        $batch = @(Invoke-IRRetry -Operation { Get-MailDetailATPReport @parameters })
        foreach ($record in $batch) {
            if ($results.Count -ge $MaximumResults) { break }
            $results.Add($record)
        }
        if (-not $command.Parameters.ContainsKey('Page') -or $batch.Count -eq 0 -or
            ($command.Parameters.ContainsKey('PageSize') -and $batch.Count -lt [int]$base.PageSize)) { break }
        $page++
    }
    if ($results.Count -ge $MaximumResults) { Write-IRWarn 'Defender mail detail collection reached its configured record ceiling.' }
    $array = $results.ToArray()
    $script:IR.Results.DefenderMailDetections = $array
    $null = Add-IRActionLog -Action 'Collect Defender mail-detail detections' -Status Read -Target $upn -Details @{ Records = $array.Count; Days = $DaysBack }
    return $array
}

function Get-IRMessageThreatHeuristic {
    [CmdletBinding()]
    param(
        [string]$UserPrincipalName,
        [object[]]$Messages,
        [string[]]$ProtectedDomains,
        [ValidateRange(1, 90)][int]$DaysBack = $script:IR.Days
    )

    $upn = Resolve-IRTarget -Upn $UserPrincipalName
    if (-not $PSBoundParameters.ContainsKey('Messages')) {
        $Messages = @(Get-IRMessageTrace -UserPrincipalName $upn -Direction Received -DaysBack $DaysBack)
    }
    if (-not $ProtectedDomains -or $ProtectedDomains.Count -eq 0) {
        $ProtectedDomains = @(Get-IRAcceptedDomain)
    }
    $protected = @($ProtectedDomains | ForEach-Object { $_.Trim().ToLowerInvariant() } | Where-Object { $_ } | Sort-Object -Unique)
    $patterns = [ordered]@{
        'Urgent action language' = '(?i)urgent.{0,25}(action|response).{0,25}required'
        'Account verification language' = '(?i)(verify|validate).{0,25}(account|identity|password)'
        'Account suspension language' = '(?i)(suspend|disable|expire).{0,25}(account|mailbox|access)'
        'Prize or lottery language' = '(?i)\b(winner|lottery|prize|gift card)\b'
        'Invoice or payment language' = '(?i)\b(invoice|payment|wire|remittance)\b'
    }
    $findings = [System.Collections.Generic.List[object]]::new()
    foreach ($message in @($Messages)) {
        $messageSender = [string](Get-IRProperty -InputObject $message -Name 'SenderAddress')
        $subject = [string](Get-IRProperty -InputObject $message -Name 'Subject')
        $senderDomain = if ($messageSender -match '@([^@]+)$') { $Matches[1].ToLowerInvariant() } else { '' }
        foreach ($pair in $patterns.GetEnumerator()) {
            if ($subject -match $pair.Value) {
                $findings.Add([pscustomobject]@{
                    FindingType = 'SubjectPattern'
                    Severity = 'Review'
                    SenderAddress = $messageSender
                    SenderDomain = $senderDomain
                    RecipientAddress = [string](Get-IRProperty -InputObject $message -Name 'RecipientAddress')
                    Subject = $subject
                    MessageTraceId = [string](Get-IRProperty -InputObject $message -Name 'MessageTraceId')
                    Received = Get-IRProperty -InputObject $message -Name 'Received'
                    Reason = [string]$pair.Key
                    ComparedDomain = $null
                })
            }
        }
        if ($senderDomain -and $senderDomain -notin $protected) {
            foreach ($domain in $protected) {
                $distance = Get-IRLevenshteinDistance -String1 $senderDomain -String2 $domain
                if ($distance -ge 1 -and $distance -le 2) {
                    $findings.Add([pscustomobject]@{
                        FindingType = 'PossibleTyposquat'
                        Severity = 'ReviewHigh'
                        SenderAddress = $messageSender
                        SenderDomain = $senderDomain
                        RecipientAddress = [string](Get-IRProperty -InputObject $message -Name 'RecipientAddress')
                        Subject = $subject
                        MessageTraceId = [string](Get-IRProperty -InputObject $message -Name 'MessageTraceId')
                        Received = Get-IRProperty -InputObject $message -Name 'Received'
                        Reason = "Edit distance $distance from protected domain"
                        ComparedDomain = $domain
                    })
                }
            }
        }
    }
    $unique = @($findings | Sort-Object FindingType, MessageTraceId, SenderAddress, Reason -Unique)
    $script:IR.Results.ThreatHeuristics = $unique
    $null = Add-IRActionLog -Action 'Run transparent message threat heuristics' -Status Read -Target $upn -Details @{ Messages = @($Messages).Count; Findings = $unique.Count; ProtectedDomains = $protected }
    return $unique
}

function New-IRThreatHuntingQueryFile {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [string]$UserPrincipalName,
        [ValidateRange(1, 90)][int]$DaysBack = $script:IR.Days
    )

    $upn = Resolve-IRTarget -Upn $UserPrincipalName
    $directory = Get-IRCasePath -ChildPath 'Threat' -CreateDirectory
    $path = Join-Path -Path $directory -ChildPath ("AdvancedHunting-{0}.kql" -f (ConvertTo-IRSafeFileName -Value $upn))
    $query = @"
// Review Defender email detections for the target.
let TargetUser = "$upn";
let Lookback = ${DaysBack}d;
EmailEvents
| where Timestamp >= ago(Lookback)
| where RecipientEmailAddress =~ TargetUser or SenderFromAddress =~ TargetUser
| where isnotempty(ThreatTypes) or isnotempty(DetectionMethods)
| project Timestamp, NetworkMessageId, InternetMessageId, SenderFromAddress,
          RecipientEmailAddress, Subject, DeliveryAction, DeliveryLocation,
          ThreatTypes, DetectionMethods
| order by Timestamp desc

// Review URL-click telemetry for the target (requires applicable licensing/retention).
UrlClickEvents
| where Timestamp >= ago(Lookback)
| where AccountUpn =~ TargetUser
| project Timestamp, AccountUpn, Url, ActionType, IsClickedThrough,
          NetworkMessageId, ThreatTypes, DetectionMethods
| order by Timestamp desc

// Review URLs delivered in messages to the target.
EmailUrlInfo
| where Timestamp >= ago(Lookback)
| join kind=inner (
    EmailEvents
    | where Timestamp >= ago(Lookback)
    | where RecipientEmailAddress =~ TargetUser
    | project NetworkMessageId
) on NetworkMessageId
| project Timestamp, NetworkMessageId, Url, UrlDomain
| order by Timestamp desc
"@
    $null = Add-IRActionLog -Action 'Generate Defender advanced-hunting query file' -Status Read -Target $upn -Details @{ Days = $DaysBack }
    if ($PSCmdlet.ShouldProcess($path, 'Write KQL hunting queries')) {
        $query | Set-Content -LiteralPath $path -Encoding utf8
    }
    return $path
}

function Export-IRThreatInvestigation {
    [CmdletBinding()]
    param(
        [string]$UserPrincipalName,
        [ValidateRange(1, 90)][int]$DaysBack = $script:IR.Days,
        [string[]]$ProtectedDomains
    )

    $upn = Resolve-IRTarget -Upn $UserPrincipalName
    $safe = ConvertTo-IRSafeFileName -Value $upn
    $messages = @(Get-IRMessageTrace -UserPrincipalName $upn -Direction Received -DaysBack $DaysBack)
    $heuristics = @(Get-IRMessageThreatHeuristic -UserPrincipalName $upn -Messages $messages -ProtectedDomains $ProtectedDomains -DaysBack $DaysBack)
    $errors = [System.Collections.Generic.List[object]]::new()
    $detections = @()
    try { $detections = @(Get-IRDefenderMailDetection -UserPrincipalName $upn -DaysBack ([math]::Min(10, $DaysBack))) }
    catch {
        $errors.Add([pscustomobject]@{ Component = 'DefenderMailDetail'; Error = $_.Exception.Message })
        Write-IRWarn "Defender mail-detail data was not collected: $($_.Exception.Message)"
    }
    $paths = [System.Collections.Generic.List[string]]::new()
    foreach ($item in @(
        @{ Data = $heuristics; Name = "ThreatHeuristics-$safe" },
        @{ Data = $detections; Name = "DefenderMailDetections-$safe" },
        @{ Data = $errors.ToArray(); Name = "ThreatCollectionErrors-$safe" }
    )) {
        if (@($item.Data).Count -eq 0) { continue }
        $path = Export-IRData -Data @($item.Data) -BaseName $item.Name -Format Csv -Subdirectory 'Threat'
        if ($path) { $paths.Add($path) }
    }
    $queryPath = New-IRThreatHuntingQueryFile -UserPrincipalName $upn -DaysBack $DaysBack
    if ($queryPath) { $paths.Add($queryPath) }
    return [pscustomobject]@{ Messages = $messages; Heuristics = $heuristics; DefenderDetections = $detections; Errors = $errors.ToArray(); Paths = $paths.ToArray(); Complete = $errors.Count -eq 0 }
}

# ---------------------------------------------------------------------------
# Microsoft Purview content search (cloud export is intentionally not faked)
# ---------------------------------------------------------------------------

function New-IRContentSearch {
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    param(
        [string]$UserPrincipalName,
        [ValidateRange(1, 180)][int]$DaysBack = $script:IR.Days,
        [string]$ContentMatchQuery,
        [string]$Name
    )

    $upn = Resolve-IRTarget -Upn $UserPrincipalName
    Connect-IRPurview
    Assert-IRCommand -Name 'New-ComplianceSearch' -Service 'Microsoft Purview'
    if ([string]::IsNullOrWhiteSpace($Name)) {
        $Name = 'IR-{0}-{1}' -f (ConvertTo-IRSafeFileName -Value $upn -MaximumLength 45), [datetime]::UtcNow.ToString('yyyyMMdd-HHmmss')
    }
    if ([string]::IsNullOrWhiteSpace($ContentMatchQuery)) {
        $start = [datetime]::UtcNow.AddDays(-$DaysBack).ToString('yyyy-MM-dd')
        $end = [datetime]::UtcNow.ToString('yyyy-MM-dd')
        $ContentMatchQuery = "(sent>=$start AND sent<=$end)"
    }
    Invoke-IRChange -Target $Name -Action 'Create Microsoft Purview content search' -Impact High -ExactConfirmation $Name -Details @{ ExchangeLocation = $upn; Query = $ContentMatchQuery } -Operation {
        New-ComplianceSearch -Name $Name -ExchangeLocation $upn -ContentMatchQuery $ContentMatchQuery -ErrorAction Stop
    }
}

function Start-IRContentSearch {
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    param([Parameter(Mandatory)][string]$Name)

    Connect-IRPurview
    Assert-IRCommand -Name 'Start-ComplianceSearch' -Service 'Microsoft Purview'
    Invoke-IRChange -Target $Name -Action 'Start Microsoft Purview content search' -Impact Medium -ExactConfirmation $Name -Operation {
        Start-ComplianceSearch -Identity $Name -Confirm:$false -ErrorAction Stop
    }
}

function Get-IRContentSearch {
    [CmdletBinding()]
    param([string]$Name)

    Connect-IRPurview
    Assert-IRCommand -Name 'Get-ComplianceSearch' -Service 'Microsoft Purview'
    $searches = if ([string]::IsNullOrWhiteSpace($Name)) {
        @(Get-ComplianceSearch -ErrorAction Stop)
    }
    else { @(Get-ComplianceSearch -Identity $Name -ErrorAction Stop) }
    $rows = @($searches | Select-Object Name, Status, Items, Size, SuccessResults, Errors, CreatedTime, LastModifiedTime, CreatedBy, ExchangeLocation, ContentMatchQuery)
    $script:IR.Results.ContentSearches = $rows
    $null = Add-IRActionLog -Action 'Review Microsoft Purview content searches' -Status Read -Target $Name -Details @{ Searches = $rows.Count }
    return $rows
}

function Remove-IRContentSearch {
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    param([Parameter(Mandatory)][string]$Name)

    Connect-IRPurview
    Assert-IRCommand -Name 'Remove-ComplianceSearch' -Service 'Microsoft Purview'
    Invoke-IRChange -Target $Name -Action 'Remove Microsoft Purview content search definition' -Impact High -ExactConfirmation $Name -Operation {
        Remove-ComplianceSearch -Identity $Name -Confirm:$false -ErrorAction Stop
    }
}

function Get-IRContentSearchExportGuidance {
    [CmdletBinding()]
    param()

    return [pscustomobject][ordered]@{
        SupportedSearchCommands = 'New-ComplianceSearch; Start-ComplianceSearch; Get-ComplianceSearch'
        CloudPowerShellExport = 'Not supported by this console. The legacy New-ComplianceSearchAction -Export flow was retired for cloud use.'
        CurrentExportPath = 'Use the Microsoft Purview portal eDiscovery export workflow, or an organization-approved current API workflow.'
        Portal = 'https://purview.microsoft.com/'
        IntegrityNote = 'After downloading, place exports in the case directory and regenerate the SHA-256 manifest.'
    }
}

# ---------------------------------------------------------------------------
# Tenant security policy review, backup, and guarded changes
# ---------------------------------------------------------------------------

function Get-IRSecurityPolicySnapshot {
    [CmdletBinding()]
    param()

    Connect-IRExchange
    $requests = @(
        @{ Name = 'InboundSpam'; Command = 'Get-HostedContentFilterPolicy' },
        @{ Name = 'OutboundSpam'; Command = 'Get-HostedOutboundSpamFilterPolicy' },
        @{ Name = 'AntiPhish'; Command = 'Get-AntiPhishPolicy' },
        @{ Name = 'SafeLinks'; Command = 'Get-SafeLinksPolicy' },
        @{ Name = 'SafeAttachments'; Command = 'Get-SafeAttachmentPolicy' },
        @{ Name = 'Quarantine'; Command = 'Get-QuarantinePolicy' },
        @{ Name = 'TransportRules'; Command = 'Get-TransportRule' }
    )
    $data = [ordered]@{}
    $status = [System.Collections.Generic.List[object]]::new()
    foreach ($request in $requests) {
        $command = Get-Command -Name $request.Command -ErrorAction SilentlyContinue
        if (-not $command) {
            $data[$request.Name] = @()
            $status.Add([pscustomobject]@{ Component = $request.Name; Status = 'Unavailable'; Records = 0; Error = "Command $($request.Command) is unavailable for this connection or role." })
            continue
        }
        try {
            $records = @(& $request.Command -ErrorAction Stop)
            $data[$request.Name] = $records
            $status.Add([pscustomobject]@{ Component = $request.Name; Status = 'Collected'; Records = $records.Count; Error = $null })
        }
        catch {
            $data[$request.Name] = @()
            $status.Add([pscustomobject]@{ Component = $request.Name; Status = 'Failed'; Records = 0; Error = $_.Exception.Message })
        }
    }
    $result = [pscustomobject]@{ CollectedUtc = [datetime]::UtcNow; Data = $data; Status = $status.ToArray(); Complete = @($status | Where-Object Status -ne 'Collected').Count -eq 0 }
    $script:IR.Results.SecurityPolicies = $result
    $null = Add-IRActionLog -Action 'Collect tenant security policy snapshot' -Status Read -Target 'Tenant' -Details @{ Status = $status.ToArray() }
    return $result
}

function Backup-IRSecurityPolicy {
    [CmdletBinding()]
    param()

    $snapshot = Get-IRSecurityPolicySnapshot
    $paths = [System.Collections.Generic.List[string]]::new()
    foreach ($key in $snapshot.Data.Keys) {
        $records = @($snapshot.Data[$key])
        if ($records.Count -eq 0) { continue }
        $json = Export-IRData -Data $records -BaseName "Policy-$key" -Format Json -Subdirectory 'Policies'
        if ($json) { $paths.Add($json) }
        $xml = Export-IRData -Data $records -BaseName "Policy-$key-Raw" -Format Clixml -Subdirectory 'Policies'
        if ($xml) { $paths.Add($xml) }
    }
    $statusPath = Export-IRData -Data $snapshot.Status -BaseName 'PolicyCollectionStatus' -Format Csv -Subdirectory 'Policies'
    if ($statusPath) { $paths.Add($statusPath) }
    return [pscustomobject]@{ Snapshot = $snapshot; Paths = $paths.ToArray(); Complete = [bool]$snapshot.Complete; Errors = @($snapshot.Status | Where-Object Status -ne 'Collected') }
}

function Add-IRBlockedSender {
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    param(
        [string[]]$SenderAddress,
        [string[]]$Domain,
        [string]$PolicyIdentity = 'Default'
    )

    if ((!$SenderAddress -or $SenderAddress.Count -eq 0) -and (!$Domain -or $Domain.Count -eq 0)) {
        throw 'Provide at least one sender address or domain.'
    }
    foreach ($address in @($SenderAddress)) {
        if (-not (Test-IRUpn -Value $address)) { throw "'$address' is not a valid sender address." }
    }
    foreach ($item in @($Domain)) {
        if ($item -notmatch '^(?=.{1,253}$)([a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$') {
            throw "'$item' is not a valid DNS domain name."
        }
    }

    Connect-IRExchange
    Assert-IRCommand -Name @('Get-HostedContentFilterPolicy', 'Set-HostedContentFilterPolicy') -Service 'Exchange Online'
    $current = Get-HostedContentFilterPolicy -Identity $PolicyIdentity -ErrorAction Stop
    $senders = @(@(Get-IRProperty -InputObject $current -Name 'BlockedSenders' -Default @()) + @($SenderAddress) | ForEach-Object { [string]$_ } | Where-Object { $_ } | Sort-Object -Unique)
    $domains = @(@(Get-IRProperty -InputObject $current -Name 'BlockedSenderDomains' -Default @()) + @($Domain) | ForEach-Object { [string]$_ } | Where-Object { $_ } | Sort-Object -Unique)
    $confirmation = "BLOCK $PolicyIdentity"
    Invoke-IRChange -Target $PolicyIdentity -Action 'Add entries to the inbound anti-spam block lists' -Impact High -ExactConfirmation $confirmation -Details @{ Senders = $SenderAddress; Domains = $Domain } -Operation {
        Set-HostedContentFilterPolicy -Identity $PolicyIdentity -BlockedSenders $senders -BlockedSenderDomains $domains -ErrorAction Stop
    }
}

function Set-IRAntiPhishProtection {
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    param([Parameter(Mandatory)][string]$PolicyIdentity)

    Connect-IRExchange
    Assert-IRCommand -Name @('Get-AntiPhishPolicy', 'Set-AntiPhishPolicy') -Service 'Exchange Online'
    $command = Get-Command Set-AntiPhishPolicy -ErrorAction Stop
    $requested = [ordered]@{
        EnableSpoofIntelligence = $true
        EnableMailboxIntelligence = $true
        EnableMailboxIntelligenceProtection = $true
        EnableFirstContactSafetyTips = $true
        EnableSimilarUsersSafetyTips = $true
        EnableSimilarDomainsSafetyTips = $true
        EnableUnusualCharactersSafetyTips = $true
    }
    $parameters = @{ Identity = $PolicyIdentity; ErrorAction = 'Stop' }
    foreach ($key in $requested.Keys) {
        if ($command.Parameters.ContainsKey($key)) { $parameters[$key] = $requested[$key] }
    }
    if ($parameters.Count -le 2) {
        throw 'The connected service did not expose the supported anti-phishing protection parameters.'
    }
    $before = Get-AntiPhishPolicy -Identity $PolicyIdentity -ErrorAction Stop
    Invoke-IRChange -Target $PolicyIdentity -Action 'Enable supported anti-phishing intelligence and safety tips' -Impact High -ExactConfirmation $PolicyIdentity -Details @{ Parameters = @($parameters.Keys | Where-Object { $_ -notin @('Identity', 'ErrorAction') }); Before = $before.Name } -Operation {
        Set-AntiPhishPolicy @parameters
    }
}

function Get-IROutboundSpamProtectionStatus {
    [CmdletBinding()]
    param()

    Connect-IRExchange
    Assert-IRCommand -Name 'Get-HostedOutboundSpamFilterPolicy' -Service 'Exchange Online'
    $policies = @(Get-HostedOutboundSpamFilterPolicy -ErrorAction Stop | Select-Object Name, IsDefault, RecipientLimitExternalPerHour, RecipientLimitInternalPerHour, RecipientLimitPerDay, ActionWhenThresholdReached, AutoForwardingMode, BccSuspiciousOutboundMail, BccSuspiciousOutboundAdditionalRecipients, NotifyOutboundSpam, NotifyOutboundSpamRecipients)
    $alerts = @()
    if (Get-Command Get-ProtectionAlert -ErrorAction SilentlyContinue) {
        $alerts = @(Get-ProtectionAlert -ErrorAction Stop | Where-Object {
            [string]$_.Name -match '(?i)(restricted.*sending|outbound.*spam)' -or [string]$_.Category -match '(?i)threat'
        } | Select-Object Name, Category, ThreatType, Severity, Disabled, NotifyUser, NotifyUserOnFilterMatch)
    }
    return [pscustomobject]@{
        OutboundPolicies = $policies
        RelevantAlerts = $alerts
        Notice = 'Microsoft recommends the built-in User restricted from sending email alert policy. Legacy outbound notification fields may be present for compatibility but are not configured by this console.'
    }
}

function New-IRPhishingQuarantineRule {
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    param(
        [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string[]]$SubjectContainsWords,
        [string]$Name,
        [ValidateSet('Audit', 'Enforce')][string]$RuleMode = 'Audit'
    )

    Connect-IRExchange
    Assert-IRCommand -Name 'New-TransportRule' -Service 'Exchange Online'
    $command = Get-Command New-TransportRule -ErrorAction Stop
    foreach ($parameterName in @('SubjectContainsWords', 'Quarantine', 'Mode')) {
        if (-not $command.Parameters.ContainsKey($parameterName)) {
            throw "The connected New-TransportRule command does not expose -$parameterName; no rule was created."
        }
    }
    if ([string]::IsNullOrWhiteSpace($Name)) { $Name = "IR-Phishing-Quarantine-$([datetime]::UtcNow.ToString('yyyyMMdd-HHmmss'))" }
    $parameters = @{
        Name = $Name
        SubjectContainsWords = $SubjectContainsWords
        Quarantine = $true
        Mode = $RuleMode
        Comments = 'Managed by M365-IR-Console. Subject-only matching requires analyst review for false positives.'
        ErrorAction = 'Stop'
    }
    Invoke-IRChange -Target $Name -Action "Create $RuleMode phishing quarantine transport rule" -Impact Critical -ExactConfirmation $Name -Details @{ SubjectContainsWords = $SubjectContainsWords; RuleMode = $RuleMode } -Operation {
        New-TransportRule @parameters
    }
}

function Get-IRConditionalAccessPolicyReport {
    [CmdletBinding()]
    param()

    $null = Connect-IRGraph -Scopes @('Policy.Read.All') -Modules @('Microsoft.Graph.Identity.SignIns')
    Assert-IRCommand -Name 'Get-MgIdentityConditionalAccessPolicy' -Service 'Microsoft Graph'
    $policies = @(Get-MgIdentityConditionalAccessPolicy -All -ErrorAction Stop)
    $rows = foreach ($policy in $policies) {
        $conditions = Get-IRProperty -InputObject $policy -Name 'Conditions'
        $users = Get-IRProperty -InputObject $conditions -Name 'Users'
        $applications = Get-IRProperty -InputObject $conditions -Name 'Applications'
        $grant = Get-IRProperty -InputObject $policy -Name 'GrantControls'
        [pscustomobject][ordered]@{
            Id = [string]$policy.Id
            DisplayName = [string]$policy.DisplayName
            State = [string]$policy.State
            CreatedDateTime = Get-IRProperty -InputObject $policy -Name 'CreatedDateTime'
            ModifiedDateTime = Get-IRProperty -InputObject $policy -Name 'ModifiedDateTime'
            Description = [string](Get-IRProperty -InputObject $policy -Name 'Description')
            IncludeUsers = ConvertTo-IRDisplayString -Value (Get-IRProperty -InputObject $users -Name 'IncludeUsers' -Default @())
            ExcludeUsers = ConvertTo-IRDisplayString -Value (Get-IRProperty -InputObject $users -Name 'ExcludeUsers' -Default @())
            IncludeGroups = ConvertTo-IRDisplayString -Value (Get-IRProperty -InputObject $users -Name 'IncludeGroups' -Default @())
            ExcludeGroups = ConvertTo-IRDisplayString -Value (Get-IRProperty -InputObject $users -Name 'ExcludeGroups' -Default @())
            IncludeRoles = ConvertTo-IRDisplayString -Value (Get-IRProperty -InputObject $users -Name 'IncludeRoles' -Default @())
            IncludeApplications = ConvertTo-IRDisplayString -Value (Get-IRProperty -InputObject $applications -Name 'IncludeApplications' -Default @())
            ClientAppTypes = ConvertTo-IRDisplayString -Value (Get-IRProperty -InputObject $conditions -Name 'ClientAppTypes' -Default @())
            SignInRiskLevels = ConvertTo-IRDisplayString -Value (Get-IRProperty -InputObject $conditions -Name 'SignInRiskLevels' -Default @())
            BuiltInControls = ConvertTo-IRDisplayString -Value (Get-IRProperty -InputObject $grant -Name 'BuiltInControls' -Default @())
            GrantOperator = [string](Get-IRProperty -InputObject $grant -Name 'Operator')
        }
    }
    $script:IR.Results.ConditionalAccessPolicies = @($rows)
    $null = Add-IRActionLog -Action 'Collect Conditional Access policy report' -Status Read -Target 'Tenant' -Details @{ Policies = @($rows).Count }
    return @($rows)
}

function New-IRConditionalAccessBaseline {
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    param(
        [Parameter(Mandatory)][guid]$ExclusionGroupId,
        [ValidateSet('BlockLegacyAuthentication', 'RequireMfaForAdmins', 'RequireMfaForUsers', 'RequireMfaForRiskySignIns')]
        [string[]]$Policy = @('BlockLegacyAuthentication', 'RequireMfaForAdmins', 'RequireMfaForUsers', 'RequireMfaForRiskySignIns'),
        [ValidateSet('enabledForReportingButNotEnabled', 'enabled')]
        [string]$State = 'enabledForReportingButNotEnabled',
        [string]$NamePrefix = 'IR Baseline'
    )

    $scopes = @('Policy.ReadWrite.ConditionalAccess', 'GroupMember.Read.All', 'RoleManagement.Read.Directory', 'User.Read.All')
    $null = Connect-IRGraph -Scopes $scopes -Modules @(
        'Microsoft.Graph.Identity.SignIns',
        'Microsoft.Graph.Groups',
        'Microsoft.Graph.Identity.DirectoryManagement',
        'Microsoft.Graph.Users'
    )
    Assert-IRCommand -Name @('Get-MgGroup', 'Get-MgGroupMember', 'Get-MgUser', 'Get-MgDirectoryRoleTemplate', 'Get-MgIdentityConditionalAccessPolicy', 'New-MgIdentityConditionalAccessPolicy') -Service 'Microsoft Graph'
    $group = Get-MgGroup -GroupId $ExclusionGroupId -Property Id, DisplayName -ErrorAction Stop
    $members = @(Get-MgGroupMember -GroupId $ExclusionGroupId -All -ErrorAction Stop)
    if ($members.Count -eq 0) {
        throw "Exclusion group '$($group.DisplayName)' is empty. Add and validate emergency-access accounts before creating broad Conditional Access policies."
    }
    $enabledEmergencyUsers = [System.Collections.Generic.List[object]]::new()
    foreach ($member in $members) {
        try {
            $memberUser = Get-MgUser -UserId $member.Id -Property Id, UserPrincipalName, AccountEnabled -ErrorAction Stop
            if ([bool]$memberUser.AccountEnabled) { $enabledEmergencyUsers.Add($memberUser) }
        }
        catch {
            Write-Verbose "Exclusion member $($member.Id) is not a readable user object: $($_.Exception.Message)"
        }
    }
    if ($enabledEmergencyUsers.Count -eq 0) {
        throw "Exclusion group '$($group.DisplayName)' has no enabled, readable user accounts. No baseline policy was created."
    }
    if ($enabledEmergencyUsers.Count -lt 2) {
        Write-IRWarn "Exclusion group '$($group.DisplayName)' has only one enabled user; two independently monitored emergency-access accounts are recommended."
    }

    $roleNames = @(
        'Global Administrator',
        'Privileged Role Administrator',
        'Conditional Access Administrator',
        'Security Administrator',
        'Exchange Administrator',
        'SharePoint Administrator'
    )
    $roleTemplates = @(Get-MgDirectoryRoleTemplate -All -ErrorAction Stop | Where-Object DisplayName -in $roleNames)
    if ($roleTemplates.Count -eq 0 -and $Policy -contains 'RequireMfaForAdmins') {
        throw 'No selected administrator role templates were returned; the administrator MFA policy was not created.'
    }

    $exclude = @([string]$ExclusionGroupId)
    $applications = @{ IncludeApplications = @('All') }
    $definitions = [ordered]@{
        BlockLegacyAuthentication = @{
            DisplayName = "$NamePrefix - Block legacy authentication"
            State = $State
            Description = "[ManagedBy:M365-IR-Console] Created $([datetime]::UtcNow.ToString('o')); emergency exclusion group $ExclusionGroupId."
            Conditions = @{
                Users = @{ IncludeUsers = @('All'); ExcludeGroups = $exclude }
                Applications = $applications
                ClientAppTypes = @('exchangeActiveSync', 'other')
            }
            GrantControls = @{ Operator = 'OR'; BuiltInControls = @('block') }
        }
        RequireMfaForAdmins = @{
            DisplayName = "$NamePrefix - Require MFA for administrators"
            State = $State
            Description = "[ManagedBy:M365-IR-Console] Created $([datetime]::UtcNow.ToString('o')); emergency exclusion group $ExclusionGroupId."
            Conditions = @{
                Users = @{ IncludeRoles = @($roleTemplates.Id); ExcludeGroups = $exclude }
                Applications = $applications
                ClientAppTypes = @('all')
            }
            GrantControls = @{ Operator = 'OR'; BuiltInControls = @('mfa') }
        }
        RequireMfaForUsers = @{
            DisplayName = "$NamePrefix - Require MFA for all users"
            State = $State
            Description = "[ManagedBy:M365-IR-Console] Created $([datetime]::UtcNow.ToString('o')); emergency exclusion group $ExclusionGroupId."
            Conditions = @{
                Users = @{ IncludeUsers = @('All'); ExcludeGroups = $exclude }
                Applications = $applications
                ClientAppTypes = @('all')
            }
            GrantControls = @{ Operator = 'OR'; BuiltInControls = @('mfa') }
        }
        RequireMfaForRiskySignIns = @{
            DisplayName = "$NamePrefix - Require MFA for risky sign-ins"
            State = $State
            Description = "[ManagedBy:M365-IR-Console] Created $([datetime]::UtcNow.ToString('o')); emergency exclusion group $ExclusionGroupId; requires Entra ID Protection licensing."
            Conditions = @{
                Users = @{ IncludeUsers = @('All'); ExcludeGroups = $exclude }
                Applications = $applications
                ClientAppTypes = @('all')
                SignInRiskLevels = @('medium', 'high')
            }
            GrantControls = @{ Operator = 'OR'; BuiltInControls = @('mfa') }
        }
    }

    $existing = @(Get-MgIdentityConditionalAccessPolicy -All -ErrorAction Stop)
    $created = [System.Collections.Generic.List[object]]::new()
    foreach ($key in $Policy) {
        $body = $definitions[$key]
        if (@($existing | Where-Object DisplayName -eq $body.DisplayName).Count -gt 0) {
            Write-IRWarn "A Conditional Access policy named '$($body.DisplayName)' already exists; skipped."
            $null = Add-IRActionLog -Action 'Create Conditional Access baseline policy' -Status Skipped -Target $body.DisplayName -Details 'Name already exists'
            continue
        }
        $result = Invoke-IRChange -Target $body.DisplayName -Action "Create Conditional Access policy in state $State" -Impact Critical -ExactConfirmation $body.DisplayName -Details @{ ExclusionGroup = [string]$ExclusionGroupId; EnabledEmergencyUsers = $enabledEmergencyUsers.Count; State = $State } -Operation {
            New-MgIdentityConditionalAccessPolicy -BodyParameter $body -ErrorAction Stop
        }
        if ($result) { $created.Add($result) }
    }
    return $created.ToArray()
}

function Set-IRConditionalAccessPolicyState {
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    param(
        [Parameter(Mandatory)][string]$PolicyId,
        [Parameter(Mandatory)][ValidateSet('enabled', 'disabled', 'enabledForReportingButNotEnabled')][string]$State
    )

    $null = Connect-IRGraph -Scopes @('Policy.ReadWrite.ConditionalAccess') -Modules @('Microsoft.Graph.Identity.SignIns')
    Assert-IRCommand -Name @('Get-MgIdentityConditionalAccessPolicy', 'Update-MgIdentityConditionalAccessPolicy') -Service 'Microsoft Graph'
    $policy = Get-MgIdentityConditionalAccessPolicy -ConditionalAccessPolicyId $PolicyId -ErrorAction Stop
    Invoke-IRChange -Target "$($policy.DisplayName) [$PolicyId]" -Action "Set Conditional Access policy state to $State" -Impact Critical -ExactConfirmation $PolicyId -Operation {
        Update-MgIdentityConditionalAccessPolicy -ConditionalAccessPolicyId $PolicyId -BodyParameter @{ State = $State } -ErrorAction Stop
    }
}

# ---------------------------------------------------------------------------
# Evidence orchestration, reporting, integrity, and portable analyst packages
# ---------------------------------------------------------------------------

function Export-IRDeviceInvestigation {
    [CmdletBinding()]
    param([string]$UserPrincipalName)

    $upn = Resolve-IRTarget -Upn $UserPrincipalName
    $safe = ConvertTo-IRSafeFileName -Value $upn
    $exchangeDevices = @()
    $intuneDevices = @()
    $errors = [System.Collections.Generic.List[object]]::new()
    try { $exchangeDevices = @(Get-IRExchangeMobileDevice -UserPrincipalName $upn) }
    catch { $errors.Add([pscustomobject]@{ Component = 'ExchangeMobileDevices'; Error = $_.Exception.Message }) }
    try { $intuneDevices = @(Get-IRIntuneManagedDevice -UserPrincipalName $upn) }
    catch { $errors.Add([pscustomobject]@{ Component = 'IntuneManagedDevices'; Error = $_.Exception.Message }) }
    $paths = [System.Collections.Generic.List[string]]::new()
    foreach ($item in @(
        @{ Data = $exchangeDevices; Name = "ExchangeMobileDevices-$safe" },
        @{ Data = $intuneDevices; Name = "IntuneManagedDevices-$safe" },
        @{ Data = $errors.ToArray(); Name = "DeviceCollectionErrors-$safe" }
    )) {
        if (@($item.Data).Count -eq 0) { continue }
        $path = Export-IRData -Data @($item.Data) -BaseName $item.Name -Format Csv -Subdirectory 'Devices'
        if ($path) { $paths.Add($path) }
    }
    return [pscustomobject]@{
        ExchangeDevices = $exchangeDevices
        IntuneDevices = $intuneDevices
        Errors = $errors.ToArray()
        Complete = $errors.Count -eq 0
        Paths = $paths.ToArray()
    }
}

function Invoke-IRCollectionStep {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][scriptblock]$Operation
    )

    $started = [datetime]::UtcNow
    Write-IRInfo "Collecting: $Name"
    try {
        $result = & $Operation
        $script:IR.Results["Collection:$Name"] = $result
        $complete = $true
        $completeProperty = Get-IRProperty -InputObject $result -Name 'Complete'
        if ($null -ne $completeProperty -and -not [bool]$completeProperty) { $complete = $false }
        $dataProperty = Get-IRProperty -InputObject $result -Name 'Data'
        $nestedComplete = Get-IRProperty -InputObject $dataProperty -Name 'Complete'
        if ($null -ne $nestedComplete -and -not [bool]$nestedComplete) { $complete = $false }
        $snapshotProperty = Get-IRProperty -InputObject $result -Name 'Snapshot'
        $snapshotComplete = Get-IRProperty -InputObject $snapshotProperty -Name 'Complete'
        if ($null -ne $snapshotComplete -and -not [bool]$snapshotComplete) { $complete = $false }
        $errors = @(Get-IRProperty -InputObject $result -Name 'Errors' -Default @())
        if ($errors.Count -gt 0) { $complete = $false }
        $status = if ($complete) { 'Completed' } else { 'Partial' }
        Write-IRSuccess "$Name collection $($status.ToLowerInvariant())."
        return [pscustomobject][ordered]@{
            Component = $Name
            Status = $status
            StartedUtc = $started
            EndedUtc = [datetime]::UtcNow
            DurationSeconds = [math]::Round(([datetime]::UtcNow - $started).TotalSeconds, 2)
            Error = if ($errors.Count -gt 0) { @($errors | ForEach-Object { [string](Get-IRProperty -InputObject $_ -Name 'Error' -Default $_) }) -join ' | ' } else { $null }
        }
    }
    catch {
        Write-IRFailure "$Name collection failed: $($_.Exception.Message)"
        $null = Add-IRActionLog -Action "Collect $Name" -Status Error -Target $script:IR.TargetUpn -Details $_.Exception.Message
        return [pscustomobject][ordered]@{
            Component = $Name
            Status = 'Failed'
            StartedUtc = $started
            EndedUtc = [datetime]::UtcNow
            DurationSeconds = [math]::Round(([datetime]::UtcNow - $started).TotalSeconds, 2)
            Error = $_.Exception.Message
        }
    }
}

function New-IRCaseReport {
    [CmdletBinding(SupportsShouldProcess)]
    param([object[]]$CollectionStatus)

    if (-not $script:IR.CasePath) { $null = Initialize-IRCase }
    $path = Join-Path -Path $script:IR.CasePath -ChildPath 'case_report.html'
    $null = Add-IRActionLog -Action 'Generate HTML case report' -Status Read -Target $path
    $statusRows = @()
    if ($null -ne $CollectionStatus) { $statusRows = @($CollectionStatus) }
    $actions = @($script:IR.ActionLog)
    $actionLogChain = Test-IRActionLogChain
    $connections = Get-IRConnectionStatus
    $builder = [System.Text.StringBuilder]::new()
    $null = $builder.AppendLine('<!doctype html><html lang="en"><head><meta charset="utf-8">')
    $null = $builder.AppendLine('<meta name="viewport" content="width=device-width,initial-scale=1">')
    $null = $builder.AppendLine('<title>M365 Incident Response Case Report</title>')
    $null = $builder.AppendLine('<style>body{font-family:Segoe UI,Arial,sans-serif;margin:2rem;color:#17202a;line-height:1.45}h1,h2,h3{color:#17365d}h2{margin-top:2rem;border-bottom:2px solid #d8e1ea;padding-bottom:.25rem}h3{margin-top:1.4rem}.table-wrap{overflow-x:auto}table{border-collapse:collapse;width:100%;margin:1rem 0;font-size:.94rem}th,td{border:1px solid #ccd4dc;padding:.45rem;text-align:left;vertical-align:top;overflow-wrap:anywhere}th{background:#eaf0f6}.Completed,.Pass{color:#166534}.Failed,.Error{color:#b91c1c}.Partial,.Warning{color:#a16207}code{background:#f1f5f9;padding:.1rem .25rem;overflow-wrap:anywhere}small{color:#52606d}@media print{body{margin:.45in;font-size:10pt}h2{break-after:avoid}table{break-inside:auto}tr{break-inside:avoid}thead{display:table-header-group}}</style></head><body>')
    $null = $builder.AppendLine('<h1>Microsoft 365 Incident Response Case Report</h1>')
    $null = $builder.AppendLine(('<p><strong>Case:</strong> {0}<br><strong>Target:</strong> {1}<br><strong>Generated UTC:</strong> {2}<br><strong>Tool:</strong> M365-IR-Console {3}<br><strong>Mode:</strong> {4}</p>' -f
        (ConvertTo-IRHtml $script:IR.CaseId), (ConvertTo-IRHtml $script:IR.TargetUpn), [datetime]::UtcNow.ToString('o'), (ConvertTo-IRHtml $script:IR.Version), (ConvertTo-IRHtml $script:IR.Mode)))
    $null = $builder.AppendLine(('<p><strong>Action log integrity:</strong> {0} ({1} entries)<br><strong>Final action hash:</strong> <code>{2}</code></p>' -f
        $(if ($actionLogChain.Valid) { 'Valid' } else { 'Invalid' }),
        $actionLogChain.Entries,
        (ConvertTo-IRHtml $actionLogChain.FinalHash)))
    $null = $builder.AppendLine('<p><small>Heuristic findings are leads for analyst validation, not determinations of compromise. Service retention, licensing, permissions, and query ceilings can limit completeness.</small></p>')

    $null = $builder.AppendLine('<h2>Collection status</h2><table><thead><tr><th>Component</th><th>Status</th><th>Duration (s)</th><th>Error / limitation</th></tr></thead><tbody>')
    foreach ($row in $statusRows) {
        $status = [string](Get-IRProperty -InputObject $row -Name 'Status')
        $null = $builder.AppendLine(('<tr><td>{0}</td><td class="{1}">{2}</td><td>{3}</td><td>{4}</td></tr>' -f
            (ConvertTo-IRHtml (Get-IRProperty -InputObject $row -Name 'Component')),
            (ConvertTo-IRHtml $status),
            (ConvertTo-IRHtml $status),
            (ConvertTo-IRHtml (Get-IRProperty -InputObject $row -Name 'DurationSeconds')),
            (ConvertTo-IRHtml (Get-IRProperty -InputObject $row -Name 'Error'))))
    }
    if ($statusRows.Count -eq 0) { $null = $builder.AppendLine('<tr><td colspan="4">No orchestrated collection status was supplied.</td></tr>') }
    $null = $builder.AppendLine('</tbody></table>')

    # Build an investigator-oriented evidence summary from the in-memory
    # collection results. The raw exports remain the authoritative pivot source;
    # this section makes the report useful without requiring the analyst to open
    # every artifact merely to understand scope and priority.
    $mailboxResult = Get-IRProperty -InputObject $script:IR.Results -Name 'Collection:Mailbox configuration'
    $messageResult = Get-IRProperty -InputObject $script:IR.Results -Name 'Collection:Message trace'
    $auditResult = Get-IRProperty -InputObject $script:IR.Results -Name 'Collection:Unified audit log'
    $identityResult = Get-IRProperty -InputObject $script:IR.Results -Name 'Collection:Identity and sign-ins'
    $threatResult = Get-IRProperty -InputObject $script:IR.Results -Name 'Collection:Threat and Defender'
    $deviceResult = Get-IRProperty -InputObject $script:IR.Results -Name 'Collection:Managed devices'
    $policyResult = Get-IRProperty -InputObject $script:IR.Results -Name 'Collection:Security policies'

    $mailboxSnapshot = Get-IRProperty -InputObject $mailboxResult -Name 'Snapshot'
    $mailboxSummary = Get-IRProperty -InputObject $mailboxSnapshot -Name 'Summary'
    $inboxRules = @(Get-IRProperty -InputObject $mailboxSnapshot -Name 'InboxRules' -Default @())
    $mailboxApplications = @(Get-IRProperty -InputObject $mailboxResult -Name 'Applications' -Default @())
    $permissionResult = Get-IRProperty -InputObject $mailboxResult -Name 'Permissions'
    $folderErrors = @(Get-IRProperty -InputObject $permissionResult -Name 'FolderErrors' -Default @())
    $skippedFolders = @(Get-IRProperty -InputObject $permissionResult -Name 'SkippedFolders' -Default @())
    $messageRows = @(Get-IRProperty -InputObject $messageResult -Name 'Messages' -Default @())
    $messageAnalysis = Get-IRProperty -InputObject $messageResult -Name 'Analysis'
    $auditEvents = @(Get-IRProperty -InputObject $auditResult -Name 'Events' -Default @())
    $auditFindings = @(Get-IRProperty -InputObject $auditResult -Name 'Findings' -Default @())
    $defenderRows = @(Get-IRProperty -InputObject $threatResult -Name 'DefenderDetections' -Default @())
    $threatHeuristics = @(Get-IRProperty -InputObject $threatResult -Name 'Heuristics' -Default @())
    $identitySets = Get-IRProperty -InputObject $identityResult -Name 'DataSets'
    $oauthGrants = @(Get-IRProperty -InputObject $identitySets -Name 'OAuthGrants' -Default @())
    $appRoleAssignments = @(Get-IRProperty -InputObject $identitySets -Name 'AppRoleAssignments' -Default @())
    $signIns = @(Get-IRProperty -InputObject $identitySets -Name 'SignIns' -Default @())
    $authenticationMethods = @(Get-IRProperty -InputObject $identitySets -Name 'AuthenticationMethods' -Default @())
    $riskyUsers = @(Get-IRProperty -InputObject $identitySets -Name 'RiskyUser' -Default @())
    $identityErrors = @(Get-IRProperty -InputObject $identityResult -Name 'Errors' -Default @())
    $exchangeDevices = @(Get-IRProperty -InputObject $deviceResult -Name 'ExchangeDevices' -Default @())
    $intuneDevices = @(Get-IRProperty -InputObject $deviceResult -Name 'IntuneDevices' -Default @())
    $deviceErrors = @(Get-IRProperty -InputObject $deviceResult -Name 'Errors' -Default @())
    $policySnapshot = Get-IRProperty -InputObject $policyResult -Name 'Snapshot'
    $policyStatus = @(Get-IRProperty -InputObject $policySnapshot -Name 'Status' -Default @())

    $null = $builder.AppendLine('<h2>Investigator summary</h2>')
    $null = $builder.AppendLine('<table><thead><tr><th>Evidence area</th><th>Observed result</th><th>Investigator significance</th></tr></thead><tbody>')
    $summaryRows = @(
        @('Message trace', "$($messageRows.Count) rows; $([int](Get-IRProperty -InputObject $messageAnalysis -Name 'SentRows' -Default 0)) sent; $([int](Get-IRProperty -InputObject $messageAnalysis -Name 'ReceivedRows' -Default 0)) received; $(@(Get-IRProperty -InputObject $messageAnalysis -Name 'Anomalies' -Default @()).Count) heuristic leads", 'Pivot by message and trace identifiers; validate external, large, repeated-subject, and after-hours leads.'),
        @('Unified audit', "$($auditEvents.Count) events; $($auditFindings.Count) triage indicators", 'Correlate high-risk, partial, deletion, and after-hours operations with known activity.'),
        @('Defender mail detail', "$($defenderRows.Count) rows; $($threatHeuristics.Count) additional message leads", 'Review verdict, delivery location, remediation, and user interaction.'),
        @('Mailbox configuration', "$($inboxRules.Count) rules; $($mailboxApplications.Count) applications; $($folderErrors.Count) folder errors; $($skippedFolders.Count) service-internal exclusions", 'Validate forwarding, delegation, hidden rules, applications, and permissions.'),
        @('Identity and applications', "$($oauthGrants.Count) OAuth grants; $($appRoleAssignments.Count) app-role assignments; $($signIns.Count) sign-ins; $($authenticationMethods.Count) authentication methods; $($riskyUsers.Count) risk-status records; $($identityErrors.Count) coverage errors", 'Validate consent provenance, least privilege, authentication outcomes, registered methods, risk state, and missing evidence.'),
        @('Devices', "$($exchangeDevices.Count) Exchange devices; $($intuneDevices.Count) Intune devices; $($deviceErrors.Count) coverage errors", 'Confirm ownership, access state, management, and stale partnerships.'),
        @('Security policies', "$(@($policyStatus | Where-Object Status -eq 'Collected').Count) collected; $(@($policyStatus | Where-Object Status -ne 'Collected').Count) unavailable or failed", 'Assess effective precedence and record license/role/service limitations.')
    )
    foreach ($row in $summaryRows) {
        $null = $builder.AppendLine(('<tr><td>{0}</td><td>{1}</td><td>{2}</td></tr>' -f (ConvertTo-IRHtml $row[0]), (ConvertTo-IRHtml $row[1]), (ConvertTo-IRHtml $row[2])))
    }
    $null = $builder.AppendLine('</tbody></table>')

    if ($mailboxSummary) {
        $delegates = ConvertTo-IRDisplayString -Value (Get-IRProperty -InputObject $mailboxSummary -Name 'GrantSendOnBehalfTo')
        $null = $builder.AppendLine('<h2>Mailbox controls and persistence review</h2>')
        $null = $builder.AppendLine('<table><thead><tr><th>Control</th><th>Observed value</th><th>Required validation</th></tr></thead><tbody>')
        foreach ($row in @(
            @('Mailbox forwarding', $(if ([bool](Get-IRProperty -InputObject $mailboxSummary -Name 'HasForwarding' -Default $false)) { "Enabled: $(Get-IRProperty -InputObject $mailboxSummary -Name 'ForwardingSmtpAddress')" } else { 'Not configured' }), 'Confirm destination, authorization, and change history.'),
            @('Deliver and forward', [string](Get-IRProperty -InputObject $mailboxSummary -Name 'DeliverToMailboxAndForward'), 'Confirm expected routing behavior.'),
            @('Send-on-Behalf delegates', $delegates, 'Confirm every delegate and business owner.'),
            @('Mailbox audit enabled', [string](Get-IRProperty -InputObject $mailboxSummary -Name 'AuditEnabled'), 'Confirm audit set and retention.'),
            @('Litigation hold', [string](Get-IRProperty -InputObject $mailboxSummary -Name 'LitigationHoldEnabled'), 'Record preservation impact.'),
            @('Single item recovery', [string](Get-IRProperty -InputObject $mailboxSummary -Name 'SingleItemRecoveryEnabled'), 'Record recovery impact.'),
            @('Mailbox population', "$(Get-IRProperty -InputObject $mailboxSummary -Name 'ItemCount') items; $(Get-IRProperty -InputObject $mailboxSummary -Name 'TotalItemSize')", 'Use as deletion and collection-scope context.')
        )) {
            $null = $builder.AppendLine(('<tr><td>{0}</td><td>{1}</td><td>{2}</td></tr>' -f (ConvertTo-IRHtml $row[0]), (ConvertTo-IRHtml $row[1]), (ConvertTo-IRHtml $row[2])))
        }
        $null = $builder.AppendLine('</tbody></table>')

        $null = $builder.AppendLine('<h3>Inbox rules</h3><table><thead><tr><th>Name</th><th>Enabled</th><th>Risk</th><th>Reasons</th><th>Forward / redirect</th><th>Move / delete / mark read</th></tr></thead><tbody>')
        foreach ($rule in $inboxRules) {
            $forwarding = @((Get-IRProperty -InputObject $rule -Name 'ForwardTo'), (Get-IRProperty -InputObject $rule -Name 'RedirectTo'), (Get-IRProperty -InputObject $rule -Name 'ForwardAsAttachmentTo')) | Where-Object { $_ }
            $otherActions = @()
            if (Get-IRProperty -InputObject $rule -Name 'MoveToFolder') { $otherActions += "Move: $(Get-IRProperty -InputObject $rule -Name 'MoveToFolder')" }
            if ([bool](Get-IRProperty -InputObject $rule -Name 'DeleteMessage' -Default $false)) { $otherActions += 'Delete' }
            if ([bool](Get-IRProperty -InputObject $rule -Name 'MarkAsRead' -Default $false)) { $otherActions += 'Mark as read' }
            $null = $builder.AppendLine(('<tr><td>{0}</td><td>{1}</td><td>{2}</td><td>{3}</td><td>{4}</td><td>{5}</td></tr>' -f
                (ConvertTo-IRHtml (Get-IRProperty -InputObject $rule -Name 'Name')),
                (ConvertTo-IRHtml (Get-IRProperty -InputObject $rule -Name 'Enabled')),
                (ConvertTo-IRHtml (Get-IRProperty -InputObject $rule -Name 'Risk')),
                (ConvertTo-IRHtml (Get-IRProperty -InputObject $rule -Name 'Reasons')),
                (ConvertTo-IRHtml ($forwarding -join ' | ')),
                (ConvertTo-IRHtml ($otherActions -join ' | '))))
        }
        if ($inboxRules.Count -eq 0) { $null = $builder.AppendLine('<tr><td colspan="6">No inbox rules returned.</td></tr>') }
        $null = $builder.AppendLine('</tbody></table>')
    }

    if ($messageRows.Count -gt 0) {
        $null = $builder.AppendLine('<h2>Message-flow analysis</h2>')
        $null = $builder.AppendLine('<h3>Disposition</h3><table><thead><tr><th>Status</th><th>Rows</th><th>Share</th></tr></thead><tbody>')
        foreach ($group in @($messageRows | Group-Object Status | Sort-Object Count -Descending)) {
            $share = if ($messageRows.Count -gt 0) { '{0:N1}%' -f (($group.Count / $messageRows.Count) * 100) } else { '0.0%' }
            $null = $builder.AppendLine(('<tr><td>{0}</td><td>{1}</td><td>{2}</td></tr>' -f (ConvertTo-IRHtml $group.Name), $group.Count, $share))
        }
        $null = $builder.AppendLine('</tbody></table>')

        $anomalies = @(Get-IRProperty -InputObject $messageAnalysis -Name 'Anomalies' -Default @())
        $null = $builder.AppendLine('<h3>Message heuristic work queue</h3><table><thead><tr><th>Type</th><th>Severity</th><th>Rows</th><th>Detail</th></tr></thead><tbody>')
        foreach ($item in $anomalies) {
            $null = $builder.AppendLine(('<tr><td>{0}</td><td>{1}</td><td>{2}</td><td>{3}</td></tr>' -f
                (ConvertTo-IRHtml (Get-IRProperty -InputObject $item -Name 'Type')),
                (ConvertTo-IRHtml (Get-IRProperty -InputObject $item -Name 'Severity')),
                (ConvertTo-IRHtml (Get-IRProperty -InputObject $item -Name 'Count')),
                (ConvertTo-IRHtml (Get-IRProperty -InputObject $item -Name 'Detail'))))
        }
        if ($anomalies.Count -eq 0) { $null = $builder.AppendLine('<tr><td colspan="4">No message heuristics returned.</td></tr>') }
        $null = $builder.AppendLine('</tbody></table>')
    }

    if ($auditEvents.Count -gt 0) {
        $null = $builder.AppendLine('<h2>Unified-audit analysis</h2>')
        $null = $builder.AppendLine('<h3>Highest-volume operations</h3><table><thead><tr><th>Operation</th><th>Rows</th><th>Share</th></tr></thead><tbody>')
        foreach ($group in @($auditEvents | Group-Object Operation | Sort-Object Count -Descending | Select-Object -First 25)) {
            $share = '{0:N1}%' -f (($group.Count / $auditEvents.Count) * 100)
            $null = $builder.AppendLine(('<tr><td>{0}</td><td>{1}</td><td>{2}</td></tr>' -f (ConvertTo-IRHtml $group.Name), $group.Count, $share))
        }
        $null = $builder.AppendLine('</tbody></table>')

        $null = $builder.AppendLine('<h3>Triage findings</h3><table><thead><tr><th>Severity</th><th>Operation</th><th>UTC</th><th>Source IP</th><th>Object</th><th>Reasons</th></tr></thead><tbody>')
        foreach ($finding in @($auditFindings | Sort-Object @{ Expression = { switch ($_.Severity) { 'High' { 1 }; 'Medium' { 2 }; default { 3 } } } }, CreationUtc | Select-Object -First 250)) {
            $null = $builder.AppendLine(('<tr><td>{0}</td><td>{1}</td><td>{2}</td><td>{3}</td><td>{4}</td><td>{5}</td></tr>' -f
                (ConvertTo-IRHtml $finding.Severity), (ConvertTo-IRHtml $finding.Operation), (ConvertTo-IRHtml $finding.CreationUtc),
                (ConvertTo-IRHtml $finding.ClientIP), (ConvertTo-IRHtml $finding.ObjectId), (ConvertTo-IRHtml $finding.Reasons)))
        }
        if ($auditFindings.Count -gt 250) { $null = $builder.AppendLine(('<tr><td colspan="6">Showing the first 250 of {0} findings. Use the exported finding table for the complete set.</td></tr>' -f $auditFindings.Count)) }
        $null = $builder.AppendLine('</tbody></table>')
    }

    if ($defenderRows.Count -gt 0) {
        $null = $builder.AppendLine('<h2>Defender mail-detail analysis</h2>')
        $null = $builder.AppendLine('<table><thead><tr><th>Verdict</th><th>Action / location</th><th>Rows</th></tr></thead><tbody>')
        foreach ($group in @($defenderRows | Group-Object VerdictSource, Action | Sort-Object Count -Descending)) {
            $sample = $group.Group | Select-Object -First 1
            $null = $builder.AppendLine(('<tr><td>{0}</td><td>{1}</td><td>{2}</td></tr>' -f (ConvertTo-IRHtml $sample.VerdictSource), (ConvertTo-IRHtml $sample.Action), $group.Count))
        }
        $null = $builder.AppendLine('</tbody></table>')
    }

    if ($oauthGrants.Count -gt 0 -or $appRoleAssignments.Count -gt 0 -or $signIns.Count -gt 0 -or $authenticationMethods.Count -gt 0 -or $riskyUsers.Count -gt 0 -or $identityErrors.Count -gt 0) {
        $null = $builder.AppendLine('<h2>Identity, consent, and authentication review</h2>')
        $null = $builder.AppendLine('<h3>Delegated OAuth grants</h3><table><thead><tr><th>Application</th><th>Publisher</th><th>Consent</th><th>Scopes</th><th>High-review scopes</th><th>Risk</th></tr></thead><tbody>')
        foreach ($grant in $oauthGrants) {
            $null = $builder.AppendLine(('<tr><td>{0}</td><td>{1}</td><td>{2}</td><td>{3}</td><td>{4}</td><td>{5}</td></tr>' -f
                (ConvertTo-IRHtml $grant.ClientApplication), (ConvertTo-IRHtml $grant.Publisher), (ConvertTo-IRHtml $grant.ConsentType),
                (ConvertTo-IRHtml $grant.Scope), (ConvertTo-IRHtml $grant.HighRiskScopes), (ConvertTo-IRHtml $grant.Risk)))
        }
        if ($oauthGrants.Count -eq 0) { $null = $builder.AppendLine('<tr><td colspan="6">No delegated OAuth grants returned.</td></tr>') }
        $null = $builder.AppendLine('</tbody></table>')

        $null = $builder.AppendLine('<h3>Authentication methods</h3><table><thead><tr><th>Type</th><th>Display name</th><th>Created</th><th>Phone type</th><th>Email</th></tr></thead><tbody>')
        foreach ($method in $authenticationMethods) {
            $null = $builder.AppendLine(('<tr><td>{0}</td><td>{1}</td><td>{2}</td><td>{3}</td><td>{4}</td></tr>' -f
                (ConvertTo-IRHtml $method.MethodType), (ConvertTo-IRHtml $method.DisplayName), (ConvertTo-IRHtml $method.CreatedDateTime),
                (ConvertTo-IRHtml $method.PhoneType), (ConvertTo-IRHtml $method.EmailAddress)))
        }
        if ($authenticationMethods.Count -eq 0) { $null = $builder.AppendLine('<tr><td colspan="5">No authentication methods returned.</td></tr>') }
        $null = $builder.AppendLine('</tbody></table>')

        if ($signIns.Count -gt 0) {
            $null = $builder.AppendLine('<h3>Sign-in evidence</h3><table><thead><tr><th>UTC</th><th>Application / resource</th><th>Client</th><th>Source and location</th><th>Device</th><th>Conditional Access</th><th>Risk</th><th>Result</th></tr></thead><tbody>')
            foreach ($signIn in @($signIns | Sort-Object CreatedDateTime -Descending | Select-Object -First 250)) {
                $resultText = if ([int](Get-IRProperty -InputObject $signIn -Name 'ErrorCode' -Default 0) -eq 0) {
                    'Success'
                }
                else {
                    "$(Get-IRProperty -InputObject $signIn -Name 'ErrorCode'): $(Get-IRProperty -InputObject $signIn -Name 'FailureReason')"
                }
                $null = $builder.AppendLine(('<tr><td>{0}</td><td>{1}</td><td>{2}</td><td>{3}</td><td>{4}</td><td>{5}</td><td>{6}</td><td>{7}</td></tr>' -f
                    (ConvertTo-IRHtml (Get-IRProperty -InputObject $signIn -Name 'CreatedDateTime')),
                    (ConvertTo-IRHtml "$(Get-IRProperty -InputObject $signIn -Name 'AppDisplayName') / $(Get-IRProperty -InputObject $signIn -Name 'ResourceDisplayName')"),
                    (ConvertTo-IRHtml (Get-IRProperty -InputObject $signIn -Name 'ClientAppUsed')),
                    (ConvertTo-IRHtml "$(Get-IRProperty -InputObject $signIn -Name 'IPAddress') [$(Get-IRProperty -InputObject $signIn -Name 'IPAddressCategory')] / $(Get-IRProperty -InputObject $signIn -Name 'City'), $(Get-IRProperty -InputObject $signIn -Name 'State'), $(Get-IRProperty -InputObject $signIn -Name 'CountryOrRegion')"),
                    (ConvertTo-IRHtml "$(Get-IRProperty -InputObject $signIn -Name 'OperatingSystem') / $(Get-IRProperty -InputObject $signIn -Name 'Browser'); managed=$(Get-IRProperty -InputObject $signIn -Name 'IsManaged'); compliant=$(Get-IRProperty -InputObject $signIn -Name 'IsCompliant')"),
                    (ConvertTo-IRHtml (Get-IRProperty -InputObject $signIn -Name 'ConditionalAccessStatus')),
                    (ConvertTo-IRHtml "$(Get-IRProperty -InputObject $signIn -Name 'RiskLevelAggregated') / $(Get-IRProperty -InputObject $signIn -Name 'RiskState')"),
                    (ConvertTo-IRHtml $resultText)))
            }
            if ($signIns.Count -gt 250) { $null = $builder.AppendLine(('<tr><td colspan="8">Showing the newest 250 of {0} sign-ins. Use the exported sign-in timeline for the complete set.</td></tr>' -f $signIns.Count)) }
            $null = $builder.AppendLine('</tbody></table>')
        }

        if ($riskyUsers.Count -gt 0) {
            $null = $builder.AppendLine('<h3>Identity Protection risk status</h3><table><thead><tr><th>Listing status</th><th>Risk level</th><th>Risk state</th><th>Detail</th><th>Last updated</th><th>Interpretation</th></tr></thead><tbody>')
            foreach ($riskRow in $riskyUsers) {
                $null = $builder.AppendLine(('<tr><td>{0}</td><td>{1}</td><td>{2}</td><td>{3}</td><td>{4}</td><td>{5}</td></tr>' -f
                    (ConvertTo-IRHtml (Get-IRProperty -InputObject $riskRow -Name 'ListingStatus')),
                    (ConvertTo-IRHtml (Get-IRProperty -InputObject $riskRow -Name 'RiskLevel')),
                    (ConvertTo-IRHtml (Get-IRProperty -InputObject $riskRow -Name 'RiskState')),
                    (ConvertTo-IRHtml (Get-IRProperty -InputObject $riskRow -Name 'RiskDetail')),
                    (ConvertTo-IRHtml (Get-IRProperty -InputObject $riskRow -Name 'RiskLastUpdatedDateTime')),
                    (ConvertTo-IRHtml (Get-IRProperty -InputObject $riskRow -Name 'Note'))))
            }
            $null = $builder.AppendLine('</tbody></table>')
        }

        if ($identityErrors.Count -gt 0) {
            $null = $builder.AppendLine('<h3>Identity coverage limitations</h3><table><thead><tr><th>Component</th><th>Limitation</th></tr></thead><tbody>')
            foreach ($errorRow in $identityErrors) {
                $null = $builder.AppendLine(('<tr><td>{0}</td><td>{1}</td></tr>' -f (ConvertTo-IRHtml $errorRow.Component), (ConvertTo-IRHtml $errorRow.Error)))
            }
            $null = $builder.AppendLine('</tbody></table>')
        }
    }

    if ($exchangeDevices.Count -gt 0 -or $intuneDevices.Count -gt 0 -or $deviceErrors.Count -gt 0) {
        $null = $builder.AppendLine('<h2>Device review</h2><table><thead><tr><th>Source</th><th>Identity / name</th><th>OS / model</th><th>Access / compliance</th><th>Last activity</th></tr></thead><tbody>')
        foreach ($device in $exchangeDevices) {
            $null = $builder.AppendLine(('<tr><td>Exchange</td><td>{0}</td><td>{1}</td><td>{2}</td><td>{3}</td></tr>' -f
                (ConvertTo-IRHtml $device.Identity), (ConvertTo-IRHtml "$($device.DeviceOS) / $($device.DeviceModel)"),
                (ConvertTo-IRHtml "$($device.DeviceAccessState) / $($device.DeviceAccessStateReason)"), (ConvertTo-IRHtml $device.LastSuccessSync)))
        }
        foreach ($device in $intuneDevices) {
            $null = $builder.AppendLine(('<tr><td>Intune</td><td>{0}</td><td>{1}</td><td>{2}</td><td>{3}</td></tr>' -f
                (ConvertTo-IRHtml $device.DeviceName), (ConvertTo-IRHtml "$($device.OperatingSystem) / $($device.Model)"),
                (ConvertTo-IRHtml "$($device.ComplianceState) / $($device.ManagedDeviceOwnerType)"), (ConvertTo-IRHtml $device.LastSyncDateTime)))
        }
        foreach ($errorRow in $deviceErrors) {
            $null = $builder.AppendLine(('<tr><td>{0}</td><td colspan="4">{1}</td></tr>' -f (ConvertTo-IRHtml $errorRow.Component), (ConvertTo-IRHtml $errorRow.Error)))
        }
        $null = $builder.AppendLine('</tbody></table>')
    }

    if ($policyStatus.Count -gt 0) {
        $null = $builder.AppendLine('<h2>Security-policy coverage</h2><table><thead><tr><th>Policy family</th><th>Status</th><th>Records</th><th>Limitation</th></tr></thead><tbody>')
        foreach ($row in $policyStatus) {
            $null = $builder.AppendLine(('<tr><td>{0}</td><td>{1}</td><td>{2}</td><td>{3}</td></tr>' -f
                (ConvertTo-IRHtml $row.Component), (ConvertTo-IRHtml $row.Status), (ConvertTo-IRHtml $row.Records), (ConvertTo-IRHtml $row.Error)))
        }
        $null = $builder.AppendLine('</tbody></table>')
    }

    $null = $builder.AppendLine('<h2>Investigator decision framework</h2>')
    $null = $builder.AppendLine('<ul><li>Validate mailbox forwarding, delegation, hidden rules, applications, and authentication methods against approved state.</li><li>Correlate Defender verdicts with final delivery location, remediation, clicks, and endpoint evidence.</li><li>Prioritize large external messages, after-hours sending, high-risk audit operations, and failed/partial source records.</li><li>Identify every OAuth client, publisher, consent actor, consent time, last use, and business owner before revocation.</li><li>Treat missing licensed workloads as coverage limitations, never as clean evidence.</li><li>Preserve the source exports and regenerate the evidence manifest after adding trusted external evidence.</li></ul>')

    $null = $builder.AppendLine('<h2>Service connections</h2><table><thead><tr><th>Service</th><th>Connected</th><th>Identity</th></tr></thead><tbody>')
    foreach ($row in @($connections)) {
        $null = $builder.AppendLine(('<tr><td>{0}</td><td>{1}</td><td>{2}</td></tr>' -f (ConvertTo-IRHtml $row.Service), (ConvertTo-IRHtml $row.Connected), (ConvertTo-IRHtml (Get-IRProperty -InputObject $row -Name 'Identity'))))
    }
    $null = $builder.AppendLine('</tbody></table>')

    $null = $builder.AppendLine('<h2>Recorded actions</h2><table><thead><tr><th>Sequence</th><th>UTC</th><th>Status</th><th>Action</th><th>Target</th><th>Details</th><th>Entry hash</th></tr></thead><tbody>')
    foreach ($entry in $actions) {
        $details = Get-IRProperty -InputObject $entry -Name 'Details'
        if ($details -and $details -isnot [string]) { $details = $details | ConvertTo-Json -Depth 8 -Compress }
        $null = $builder.AppendLine(('<tr><td>{0}</td><td>{1}</td><td>{2}</td><td>{3}</td><td>{4}</td><td>{5}</td><td><code>{6}</code></td></tr>' -f
            (ConvertTo-IRHtml $entry.Sequence), (ConvertTo-IRHtml $entry.TimestampUtc), (ConvertTo-IRHtml $entry.Status), (ConvertTo-IRHtml $entry.Action), (ConvertTo-IRHtml $entry.Target), (ConvertTo-IRHtml $details), (ConvertTo-IRHtml $entry.EntryHash)))
    }
    $null = $builder.AppendLine('</tbody></table>')
    $null = $builder.AppendLine('<h2>Evidence location</h2>')
    $null = $builder.AppendLine(('<p><code>{0}</code></p>' -f (ConvertTo-IRHtml $script:IR.CasePath)))
    $null = $builder.AppendLine('</body></html>')
    if ($PSCmdlet.ShouldProcess($path, 'Write HTML case report')) {
        $builder.ToString() | Set-Content -LiteralPath $path -Encoding utf8
    }
    Write-IRSuccess "Generated case report: $path"
    return $path
}

function New-IRAxiomImportPackage {
    [CmdletBinding(SupportsShouldProcess)]
    param()

    if (-not $script:IR.CasePath) { $null = Initialize-IRCase }
    $directory = Get-IRCasePath -ChildPath 'AxiomImport' -CreateDirectory
    $created = [System.Collections.Generic.List[string]]::new()
    $mappings = @(
        @{ Key = 'AuditEvents'; File = 'UnifiedAudit_Timeline.csv'; Fields = @('CreationUtc', 'Operation', 'Category', 'UserId', 'ClientIP', 'IPAddressCategory', 'ObjectId', 'Workload', 'ResultStatus', 'RawAuditData') },
        @{ Key = 'MessageTrace'; File = 'MessageTrace_Timeline.csv'; Fields = @('ReceivedUtc', 'Direction', 'SenderAddress', 'RecipientAddress', 'Subject', 'Status', 'Size', 'MessageId', 'MessageTraceId') },
        @{ Key = 'SignIns'; File = 'EntraSignIns_Timeline.csv'; Fields = @('CreatedDateTime', 'UserPrincipalName', 'AppDisplayName', 'IPAddress', 'CountryOrRegion', 'City', 'OperatingSystem', 'Browser', 'ConditionalAccessStatus', 'RiskLevelAggregated', 'ErrorCode') }
    )
    foreach ($mapping in $mappings) {
        $records = @($script:IR.Results[$mapping.Key])
        if ($records.Count -eq 0) { continue }
        $path = Join-Path -Path $directory -ChildPath $mapping.File
        if ($PSCmdlet.ShouldProcess($path, 'Write normalized CSV for analyst-tool import')) {
            $records | Select-Object -Property $mapping.Fields | Export-Csv -LiteralPath $path -NoTypeInformation -Encoding utf8
        }
        $created.Add($path)
    }
    $readmePath = Join-Path -Path $directory -ChildPath 'README.txt'
    $readme = @(
        'M365-IR-Console portable analyst import package',
        "Case: $($script:IR.CaseId)",
        "Target: $($script:IR.TargetUpn)",
        "Generated UTC: $([datetime]::UtcNow.ToString('o'))",
        '',
        'These are normalized UTF-8 CSV files, not a proprietary Magnet AXIOM case format.',
        'Import the applicable CSVs through your forensic tool workflow and preserve original raw JSON/CSV evidence from the parent case.',
        'Field availability depends on licensing, retention, roles, and successful collection.'
    )
    if ($PSCmdlet.ShouldProcess($readmePath, 'Write package README')) { $readme | Set-Content -LiteralPath $readmePath -Encoding utf8 }
    $created.Add($readmePath)
    $null = Add-IRActionLog -Action 'Create portable analyst import package' -Status Read -Target $directory -Details @{ Files = $created.Count }
    return $created.ToArray()
}

function New-IREvidenceManifest {
    [CmdletBinding(SupportsShouldProcess)]
    param()

    if (-not $script:IR.CasePath) { $null = Initialize-IRCase }
    $jsonPath = Join-Path -Path $script:IR.CasePath -ChildPath 'evidence_manifest.sha256.json'
    $csvPath = Join-Path -Path $script:IR.CasePath -ChildPath 'evidence_manifest.sha256.csv'
    $null = Add-IRActionLog -Action 'Seal current case files with SHA-256 manifest' -Status Read -Target $jsonPath
    $actionLogChain = Test-IRActionLogChain
    if (-not $actionLogChain.Valid) {
        throw "The action log hash chain is invalid and the case cannot be sealed: $($actionLogChain.Error)"
    }
    $excluded = @($jsonPath, $csvPath)
    $files = @(Get-ChildItem -LiteralPath $script:IR.CasePath -File -Recurse -Force | Where-Object { $_.FullName -notin $excluded } | Sort-Object FullName)
    $rows = foreach ($file in $files) {
        [pscustomobject][ordered]@{
            RelativePath = [System.IO.Path]::GetRelativePath($script:IR.CasePath, $file.FullName).Replace([System.IO.Path]::DirectorySeparatorChar, '/')
            Length = $file.Length
            LastWriteTimeUtc = $file.LastWriteTimeUtc.ToString('o')
            SHA256 = (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant()
        }
    }
    $manifest = [ordered]@{
        Schema = 'm365-ir-evidence-manifest/v1'
        CaseId = $script:IR.CaseId
        ToolVersion = $script:IR.Version.ToString()
        GeneratedUtc = [datetime]::UtcNow.ToString('o')
        HashAlgorithm = 'SHA-256'
        ActionLogChainValid = $actionLogChain.Valid
        ActionLogEntries = $actionLogChain.Entries
        ActionLogFinalHash = $actionLogChain.FinalHash
        ManifestFilesExcluded = @([System.IO.Path]::GetFileName($jsonPath), [System.IO.Path]::GetFileName($csvPath))
        FileCount = @($rows).Count
        Files = @($rows)
    }
    if ($PSCmdlet.ShouldProcess($jsonPath, 'Write SHA-256 evidence manifests')) {
        $manifest | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $jsonPath -Encoding utf8
        @($rows) | Export-Csv -LiteralPath $csvPath -NoTypeInformation -Encoding utf8
    }
    Write-IRSuccess "Sealed $(@($rows).Count) file(s) in the SHA-256 manifest."
    return [pscustomobject]@{ JsonPath = $jsonPath; CsvPath = $csvPath; FileCount = @($rows).Count; Files = @($rows) }
}

function Test-IREvidenceManifest {
    [CmdletBinding()]
    param([string]$ManifestPath)

    if (-not $script:IR.CasePath) { throw 'No case is initialized.' }
    if ([string]::IsNullOrWhiteSpace($ManifestPath)) { $ManifestPath = Join-Path -Path $script:IR.CasePath -ChildPath 'evidence_manifest.sha256.json' }
    if (-not (Test-Path -LiteralPath $ManifestPath -PathType Leaf)) { throw "Manifest not found: $ManifestPath" }
    $manifest = Get-Content -LiteralPath $ManifestPath -Raw -Encoding utf8 | ConvertFrom-Json -Depth 20 -DateKind String
    if ([string]$manifest.Schema -cne 'm365-ir-evidence-manifest/v1') {
        throw "Unsupported evidence manifest schema '$($manifest.Schema)'."
    }
    if ([string]$manifest.HashAlgorithm -cne 'SHA-256') {
        throw "Unsupported evidence manifest hash algorithm '$($manifest.HashAlgorithm)'."
    }
    if ([int]$manifest.FileCount -ne @($manifest.Files).Count) {
        throw 'The evidence manifest file count does not match its entry list.'
    }
    $pathComparer = if ($IsWindows) { [System.StringComparer]::OrdinalIgnoreCase } else { [System.StringComparer]::Ordinal }
    $expectedPaths = [System.Collections.Generic.HashSet[string]]::new($pathComparer)
    $rows = [System.Collections.Generic.List[object]]::new()
    foreach ($entry in @($manifest.Files)) {
        $relative = [string]$entry.RelativePath
        $normalizedRelative = $relative.Replace('\', '/')
        if (-not $expectedPaths.Add($normalizedRelative)) {
            $rows.Add([pscustomobject]@{ RelativePath = $relative; Status = 'Duplicate'; ExpectedSHA256 = $entry.SHA256; ActualSHA256 = $null })
            continue
        }
        $platformRelative = $normalizedRelative.Replace('/', [System.IO.Path]::DirectorySeparatorChar)
        if ([System.IO.Path]::IsPathRooted($platformRelative)) {
            $rows.Add([pscustomobject]@{ RelativePath = $relative; Status = 'UnsafePath'; ExpectedSHA256 = $entry.SHA256; ActualSHA256 = $null })
            continue
        }
        $fullPath = [System.IO.Path]::GetFullPath((Join-Path -Path $script:IR.CasePath -ChildPath $platformRelative))
        if (-not (Test-IRPathWithinRoot -Root $script:IR.CasePath -Candidate $fullPath)) {
            $rows.Add([pscustomobject]@{ RelativePath = $relative; Status = 'UnsafePath'; ExpectedSHA256 = $entry.SHA256; ActualSHA256 = $null })
            continue
        }
        if (-not (Test-Path -LiteralPath $fullPath -PathType Leaf)) {
            $rows.Add([pscustomobject]@{ RelativePath = $relative; Status = 'Missing'; ExpectedSHA256 = $entry.SHA256; ActualSHA256 = $null })
            continue
        }
        $actual = (Get-FileHash -LiteralPath $fullPath -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant()
        $rows.Add([pscustomobject]@{
            RelativePath = $relative
            Status = if ($actual -ceq [string]$entry.SHA256) { 'Verified' } else { 'Modified' }
            ExpectedSHA256 = [string]$entry.SHA256
            ActualSHA256 = $actual
        })
    }
    $excludedPaths = @($manifest.ManifestFilesExcluded | ForEach-Object { ([string]$_).Replace('\', '/') })
    foreach ($file in @(Get-ChildItem -LiteralPath $script:IR.CasePath -File -Recurse -Force)) {
        $relative = [System.IO.Path]::GetRelativePath($script:IR.CasePath, $file.FullName).Replace([System.IO.Path]::DirectorySeparatorChar, '/')
        if ($relative -in $excludedPaths -or $expectedPaths.Contains($relative)) { continue }
        $rows.Add([pscustomobject]@{
            RelativePath = $relative
            Status = 'Extra'
            ExpectedSHA256 = $null
            ActualSHA256 = (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant()
        })
    }
    $array = $rows.ToArray()
    $verified = @($array | Where-Object Status -eq 'Verified').Count
    $failed = @($array | Where-Object Status -ne 'Verified').Count
    $actionLogChain = Test-IRActionLogChain
    return [pscustomobject]@{
        ManifestPath = $ManifestPath
        Verified = $verified
        Failed = $failed
        IsValid = $failed -eq 0 -and $actionLogChain.Valid
        ActionLogChain = $actionLogChain
        Files = $array
    }
}

function New-IRCaseArchive {
    [CmdletBinding(SupportsShouldProcess)]
    param()

    if (-not $script:IR.CasePath) { throw 'No case is initialized.' }
    $archiveName = '{0}-{1}.zip' -f $script:IR.CaseId, [datetime]::UtcNow.ToString('yyyyMMdd-HHmmss')
    $archivePath = Join-Path -Path $script:IR.OutputRoot -ChildPath $archiveName
    $null = Add-IRActionLog -Action 'Create case ZIP archive' -Status Read -Target $archivePath
    $manifest = New-IREvidenceManifest
    if ($PSCmdlet.ShouldProcess($archivePath, 'Create ZIP archive of the case directory')) {
        Compress-Archive -LiteralPath $script:IR.CasePath -DestinationPath $archivePath -CompressionLevel Optimal -ErrorAction Stop
        $null = Protect-IRCaseFile -Path $archivePath
        $hash = (Get-FileHash -LiteralPath $archivePath -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant()
        Write-IRSuccess "Created archive: $archivePath"
        return [pscustomobject]@{ ArchivePath = $archivePath; SHA256 = $hash; Manifest = $manifest }
    }
    return [pscustomobject]@{ ArchivePath = $archivePath; SHA256 = $null; Manifest = $manifest; Planned = $true }
}

function Invoke-IRComprehensiveCollection {
    [CmdletBinding()]
    param(
        [string]$UserPrincipalName,
        [ValidateRange(1, 90)][int]$DaysBack = $script:IR.Days,
        [switch]$Quick,
        [switch]$IncludeSharePoint,
        [ValidateRange(1, 100000)][int]$MaximumSharePointSites = 500,
        [switch]$IncludeAllMailboxFolders,
        [switch]$SkipTeams,
        [switch]$SkipDefender,
        [switch]$SkipPolicies,
        [switch]$CreateAxiomImport,
        [switch]$Archive
    )

    $upn = Resolve-IRTarget -Upn $UserPrincipalName
    $null = Set-IRTarget -Upn $upn
    $null = Initialize-IRCase
    $script:IR.Days = $DaysBack
    $maximumSites = $MaximumSharePointSites
    $includeFolderInventory = $IncludeAllMailboxFolders.IsPresent
    $status = [System.Collections.Generic.List[object]]::new()
    $safe = ConvertTo-IRSafeFileName -Value $upn

    # Complete the Exchange-backed steps before Graph authentication. The
    # verified module baselines currently carry different MSAL versions; this
    # order avoids the Graph-first assembly collision while keeping each step's
    # failure reporting independent.
    $status.Add((Invoke-IRCollectionStep -Name 'Mailbox configuration' -Operation {
        Export-IRMailboxInvestigation -UserPrincipalName $upn -IncludeAllFolders:$includeFolderInventory
    }))
    $status.Add((Invoke-IRCollectionStep -Name 'Message trace' -Operation {
        Export-IRMessageInvestigation -UserPrincipalName $upn -DaysBack $DaysBack
    }))
    $status.Add((Invoke-IRCollectionStep -Name 'Unified audit log' -Operation {
        Export-IRUserAuditInvestigation -UserPrincipalName $upn -DaysBack $DaysBack -IncludeAdminOnlyExport
    }))

    if (-not $Quick) {
        if (-not $SkipDefender) {
            $status.Add((Invoke-IRCollectionStep -Name 'Threat and Defender' -Operation {
                Export-IRThreatInvestigation -UserPrincipalName $upn -DaysBack $DaysBack
            }))
        }
        if (-not $SkipPolicies) {
            $status.Add((Invoke-IRCollectionStep -Name 'Security policies' -Operation {
                Backup-IRSecurityPolicy
            }))
        }
    }

    $status.Add((Invoke-IRCollectionStep -Name 'User profile' -Operation {
        $userProfile = Get-IRGraphUser -UserPrincipalName $upn
        # Export a stable evidence record instead of recursively serializing the
        # Graph SDK object's internal backing graph, which can be very large and
        # can exceed ConvertTo-Json's maximum depth.
        $userRecord = [pscustomobject][ordered]@{
            Id = [string]$userProfile.Id
            UserPrincipalName = [string]$userProfile.UserPrincipalName
            DisplayName = [string]$userProfile.DisplayName
            AccountEnabled = [bool]$userProfile.AccountEnabled
            Mail = [string]$userProfile.Mail
            MySite = [string]$userProfile.MySite
        }
        $null = Export-IRData -Data @($userRecord) -BaseName "UserProfile-$safe" -Format Json -Subdirectory 'Identity'
        $userRecord
    }))
    $status.Add((Invoke-IRCollectionStep -Name 'Identity and sign-ins' -Operation {
        Export-IRIdentityInvestigation -UserPrincipalName $upn -DaysBack ([math]::Min(180, $DaysBack))
    }))

    if (-not $Quick) {
        $status.Add((Invoke-IRCollectionStep -Name 'Managed devices' -Operation {
            Export-IRDeviceInvestigation -UserPrincipalName $upn
        }))
        $status.Add((Invoke-IRCollectionStep -Name 'Conditional Access' -Operation {
            $policies = @(Get-IRConditionalAccessPolicyReport)
            $null = Export-IRData -Data $policies -BaseName 'ConditionalAccessPolicies' -Format Csv -Subdirectory 'Policies'
            $policies
        }))
        if (-not $SkipTeams) {
            $status.Add((Invoke-IRCollectionStep -Name 'Microsoft Teams' -Operation {
                Export-IRTeamsForensicData -UserPrincipalName $upn -IncludeAuditEvents -DaysBack ([math]::Min(180, $DaysBack))
            }))
        }
        if ($IncludeSharePoint) {
            $status.Add((Invoke-IRCollectionStep -Name 'SharePoint access' -Operation {
                Export-IRSharePointUserAccess -UserPrincipalName $upn -MaximumSites $maximumSites
            }))
        }
    }

    $statusArray = $status.ToArray()
    $null = Export-IRData -Data $statusArray -BaseName 'CollectionStatus' -Format Csv -Subdirectory 'Reports'
    $null = Export-IRData -Data $statusArray -BaseName 'CollectionStatus' -Format Json -Subdirectory 'Reports'
    $reportPath = New-IRCaseReport -CollectionStatus $statusArray
    $packageFiles = @()
    if ($CreateAxiomImport) { $packageFiles = @(New-IRAxiomImportPackage) }
    $seal = if ($Archive) { New-IRCaseArchive } else { New-IREvidenceManifest }

    $failed = @($statusArray | Where-Object Status -eq 'Failed').Count
    $partial = @($statusArray | Where-Object Status -eq 'Partial').Count
    Write-IRInfo "Collection finished with $failed failed and $partial partial component(s)."
    return [pscustomobject]@{
        CaseId = $script:IR.CaseId
        CasePath = $script:IR.CasePath
        Status = $statusArray
        Failed = $failed
        Partial = $partial
        ReportPath = $reportPath
        AnalystPackageFiles = $packageFiles
        SealOrArchive = $seal
        Complete = $failed -eq 0 -and $partial -eq 0
    }
}

# ---------------------------------------------------------------------------
# Deterministic offline regression tests
# ---------------------------------------------------------------------------

function Invoke-IROfflineSelfTest {
    [CmdletBinding()]
    param()

    $results = [System.Collections.Generic.List[object]]::new()
    $run = {
        param([string]$Name, [scriptblock]$Test)
        try {
            $value = & $Test
            if (-not [bool]$value) { throw 'Assertion returned false.' }
            $results.Add([pscustomobject]@{ Test = $Name; Status = 'Pass'; Detail = $null })
        }
        catch {
            $results.Add([pscustomobject]@{ Test = $Name; Status = 'Fail'; Detail = $_.Exception.Message })
        }
    }

    & $run 'PowerShell 7.6+ Core runtime' {
        $PSVersionTable.PSEdition -eq 'Core' -and [version]$PSVersionTable.PSVersion -ge $script:IRMinimumPowerShell
    }
    & $run 'Script parses without errors' {
        $tokens = $null
        $errors = $null
        [void][System.Management.Automation.Language.Parser]::ParseFile($script:IRScriptPath, [ref]$tokens, [ref]$errors)
        @($errors).Count -eq 0
    }
    & $run 'Function names are unique' {
        $tokens = $null
        $errors = $null
        $ast = [System.Management.Automation.Language.Parser]::ParseFile($script:IRScriptPath, [ref]$tokens, [ref]$errors)
        $names = @($ast.FindAll({ param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true).Name)
        @($names | Group-Object | Where-Object Count -gt 1).Count -eq 0
    }
    & $run 'No Invoke-Expression or retired cloud export command' {
        $tokens = $null
        $errors = $null
        $ast = [System.Management.Automation.Language.Parser]::ParseFile($script:IRScriptPath, [ref]$tokens, [ref]$errors)
        $commands = @($ast.FindAll({ param($node) $node -is [System.Management.Automation.Language.CommandAst] }, $true) | ForEach-Object { $_.GetCommandName() })
        'Invoke-Expression' -notin $commands -and 'New-ComplianceSearchAction' -notin $commands
    }
    & $run 'Safe file names remove path separators' {
        $safe = ConvertTo-IRSafeFileName -Value '..\bad/name:*?'
        $safe -notmatch '[\\/:*?]' -and $safe -ne '..'
    }
    & $run 'Safe file names are portable and reject Windows device names' {
        (ConvertTo-IRSafeFileName -Value 'CON.txt') -ceq '_CON.txt' -and
        (ConvertTo-IRSafeFileName -Value 'report<draft>|final') -ceq 'report_draft__final'
    }
    & $run 'Path containment rejects sibling-prefix and traversal paths' {
        $root = Join-Path -Path ([System.IO.Path]::GetTempPath()) -ChildPath 'm365-ir-root'
        $child = Join-Path -Path $root -ChildPath 'case/evidence.json'
        $sibling = "$root-escape/evidence.json"
        (Test-IRPathWithinRoot -Root $root -Candidate $child) -and
        -not (Test-IRPathWithinRoot -Root $root -Candidate $sibling)
    }
    & $run 'OData literals escape apostrophes' {
        (ConvertTo-IRODataLiteral -Value "O'Brien") -ceq "O''Brien"
    }
    & $run 'UPN validation rejects malformed input' {
        (Test-IRUpn -Value 'analyst@example.com') -and -not (Test-IRUpn -Value 'bad value@example')
    }
    & $run 'HTML output encoding is safe' {
        (ConvertTo-IRHtml -Value '<script>&') -ceq '&lt;script&gt;&amp;'
    }
    & $run 'IP classification covers private, public, special, and invalid input' {
        (Get-IRIPAddressCategory -IPAddress '10.0.0.1') -eq 'PrivateIPv4' -and
        (Get-IRIPAddressCategory -IPAddress '8.8.8.8') -eq 'PublicIPv4' -and
        (Get-IRIPAddressCategory -IPAddress '100.64.0.1') -eq 'CarrierGradeNATIPv4' -and
        (Get-IRIPAddressCategory -IPAddress '192.0.2.5') -eq 'DocumentationIPv4' -and
        (Get-IRIPAddressCategory -IPAddress '169.254.1.5') -eq 'LinkLocalIPv4' -and
        (Get-IRIPAddressCategory -IPAddress 'fd00::1') -eq 'PrivateIPv6' -and
        (Get-IRIPAddressCategory -IPAddress '2001:db8::1') -eq 'DocumentationIPv6' -and
        (Get-IRIPAddressCategory -IPAddress '::ffff:192.168.1.5') -eq 'IPv4Mapped-PrivateIPv4' -and
        (Get-IRIPAddressCategory -IPAddress 'not-an-ip') -eq 'Invalid'
    }
    & $run 'Public IP alone does not create a noisy audit finding' {
        $auditSample = [pscustomobject]@{
            CreationUtc = [datetime]'2026-01-01T12:00:00Z'
            Operation = 'UserLoggedIn'
            Category = 'Authentication'
            UserId = 'user@example.com'
            ClientIP = '8.8.8.8'
            IPAddressCategory = 'PublicIPv4'
            ResultStatus = 'Succeeded'
            ObjectId = $null
        }
        @(Get-IRAuditFinding -Events @($auditSample) -TimeZoneId 'UTC').Count -eq 0
    }
    & $run 'Risky audit operation retains public-IP context' {
        $auditSample = [pscustomobject]@{
            CreationUtc = [datetime]'2026-01-01T12:00:00Z'
            Operation = 'New-InboxRule'
            Category = 'RulesAndSettings'
            UserId = 'user@example.com'
            ClientIP = '8.8.8.8'
            IPAddressCategory = 'PublicIPv4'
            ResultStatus = 'Succeeded'
            ObjectId = 'rule-1'
        }
        $finding = @(Get-IRAuditFinding -Events @($auditSample) -TimeZoneId 'UTC') | Select-Object -First 1
        $finding.Severity -eq 'High' -and $finding.Reasons -match 'Public source IP is context'
    }
    & $run 'Audit mode maps reviewed Graph write scopes to read-only scopes' {
        $scopes = @(ConvertTo-IRAuditGraphScope -Scopes @(
            'User.ReadWrite.All',
            'Policy.ReadWrite.ConditionalAccess',
            'DeviceManagementManagedDevices.ReadWrite.All',
            'AuditLog.Read.All'
        ))
        'User.Read.All' -in $scopes -and
        'Policy.Read.All' -in $scopes -and
        'DeviceManagementManagedDevices.Read.All' -in $scopes -and
        'AuditLog.Read.All' -in $scopes -and
        @($scopes | Where-Object { Test-IRGraphWriteScope -Scope $_ }).Count -eq 0
    }
    & $run 'Audit mode fails closed for an unreviewed Graph write scope' {
        $rejected = $false
        try { $null = ConvertTo-IRAuditGraphScope -Scopes @('Files.ReadWrite.All') }
        catch { $rejected = $true }
        $rejected
    }
    & $run 'Levenshtein calculation identifies one edit' {
        (Get-IRLevenshteinDistance -String1 'cont0so.com' -String2 'contoso.com') -eq 1
    }
    & $run 'Password generator meets length and character-class rules' {
        $password = New-IRRandomPassword -Length 32
        $password.Length -eq 32 -and $password -cmatch '[a-z]' -and $password -cmatch '[A-Z]' -and $password -match '[0-9]' -and $password -match '[^a-zA-Z0-9]'
    }
    & $run 'Audit JSON normalization tolerates missing properties' {
        $mock = [pscustomobject]@{
            CreationDate = [datetime]'2026-01-01T00:00:00Z'
            Operations = 'UserLoggedIn'
            RecordType = 'AzureActiveDirectoryStsLogon'
            AuditData = '{"Operation":"UserLoggedIn","UserId":"user@example.com","ClientIP":"8.8.8.8"}'
        }
        $row = $mock | ConvertFrom-IRAuditRecord
        $row.Operation -eq 'UserLoggedIn' -and $row.UserId -eq 'user@example.com' -and $row.IPAddressCategory -eq 'PublicIPv4'
    }
    & $run 'Audit mode blocks tenant operation scriptblocks' {
        $previousMode = $script:IR.Mode
        $marker = [pscustomobject]@{ Executed = $false }
        try {
            $script:IR.Mode = 'Audit'
            $null = Invoke-IRChange -Target 'self-test' -Action 'execute test mutation' -Operation { $marker.Executed = $true } -Confirm:$false
            -not $marker.Executed
        }
        finally { $script:IR.Mode = $previousMode }
    }
    & $run 'Every production mutation call has exact confirmation' {
        $tokens = $null
        $errors = $null
        $ast = [System.Management.Automation.Language.Parser]::ParseFile($script:IRScriptPath, [ref]$tokens, [ref]$errors)
        $calls = @($ast.FindAll({
            param($node)
            $node -is [System.Management.Automation.Language.CommandAst] -and
            $node.GetCommandName() -eq 'Invoke-IRChange'
        }, $true))
        @($calls | Where-Object {
            $_.Extent.Text -notmatch '(?i)-ExactConfirmation\b' -and
            $_.Extent.Text -notmatch "(?i)-Target\s+'self-test'"
        }).Count -eq 0
    }
    & $run 'Action log hash chain validates and detects tampering' {
        $path = Join-Path -Path ([System.IO.Path]::GetTempPath()) -ChildPath ("m365-ir-action-{0}.jsonl" -f [guid]::NewGuid().ToString('N'))
        try {
            $timestamp = '2026-01-01T00:00:00.0000000Z'
            $previous = '0' * 64
            $details = [ordered]@{ Records = 2; Complete = $true }
            $hash = Get-IRActionLogHash -Sequence 1 -TimestampUtc $timestamp -Status Read -Action 'Synthetic collection' -Target 'user@example.com' -Investigator 'offline-self-test' -Mode Audit -Details $details -PreviousHash $previous
            $entry = [ordered]@{
                Sequence = 1
                TimestampUtc = $timestamp
                Status = 'Read'
                Action = 'Synthetic collection'
                Target = 'user@example.com'
                Investigator = 'offline-self-test'
                Mode = 'Audit'
                Details = $details
                PreviousHash = $previous
                EntryHash = $hash
            }
            $entry | ConvertTo-Json -Depth 10 -Compress | Set-Content -LiteralPath $path -Encoding utf8
            $valid = Test-IRActionLogChain -Path $path
            (Get-Content -LiteralPath $path -Raw -Encoding utf8).Replace('Synthetic collection', 'Altered collection') | Set-Content -LiteralPath $path -Encoding utf8
            $altered = Test-IRActionLogChain -Path $path
            $valid.Valid -and $valid.Entries -eq 1 -and -not $altered.Valid
        }
        finally {
            if ([System.IO.File]::Exists($path)) { [System.IO.File]::Delete($path) }
        }
    }
    & $run 'Installed Graph command mappings are not shadowed' {
        foreach ($module in @('Microsoft.Graph.Users.Actions', 'Microsoft.Graph.Identity.SignIns', 'Microsoft.Graph.Applications', 'Microsoft.Graph.Reports')) {
            $status = Get-IRModuleStatus -Name $module
            if ($status.MeetsMinimum) { $null = Import-IRModule -Name $module }
        }
        $mapping = @{
            'Revoke-MgUserSignInSession' = 'Microsoft.Graph.Users.Actions'
            'Remove-MgOauth2PermissionGrant' = 'Microsoft.Graph.Identity.SignIns'
            'Get-MgServicePrincipal' = 'Microsoft.Graph.Applications'
            'Get-MgAuditLogSignIn' = 'Microsoft.Graph.Reports'
        }
        foreach ($name in $mapping.Keys) {
            $command = Get-Command -Name $name -ErrorAction SilentlyContinue
            if ($command -and [string]$command.Source -ne $mapping[$name]) { return $false }
        }
        return $true
    }

    $array = $results.ToArray()
    $failed = @($array | Where-Object Status -eq 'Fail').Count
    return [pscustomobject]@{
        TimestampUtc = [datetime]::UtcNow
        Passed = $array.Count - $failed
        Failed = $failed
        Overall = if ($failed -eq 0) { 'Pass' } else { 'Fail' }
        Tests = $array
    }
}

function Show-IROfflineSelfTest {
    param([Parameter(Mandatory)][psobject]$Report)
    Write-IRConsole
    Write-IRConsole -Message 'OFFLINE SELF-TEST' -Color Cyan
    $Report.Tests | Format-Table Test, Status, Detail -Wrap -AutoSize | Out-Host
    $color = if ($Report.Failed -eq 0) { [ConsoleColor]::Green } else { [ConsoleColor]::Red }
    Write-IRConsole -Message "Overall: $($Report.Overall) ($($Report.Passed) passed, $($Report.Failed) failed)" -Color $color
}

# ---------------------------------------------------------------------------
# Interactive console menus
# ---------------------------------------------------------------------------

function Show-IRResult {
    param([AllowNull()][object]$InputObject)

    if ($null -eq $InputObject) { return }
    $items = @($InputObject)
    if ($items.Count -eq 0) { return }
    Write-IRConsole
    if ($items.Count -gt 1) {
        $items | Select-Object -First 50 | Format-Table -AutoSize -Wrap | Out-Host
        if ($items.Count -gt 50) { Write-IRWarn "Showing the first 50 of $($items.Count) objects. Export the result for complete detail." }
    }
    else {
        $items[0] | Format-List * | Out-Host
    }
}

function Invoke-IRMenuAction {
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][scriptblock]$Operation,
        [switch]$NoPause
    )

    Write-IRConsole
    Write-IRConsole -Message $Name.ToUpperInvariant() -Color Cyan
    try {
        $result = & $Operation
        $script:IR.Results.LastResult = $result
        Show-IRResult -InputObject $result
    }
    catch {
        Write-IRFailure $_.Exception.Message
        $null = Add-IRActionLog -Action $Name -Status Error -Target $script:IR.TargetUpn -Details $_.Exception.Message
    }
    if (-not $NoPause) { Wait-IRKey }
}

function Show-IRSettingsMenu {
    while ($true) {
        Write-IRConsole
        Write-IRConsole -Message 'TARGET, CASE, AND EXECUTION SETTINGS' -Color Cyan
        Write-IRConsole -Message "Target: $($script:IR.TargetUpn) | Days: $($script:IR.Days) | Mode: $($script:IR.Mode)"
        Write-IRConsole -Message "Case: $($script:IR.CaseId) | Path: $($script:IR.CasePath)"
        Write-IRConsole -Message '  1. Change target user'
        Write-IRConsole -Message '  2. Change investigation lookback'
        Write-IRConsole -Message '  3. Change Audit/Live mode'
        Write-IRConsole -Message '  4. Start a new case folder'
        Write-IRConsole -Message '  5. Show case metadata'
        Write-IRConsole -Message '  0. Back'
        switch (Read-Host 'Select') {
            '1' { $null = Set-IRTarget -Upn (Read-IRUpn -Default $script:IR.TargetUpn) }
            '2' { $script:IR.Days = Read-IRInteger -Prompt 'Lookback days' -Default $script:IR.Days -Minimum 1 -Maximum 90 }
            '3' {
                $newMode = if ($script:IR.Mode -eq 'Audit') { 'Live' } else { 'Audit' }
                $null = Set-IRMode -NewMode $newMode
            }
            '4' {
                $caseId = Read-IRText -Prompt 'New case ID (blank generates one)' -AllowEmpty
                Invoke-IRMenuAction -Name 'Create new case' -Operation { Initialize-IRCase -CaseId $caseId -ForceNew } -NoPause
            }
            '5' {
                Show-IRResult ([pscustomobject]$script:IR)
                Wait-IRKey
            }
            '0' { return }
            default { Write-IRWarn 'Unknown selection.' }
        }
    }
}

function Show-IRConnectionMenu {
    while ($true) {
        Write-IRConsole
        Write-IRConsole -Message 'PREFLIGHT AND CONNECTIONS' -Color Cyan
        Write-IRConsole -Message '  1. Offline preflight'
        Write-IRConsole -Message '  2. Online preflight (Graph + Exchange)'
        Write-IRConsole -Message '  3. Connect Microsoft Graph'
        Write-IRConsole -Message '  4. Connect Exchange Online'
        Write-IRConsole -Message '  5. Connect Microsoft Purview'
        Write-IRConsole -Message '  6. Connect Microsoft Teams'
        Write-IRConsole -Message '  7. Connect SharePoint Online'
        Write-IRConsole -Message '  8. Show connection status'
        Write-IRConsole -Message '  9. Disconnect all services'
        Write-IRConsole -Message '  0. Back'
        $choice = Read-Host 'Select'
        switch ($choice) {
            '1' { Invoke-IRMenuAction -Name 'Offline preflight' -Operation { $r = Test-IRPreflight; Show-IRPreflight $r; $r } }
            '2' { Invoke-IRMenuAction -Name 'Online preflight' -Operation { $r = Test-IRPreflight -Online; Show-IRPreflight $r; $r } }
            '3' { Invoke-IRMenuAction -Name 'Connect Microsoft Graph' -Operation { Connect-IRGraph } }
            '4' { Invoke-IRMenuAction -Name 'Connect Exchange Online' -Operation { Connect-IRExchange; Get-IRConnectionStatus } }
            '5' { Invoke-IRMenuAction -Name 'Connect Microsoft Purview' -Operation { Connect-IRPurview; Get-IRConnectionStatus } }
            '6' { Invoke-IRMenuAction -Name 'Connect Microsoft Teams' -Operation { Connect-IRTeamService; Get-IRConnectionStatus } }
            '7' { Invoke-IRMenuAction -Name 'Connect SharePoint Online' -Operation { Connect-IRSharePoint; Get-IRConnectionStatus } }
            '8' { Invoke-IRMenuAction -Name 'Connection status' -Operation { Get-IRConnectionStatus } }
            '9' { Invoke-IRMenuAction -Name 'Disconnect services' -Operation { Disconnect-IRService; Get-IRConnectionStatus } }
            '0' { return }
            default { Write-IRWarn 'Unknown selection.' }
        }
    }
}

function Show-IRContainmentMenu {
    while ($true) {
        Write-IRConsole
        Write-IRConsole -Message 'ACCOUNT CONTAINMENT' -Color Cyan
        Write-IRConsole -Message '  1. Revoke all user sessions'
        Write-IRConsole -Message '  2. Reset password (never written as plaintext)'
        Write-IRConsole -Message '  3. Block sign-in'
        Write-IRConsole -Message '  4. Unblock sign-in'
        Write-IRConsole -Message '  5. Review Conditional Access scope for target'
        Write-IRConsole -Message '  6. Create temporary targeted-MFA policy'
        Write-IRConsole -Message '  7. Review/remove managed temporary policies'
        Write-IRConsole -Message '  8. Guided containment runbook'
        Write-IRConsole -Message '  0. Back'
        switch (Read-Host 'Select') {
            '1' { Invoke-IRMenuAction -Name 'Revoke sessions' -Operation { Revoke-IRUserSession } }
            '2' { Invoke-IRMenuAction -Name 'Reset password' -Operation { Reset-IRUserPassword -DisplayOnce } }
            '3' { Invoke-IRMenuAction -Name 'Block sign-in' -Operation { Set-IRUserSignIn -Action Block } }
            '4' { Invoke-IRMenuAction -Name 'Unblock sign-in' -Operation { Set-IRUserSignIn -Action Unblock } }
            '5' { Invoke-IRMenuAction -Name 'Conditional Access target review' -Operation { Get-IRConditionalAccessReview } }
            '6' {
                $hours = Read-IRInteger -Prompt 'Policy lifetime in hours' -Default 24 -Minimum 1 -Maximum 168
                $state = if (Read-IRYesNo -Prompt 'Enable immediately? (No creates report-only)') { 'enabled' } else { 'enabledForReportingButNotEnabled' }
                Invoke-IRMenuAction -Name 'Create temporary MFA policy' -Operation { New-IRTemporaryMfaPolicy -LifetimeHours $hours -State $state }
            }
            '7' {
                Invoke-IRMenuAction -Name 'Review managed policies' -Operation {
                    $policies = @(Get-IRManagedConditionalAccessPolicy)
                    Show-IRResult $policies
                    if ($policies.Count -gt 0 -and (Read-IRYesNo -Prompt 'Remove selected managed policies?')) {
                        $selected = @(Select-IRItem -Items $policies -AllowMultiple -AllowCancel -Prompt 'Policy number(s)' -Label { param($p) "$($p.DisplayName) [$($p.State)] expires $($p.ExpiresUtc)" })
                        if ($selected.Count -gt 0) { Remove-IRManagedConditionalAccessPolicy -Policy $selected }
                    }
                    $policies
                }
            }
            '8' { Invoke-IRMenuAction -Name 'Guided containment runbook' -Operation { Invoke-IRContainmentRunbook } }
            '0' { return }
            default { Write-IRWarn 'Unknown selection.' }
        }
    }
}

function Show-IRMailboxMenu {
    while ($true) {
        Write-IRConsole
        Write-IRConsole -Message 'MAILBOX PERSISTENCE AND DELEGATION' -Color Cyan
        Write-IRConsole -Message '  1. Review mailbox and inbox rules'
        Write-IRConsole -Message '  2. Review mailbox permissions'
        Write-IRConsole -Message '  3. Review mailbox applications'
        Write-IRConsole -Message '  4. Review tenant transport rules'
        Write-IRConsole -Message '  5. Export complete mailbox investigation'
        Write-IRConsole -Message '  6. Disable selected inbox rule'
        Write-IRConsole -Message '  7. Remove selected inbox rule'
        Write-IRConsole -Message '  8. Clear mailbox forwarding'
        Write-IRConsole -Message '  9. Disable selected mailbox application'
        Write-IRConsole -Message ' 10. Remove selected delegation'
        Write-IRConsole -Message ' 11. Disable selected transport rule'
        Write-IRConsole -Message '  0. Back'
        switch (Read-Host 'Select') {
            '1' { Invoke-IRMenuAction -Name 'Mailbox and inbox rules' -Operation { $r = Get-IRMailboxSnapshot; Show-IRResult $r.Summary; $r.InboxRules } }
            '2' {
                $all = Read-IRYesNo -Prompt 'Enumerate every mailbox folder? (Calendar-only is faster)'
                Invoke-IRMenuAction -Name 'Mailbox permissions' -Operation { (Get-IRMailboxPermissionInventory -IncludeAllFolders:$all).Permissions }
            }
            '3' { Invoke-IRMenuAction -Name 'Mailbox applications' -Operation { Get-IRMailboxApplication } }
            '4' { Invoke-IRMenuAction -Name 'Transport rules' -Operation { Get-IRTransportRuleReview } }
            '5' {
                $all = Read-IRYesNo -Prompt 'Enumerate every mailbox folder?'
                Invoke-IRMenuAction -Name 'Export mailbox investigation' -Operation { Export-IRMailboxInvestigation -IncludeAllFolders:$all }
            }
            '6' {
                Invoke-IRMenuAction -Name 'Disable inbox rule' -Operation {
                    $rules = @((Get-IRMailboxSnapshot).InboxRules | Where-Object Enabled)
                    $selected = @(Select-IRItem -Items $rules -AllowCancel -Prompt 'Rule number' -Label { param($r) "$($r.Name) [$($r.Risk)] $($r.Reasons)" })
                    if ($selected.Count) { Set-IRInboxRuleEnabled -Identity $selected[0].Identity -Enabled:$false }
                }
            }
            '7' {
                Invoke-IRMenuAction -Name 'Remove inbox rule' -Operation {
                    $rules = @((Get-IRMailboxSnapshot).InboxRules)
                    $selected = @(Select-IRItem -Items $rules -AllowCancel -Prompt 'Rule number' -Label { param($r) "$($r.Name) [$($r.Risk)] $($r.Reasons)" })
                    if ($selected.Count) { Remove-IRInboxRule -Identity $selected[0].Identity }
                }
            }
            '8' { Invoke-IRMenuAction -Name 'Clear mailbox forwarding' -Operation { Clear-IRMailboxForwarding } }
            '9' {
                Invoke-IRMenuAction -Name 'Disable mailbox application' -Operation {
                    $apps = @(Get-IRMailboxApplication | Where-Object Enabled)
                    $selected = @(Select-IRItem -Items $apps -AllowCancel -Prompt 'Application number' -Label { param($a) "$($a.DisplayName) [$($a.Identity)]" })
                    if ($selected.Count) { Disable-IRMailboxApplication -Identity $selected[0].Identity }
                }
            }
            '10' {
                $all = Read-IRYesNo -Prompt 'Enumerate every mailbox folder?'
                Invoke-IRMenuAction -Name 'Remove mailbox delegation' -Operation {
                    $permissions = @((Get-IRMailboxPermissionInventory -IncludeAllFolders:$all).Permissions)
                    $selected = @(Select-IRItem -Items $permissions -AllowCancel -Prompt 'Permission number' -Label { param($p) "$($p.PermissionType): $($p.Trustee) on $($p.Resource) [$($p.AccessRights)]" })
                    if ($selected.Count) {
                        $p = $selected[0]
                        Remove-IRMailboxDelegation -PermissionType $p.PermissionType -Trustee $p.Trustee -Resource $p.Resource
                    }
                }
            }
            '11' {
                Invoke-IRMenuAction -Name 'Disable transport rule' -Operation {
                    $rules = @(Get-IRTransportRuleReview | Where-Object State -ne 'Disabled')
                    $selected = @(Select-IRItem -Items $rules -AllowCancel -Prompt 'Rule number' -Label { param($r) "$($r.Name) [$($r.Mode)] $($r.RiskReasons)" })
                    if ($selected.Count) { Disable-IRTransportRule -Identity $selected[0].Identity }
                }
            }
            '0' { return }
            default { Write-IRWarn 'Unknown selection.' }
        }
    }
}

function Show-IRInvestigationMenu {
    while ($true) {
        Write-IRConsole
        Write-IRConsole -Message 'MESSAGE AND AUDIT INVESTIGATION' -Color Cyan
        Write-IRConsole -Message '  1. Export message trace and analysis'
        Write-IRConsole -Message '  2. Export unified-audit investigation'
        Write-IRConsole -Message '  3. Find phishing spread from a sender'
        Write-IRConsole -Message '  4. Warn selected internal recipients from spread result'
        Write-IRConsole -Message '  5. Search SharePoint file access by path fragment'
        Write-IRConsole -Message '  0. Back'
        switch (Read-Host 'Select') {
            '1' {
                $subject = Read-IRText -Prompt 'Optional subject fragment' -AllowEmpty
                Invoke-IRMenuAction -Name 'Message trace investigation' -Operation { Export-IRMessageInvestigation -DaysBack $script:IR.Days -SubjectContains $subject }
            }
            '2' { Invoke-IRMenuAction -Name 'Unified audit investigation' -Operation { Export-IRUserAuditInvestigation -DaysBack $script:IR.Days -IncludeAdminOnlyExport } }
            '3' {
                $sourceAddress = Read-IRUpn -Prompt 'Sender address' -Default $script:IR.TargetUpn
                $subject = Read-IRText -Prompt 'Optional subject fragment' -AllowEmpty
                Invoke-IRMenuAction -Name 'Phishing spread investigation' -Operation { Find-IRPhishingSpread -SenderAddress $sourceAddress -SubjectContains $subject -DaysBack ([math]::Min(90, $script:IR.Days)) }
            }
            '4' {
                Invoke-IRMenuAction -Name 'Send phishing warning' -Operation {
                    $spread = @($script:IR.Results.PhishingSpread | Where-Object Internal)
                    if ($spread.Count -eq 0) { throw 'Run the phishing-spread investigation first; no internal recipient result is available.' }
                    $selected = @(Select-IRItem -Items $spread -AllowMultiple -AllowCancel -Prompt 'Recipient number(s)' -Label { param($r) "$($r.Recipient) - $($r.MessageCount) message(s)" })
                    if ($selected.Count) { Send-IRPhishingWarning -Recipients @($selected.Recipient) }
                }
            }
            '5' {
                $fragment = Read-IRText -Prompt 'File name, site URL, or path fragment'
                Invoke-IRMenuAction -Name 'SharePoint file access search' -Operation {
                    $events = @(Get-IRSharePointFileAccess -PathFragment $fragment -DaysBack ([math]::Min(180, $script:IR.Days)) -UserPrincipalName $script:IR.TargetUpn)
                    if ($events.Count) { $null = Export-IRData -Data $events -BaseName 'SharePointFileAccess' -Format Csv -Subdirectory 'SharePoint' }
                    $events
                }
            }
            '0' { return }
            default { Write-IRWarn 'Unknown selection.' }
        }
    }
}

function Show-IRIdentityMenu {
    while ($true) {
        Write-IRConsole
        Write-IRConsole -Message 'IDENTITY, APPLICATIONS, AND DEVICES' -Color Cyan
        Write-IRConsole -Message '  1. Review delegated OAuth grants'
        Write-IRConsole -Message '  2. Remove selected OAuth grant'
        Write-IRConsole -Message '  3. Review enterprise-app assignments'
        Write-IRConsole -Message '  4. Remove selected enterprise-app assignment'
        Write-IRConsole -Message '  5. Review Entra sign-ins'
        Write-IRConsole -Message '  6. Review risky-user status'
        Write-IRConsole -Message '  7. Review authentication methods'
        Write-IRConsole -Message '  8. Review/export Exchange and Intune devices'
        Write-IRConsole -Message '  9. Remove selected Exchange device partnership'
        Write-IRConsole -Message ' 10. Delete selected Intune managed-device record'
        Write-IRConsole -Message ' 11. Export complete identity investigation'
        Write-IRConsole -Message '  0. Back'
        switch (Read-Host 'Select') {
            '1' { Invoke-IRMenuAction -Name 'OAuth grants' -Operation { Get-IROAuthGrant } }
            '2' {
                Invoke-IRMenuAction -Name 'Remove OAuth grant' -Operation {
                    $grants = @(Get-IROAuthGrant)
                    $selected = @(Select-IRItem -Items $grants -AllowCancel -Prompt 'Grant number' -Label { param($g) "$($g.ClientApplication) -> $($g.Resource): $($g.Scope)" })
                    if ($selected.Count) { Remove-IROAuthGrant -GrantId $selected[0].GrantId }
                }
            }
            '3' { Invoke-IRMenuAction -Name 'Enterprise application assignments' -Operation { Get-IRAppRoleAssignment } }
            '4' {
                Invoke-IRMenuAction -Name 'Remove enterprise application assignment' -Operation {
                    $items = @(Get-IRAppRoleAssignment)
                    $selected = @(Select-IRItem -Items $items -AllowCancel -Prompt 'Assignment number' -Label { param($a) "$($a.Application): $($a.AppRoleValue) [$($a.AssignmentId)]" })
                    if ($selected.Count) { Remove-IRAppRoleAssignment -AssignmentId $selected[0].AssignmentId }
                }
            }
            '5' { Invoke-IRMenuAction -Name 'Entra sign-in logs' -Operation { Get-IRUserSignInLog -DaysBack ([math]::Min(180, $script:IR.Days)) } }
            '6' { Invoke-IRMenuAction -Name 'Risky user status' -Operation { Get-IRRiskyUser } }
            '7' { Invoke-IRMenuAction -Name 'Authentication methods' -Operation { Get-IRAuthenticationMethod } }
            '8' { Invoke-IRMenuAction -Name 'Managed devices' -Operation { Export-IRDeviceInvestigation } }
            '9' {
                Invoke-IRMenuAction -Name 'Remove Exchange mobile device' -Operation {
                    $items = @(Get-IRExchangeMobileDevice)
                    $selected = @(Select-IRItem -Items $items -AllowCancel -Prompt 'Device number' -Label { param($d) "$($d.DeviceType) $($d.DeviceModel) - $($d.LastSuccessSync) [$($d.Identity)]" })
                    if ($selected.Count) { Remove-IRExchangeMobileDevice -Identity $selected[0].Identity }
                }
            }
            '10' {
                Invoke-IRMenuAction -Name 'Delete Intune managed-device record' -Operation {
                    $items = @(Get-IRIntuneManagedDevice)
                    $selected = @(Select-IRItem -Items $items -AllowCancel -Prompt 'Device number' -Label { param($d) "$($d.DeviceName) $($d.OperatingSystem) [$($d.ManagedDeviceId)]" })
                    if ($selected.Count) { Remove-IRIntuneManagedDevice -ManagedDeviceId $selected[0].ManagedDeviceId }
                }
            }
            '11' { Invoke-IRMenuAction -Name 'Export identity investigation' -Operation { Export-IRIdentityInvestigation -DaysBack ([math]::Min(180, $script:IR.Days)) } }
            '0' { return }
            default { Write-IRWarn 'Unknown selection.' }
        }
    }
}

function Show-IRCollaborationMenu {
    while ($true) {
        Write-IRConsole
        Write-IRConsole -Message 'TEAMS AND SHAREPOINT' -Color Cyan
        Write-IRConsole -Message '  1. Export Teams memberships, channels, and audit events'
        Write-IRConsole -Message '  2. Scan SharePoint site access for target'
        Write-IRConsole -Message '  3. Search SharePoint file access by path'
        Write-IRConsole -Message '  0. Back'
        switch (Read-Host 'Select') {
            '1' { Invoke-IRMenuAction -Name 'Teams forensic data' -Operation { Export-IRTeamsForensicData -IncludeAuditEvents -DaysBack ([math]::Min(180, $script:IR.Days)) } }
            '2' {
                $maximum = Read-IRInteger -Prompt 'Maximum sites to scan' -Default 500 -Minimum 1 -Maximum 100000
                Invoke-IRMenuAction -Name 'SharePoint access scan' -Operation { Export-IRSharePointUserAccess -MaximumSites $maximum }
            }
            '3' {
                $fragment = Read-IRText -Prompt 'File name, site URL, or path fragment'
                Invoke-IRMenuAction -Name 'SharePoint file access' -Operation {
                    $data = @(Get-IRSharePointFileAccess -PathFragment $fragment -UserPrincipalName $script:IR.TargetUpn -DaysBack ([math]::Min(180, $script:IR.Days)))
                    if ($data.Count) { $null = Export-IRData -Data $data -BaseName 'SharePointFileAccess' -Format Csv -Subdirectory 'SharePoint' }
                    $data
                }
            }
            '0' { return }
            default { Write-IRWarn 'Unknown selection.' }
        }
    }
}

function Show-IRThreatPurviewMenu {
    while ($true) {
        Write-IRConsole
        Write-IRConsole -Message 'THREAT ANALYSIS AND PURVIEW SEARCH' -Color Cyan
        Write-IRConsole -Message '  1. Export threat heuristics and Defender detections'
        Write-IRConsole -Message '  2. Review Defender mail detections (last 1-10 days)'
        Write-IRConsole -Message '  3. Create a Purview content search'
        Write-IRConsole -Message '  4. Start a Purview content search'
        Write-IRConsole -Message '  5. Review Purview content searches'
        Write-IRConsole -Message '  6. Remove a Purview content search definition'
        Write-IRConsole -Message '  7. Show current export guidance'
        Write-IRConsole -Message '  0. Back'
        switch (Read-Host 'Select') {
            '1' { Invoke-IRMenuAction -Name 'Threat investigation' -Operation { Export-IRThreatInvestigation -DaysBack $script:IR.Days } }
            '2' {
                $days = Read-IRInteger -Prompt 'Defender report days' -Default ([math]::Min(10, $script:IR.Days)) -Minimum 1 -Maximum 10
                Invoke-IRMenuAction -Name 'Defender mail detections' -Operation { Get-IRDefenderMailDetection -DaysBack $days }
            }
            '3' {
                $name = Read-IRText -Prompt 'Search name (blank generates one)' -AllowEmpty
                $query = Read-IRText -Prompt 'KQL query (blank uses the configured date window)' -AllowEmpty
                Invoke-IRMenuAction -Name 'Create Purview content search' -Operation { New-IRContentSearch -Name $name -ContentMatchQuery $query -DaysBack ([math]::Min(180, $script:IR.Days)) }
            }
            '4' {
                $name = Read-IRText -Prompt 'Search name'
                Invoke-IRMenuAction -Name 'Start Purview content search' -Operation { Start-IRContentSearch -Name $name }
            }
            '5' { Invoke-IRMenuAction -Name 'Purview content searches' -Operation { Get-IRContentSearch } }
            '6' {
                $name = Read-IRText -Prompt 'Search name'
                Invoke-IRMenuAction -Name 'Remove Purview content search' -Operation { Remove-IRContentSearch -Name $name }
            }
            '7' { Invoke-IRMenuAction -Name 'Purview export guidance' -Operation { Get-IRContentSearchExportGuidance } }
            '0' { return }
            default { Write-IRWarn 'Unknown selection.' }
        }
    }
}

function Show-IRPolicyMenu {
    while ($true) {
        Write-IRConsole
        Write-IRConsole -Message 'TENANT POLICY REVIEW AND PREVENTION' -Color Cyan
        Write-IRConsole -Message '  1. Review security policies'
        Write-IRConsole -Message '  2. Back up security policies'
        Write-IRConsole -Message '  3. Add blocked senders/domains to inbound policy'
        Write-IRConsole -Message '  4. Enable supported anti-phishing protections'
        Write-IRConsole -Message '  5. Review outbound spam protection and alerts'
        Write-IRConsole -Message '  6. Create subject quarantine rule (Audit mode by default)'
        Write-IRConsole -Message '  7. Export Conditional Access report'
        Write-IRConsole -Message '  8. Create Conditional Access baseline (report-only default)'
        Write-IRConsole -Message '  9. Change a Conditional Access policy state'
        Write-IRConsole -Message '  0. Back'
        switch (Read-Host 'Select') {
            '1' { Invoke-IRMenuAction -Name 'Security policy snapshot' -Operation { Get-IRSecurityPolicySnapshot } }
            '2' { Invoke-IRMenuAction -Name 'Back up security policies' -Operation { Backup-IRSecurityPolicy } }
            '3' {
                $senders = @((Read-IRText -Prompt 'Sender addresses (comma-separated, blank for none)' -AllowEmpty) -split ',' | ForEach-Object Trim | Where-Object { $_ })
                $domains = @((Read-IRText -Prompt 'Domains (comma-separated, blank for none)' -AllowEmpty) -split ',' | ForEach-Object Trim | Where-Object { $_ })
                $identity = Read-IRText -Prompt 'Policy identity' -Default 'Default'
                Invoke-IRMenuAction -Name 'Add inbound block-list entries' -Operation { Add-IRBlockedSender -SenderAddress $senders -Domain $domains -PolicyIdentity $identity }
            }
            '4' {
                $identity = Read-IRText -Prompt 'Anti-phishing policy identity'
                Invoke-IRMenuAction -Name 'Enable anti-phishing protections' -Operation { Set-IRAntiPhishProtection -PolicyIdentity $identity }
            }
            '5' { Invoke-IRMenuAction -Name 'Outbound spam protection status' -Operation { Get-IROutboundSpamProtectionStatus } }
            '6' {
                $words = @((Read-IRText -Prompt 'Subject phrases (comma-separated)') -split ',' | ForEach-Object Trim | Where-Object { $_ })
                $name = Read-IRText -Prompt 'Rule name (blank generates one)' -AllowEmpty
                $ruleMode = if (Read-IRYesNo -Prompt 'Create directly in Enforce mode?') { 'Enforce' } else { 'Audit' }
                Invoke-IRMenuAction -Name 'Create phishing quarantine rule' -Operation { New-IRPhishingQuarantineRule -SubjectContainsWords $words -Name $name -RuleMode $ruleMode }
            }
            '7' {
                Invoke-IRMenuAction -Name 'Conditional Access report' -Operation {
                    $rows = @(Get-IRConditionalAccessPolicyReport)
                    if ($rows.Count) { $null = Export-IRData -Data $rows -BaseName 'ConditionalAccessPolicies' -Format Csv -Subdirectory 'Policies' }
                    $rows
                }
            }
            '8' {
                $groupText = Read-IRText -Prompt 'Emergency-access exclusion group object ID'
                $groupId = [guid]::Empty
                if (-not [guid]::TryParse($groupText, [ref]$groupId)) { Write-IRWarn 'That is not a GUID.'; continue }
                $options = @('BlockLegacyAuthentication', 'RequireMfaForAdmins', 'RequireMfaForUsers', 'RequireMfaForRiskySignIns')
                $selected = @(Select-IRItem -Items $options -AllowMultiple -AllowCancel -Prompt 'Baseline policy number(s)' -Label { param($p) $p })
                if ($selected.Count -eq 0) { continue }
                $state = if (Read-IRYesNo -Prompt 'Enable immediately? (No creates report-only)') { 'enabled' } else { 'enabledForReportingButNotEnabled' }
                Invoke-IRMenuAction -Name 'Create Conditional Access baseline' -Operation { New-IRConditionalAccessBaseline -ExclusionGroupId $groupId -Policy @($selected) -State $state }
            }
            '9' {
                Invoke-IRMenuAction -Name 'Change Conditional Access policy state' -Operation {
                    $items = @(Get-IRConditionalAccessPolicyReport)
                    $selected = @(Select-IRItem -Items $items -AllowCancel -Prompt 'Policy number' -Label { param($p) "$($p.DisplayName) [$($p.State)]" })
                    if (-not $selected.Count) { return }
                    $states = @('enabledForReportingButNotEnabled', 'enabled', 'disabled')
                    $chosenState = @(Select-IRItem -Items $states -AllowCancel -Prompt 'State number' -Label { param($s) $s })
                    if ($chosenState.Count) { Set-IRConditionalAccessPolicyState -PolicyId $selected[0].Id -State $chosenState[0] }
                }
            }
            '0' { return }
            default { Write-IRWarn 'Unknown selection.' }
        }
    }
}

function Show-IREvidenceMenu {
    while ($true) {
        Write-IRConsole
        Write-IRConsole -Message 'COLLECTION, REPORTING, AND INTEGRITY' -Color Cyan
        Write-IRConsole -Message '  1. Quick collection'
        Write-IRConsole -Message '  2. Comprehensive collection'
        Write-IRConsole -Message '  3. Generate/update HTML case report'
        Write-IRConsole -Message '  4. Create portable analyst/Axiom import CSVs'
        Write-IRConsole -Message '  5. Generate SHA-256 evidence manifest'
        Write-IRConsole -Message '  6. Verify SHA-256 evidence manifest'
        Write-IRConsole -Message '  7. Seal and create case ZIP archive'
        Write-IRConsole -Message '  0. Back'
        switch (Read-Host 'Select') {
            '1' {
                $archive = Read-IRYesNo -Prompt 'Create ZIP archive when complete?'
                Invoke-IRMenuAction -Name 'Quick forensic collection' -Operation { Invoke-IRComprehensiveCollection -Quick -Archive:$archive }
            }
            '2' {
                $sharePoint = Read-IRYesNo -Prompt 'Include the potentially slow SharePoint site scan?'
                $maximum = if ($sharePoint) { Read-IRInteger -Prompt 'Maximum SharePoint sites' -Default 500 -Minimum 1 -Maximum 100000 } else { 500 }
                $allFolders = Read-IRYesNo -Prompt 'Enumerate permissions on every mailbox folder?'
                $skipTeams = -not (Read-IRYesNo -Prompt 'Include Teams?' -DefaultYes)
                $skipDefender = -not (Read-IRYesNo -Prompt 'Include Defender mail detections?' -DefaultYes)
                $skipPolicies = -not (Read-IRYesNo -Prompt 'Include tenant policy backups?' -DefaultYes)
                $axiom = Read-IRYesNo -Prompt 'Create portable analyst/Axiom import CSVs?'
                $archive = Read-IRYesNo -Prompt 'Create ZIP archive when complete?'
                Invoke-IRMenuAction -Name 'Comprehensive forensic collection' -Operation {
                    Invoke-IRComprehensiveCollection -IncludeSharePoint:$sharePoint -MaximumSharePointSites $maximum -IncludeAllMailboxFolders:$allFolders -SkipTeams:$skipTeams -SkipDefender:$skipDefender -SkipPolicies:$skipPolicies -CreateAxiomImport:$axiom -Archive:$archive
                }
            }
            '3' { Invoke-IRMenuAction -Name 'Generate case report' -Operation { New-IRCaseReport } }
            '4' { Invoke-IRMenuAction -Name 'Create portable analyst import files' -Operation { New-IRAxiomImportPackage } }
            '5' { Invoke-IRMenuAction -Name 'Generate evidence manifest' -Operation { New-IREvidenceManifest } }
            '6' { Invoke-IRMenuAction -Name 'Verify evidence manifest' -Operation { $r = Test-IREvidenceManifest; Show-IRResult $r.Files; $r } }
            '7' { Invoke-IRMenuAction -Name 'Create case archive' -Operation { New-IRCaseArchive } }
            '0' { return }
            default { Write-IRWarn 'Unknown selection.' }
        }
    }
}

function Show-IRBanner {
    Write-IRConsole
    Write-IRConsole -Message '====================================================================' -Color DarkCyan
    Write-IRConsole -Message " Microsoft 365 Incident Response Console v$script:IRVersion" -Color Cyan
    Write-IRConsole -Message ' PowerShell 7.6+ | Evidence-first | Explicit-change controls' -Color Cyan
    Write-IRConsole -Message '====================================================================' -Color DarkCyan
}

function Start-IRInteractiveConsole {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSUseShouldProcessForStateChangingFunctions',
        '',
        Justification = 'This function starts the interactive UI; tenant changes remain guarded by Invoke-IRChange.'
    )]
    [CmdletBinding()]
    param()

    Show-IRBanner
    if (-not $script:IR.TargetUpn) { $null = Set-IRTarget -Upn (Read-IRUpn) }
    $null = Initialize-IRCase
    if (-not $script:IR.SkipPreflight) {
        $preflight = Test-IRPreflight
        Show-IRPreflight -Report $preflight
        if ($preflight.Overall -eq 'Fail') { Write-IRWarn 'Required prerequisites failed. Individual actions will stop with explicit errors until corrected.' }
    }
    if (-not $script:IR.NoAutoConnect) {
        if (Read-IRYesNo -Prompt 'Connect to Microsoft Graph and Exchange Online now?') {
            try { Connect-IRExchange } catch { Write-IRWarn "Exchange connection failed: $($_.Exception.Message)" }
            try { $null = Connect-IRGraph } catch { Write-IRWarn "Graph connection failed: $($_.Exception.Message)" }
        }
    }

    while ($true) {
        Write-IRConsole
        Write-IRConsole -Message "MAIN MENU | $($script:IR.Mode.ToUpperInvariant()) | $($script:IR.TargetUpn) | $($script:IR.Days) day(s)" -Color Cyan
        Write-IRConsole -Message '  1. Target, case, and execution settings'
        Write-IRConsole -Message '  2. Preflight and service connections'
        Write-IRConsole -Message '  3. Account containment'
        Write-IRConsole -Message '  4. Mailbox persistence and delegation'
        Write-IRConsole -Message '  5. Message and audit investigation'
        Write-IRConsole -Message '  6. Identity, applications, and devices'
        Write-IRConsole -Message '  7. Teams and SharePoint'
        Write-IRConsole -Message '  8. Threat analysis and Purview search'
        Write-IRConsole -Message '  9. Tenant policy review and prevention'
        Write-IRConsole -Message ' 10. Collection, reporting, and integrity'
        Write-IRConsole -Message '  T. Toggle Audit/Live mode'
        Write-IRConsole -Message '  Q. Quit'
        switch ((Read-Host 'Select').Trim().ToUpperInvariant()) {
            '1' { Show-IRSettingsMenu }
            '2' { Show-IRConnectionMenu }
            '3' { Show-IRContainmentMenu }
            '4' { Show-IRMailboxMenu }
            '5' { Show-IRInvestigationMenu }
            '6' { Show-IRIdentityMenu }
            '7' { Show-IRCollaborationMenu }
            '8' { Show-IRThreatPurviewMenu }
            '9' { Show-IRPolicyMenu }
            '10' { Show-IREvidenceMenu }
            'T' { $null = Set-IRMode -NewMode $(if ($script:IR.Mode -eq 'Audit') { 'Live' } else { 'Audit' }) }
            'Q' { return }
            default { Write-IRWarn 'Unknown selection.' }
        }
    }
}

# Script entry point. Dot-sourcing exposes functions without starting the UI.
$script:IR.Interactive = $MyInvocation.InvocationName -ne '.'
if ($OfflineSelfTest) {
    $report = Invoke-IROfflineSelfTest
    Show-IROfflineSelfTest -Report $report
    if ($report.Failed -gt 0) { throw "$($report.Failed) offline self-test(s) failed." }
    return
}
if ($PreflightOnly) {
    $report = Test-IRPreflight
    Show-IRPreflight -Report $report
    if ($report.Overall -eq 'Fail') { throw 'One or more required preflight checks failed.' }
    return
}
if ($script:IR.Interactive) {
    Start-IRInteractiveConsole
}
